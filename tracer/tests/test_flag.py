"""`codegraph-trace flag`: join Semgrep findings with the recorded trace.

Uses a synthetic findings.json (the real Semgrep output shape: results[] with path,
start.line, end.line, check_id, extra.severity/extra.message) so the tests need no semgrep
install. Covers:

- line -> symbol mapping via the recorder's own resolution path (same qualified names);
- the story join: steps, reasoning, author, lock state, touch_count, branch summary;
- sensitive_reasoning positive and negative, with the matched keywords;
- one_shot_confident positive and negative (multi-touch, hedging words);
- the review-first message exactly when one_shot_confident AND NOT sensitive_reasoning;
- findings on unrecorded files still produce a row (nothing silently dropped).
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path

import pytest

from codegraph_trace.branches import derive_branches
from codegraph_trace.config import TraceConfig
from codegraph_trace.flag import flag_findings, format_report
from codegraph_trace.models import Step
from codegraph_trace.recorder import Recorder

CALC_V1 = (
    "def add(a, b):\n"
    "    return a + b\n"
    "\n"
    "\n"
    "def cache_key(a):\n"
    "    return f\"k-{a}\"\n"
)
CALC_V2 = CALC_V1 + (
    "\n"
    "\n"
    "def unsafe_query(name):\n"
    "    q = \"SELECT * FROM users WHERE name = '\" + name + \"'\"\n"
    "    return q\n"
)
CALC_V3 = CALC_V2.replace(
    "def add(a, b):\n    return a + b\n",
    "def add(a, b):\n    # checked\n    return a + b\n",
)
HUMAN_PY = "def reviewed_by_human():\n    return True\n"


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.com", *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr}")
    return proc.stdout


def _write(repo: Path, rel: str, content: str) -> None:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8", newline="\n")


def _commit(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", message)
    return _git(repo, "rev-parse", "HEAD").strip()


def _graph(db_path: Path) -> None:
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE projects (name TEXT, indexed_at TEXT, root_path TEXT);
        CREATE TABLE nodes (
            id INTEGER PRIMARY KEY, label TEXT, name TEXT, qualified_name TEXT,
            file_path TEXT, start_line INTEGER, end_line INTEGER
        );
        CREATE TABLE edges (source_id INTEGER, target_id INTEGER, type TEXT);
        """
    )
    conn.execute("INSERT INTO projects VALUES (?, ?, ?)", ("scratch", "2026", "src"))
    conn.executemany(
        "INSERT INTO nodes VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            (1, "File", "calc.py", "scratch.src.calc", "src/calc.py", 0, 0),
            (2, "Function", "add", "scratch.src.calc.add", "src/calc.py", 1, 2),
        ],
    )
    conn.commit()
    conn.close()


def _finding(check_id: str, path: str, start: int, end: int, severity: str = "ERROR"):
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": start, "col": 1},
        "end": {"line": end, "col": 1},
        "extra": {"severity": severity, "message": f"{check_id} message"},
    }


@pytest.fixture
def recorded_repo(tmp_path: Path):
    """Three agent steps plus one human step, branch ledger derived.

    Final src/calc.py:  add (touched twice, hedged reasoning on the second touch),
    cache_key (one confident pass, no security vocabulary), unsafe_query (one pass,
    security vocabulary in the reasoning). src/human.py is a locked human edit.
    src/other.py exists on disk but was never recorded.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _write(repo, "src/calc.py", CALC_V1)
    sha1 = _commit(repo, "step1")
    _write(repo, "src/calc.py", CALC_V2)
    sha2 = _commit(repo, "step2")
    _write(repo, "src/calc.py", CALC_V3)
    sha3 = _commit(repo, "step3")
    _write(repo, "src/human.py", HUMAN_PY)
    sha4 = _commit(repo, "human edit")
    # On disk, never committed to the trace: the finding must still produce a row.
    _write(repo, "src/other.py", "def orphan():\n    return 0\n")

    graph_db = tmp_path / "graph.db"
    _graph(graph_db)

    config = TraceConfig(repo_root=repo, graph_db_path=graph_db, embedding_model="hash")
    with Recorder(config, enable_embeddings=False) as rec:
        rec.record_step(Step(step_id="oh-conv1-1", prompt="create the calculator",
                             reasoning_text="create add and the cache key helper in one pass",
                             before_sha=None, after_sha=sha1))
        rec.record_step(Step(step_id="oh-conv1-2", prompt="add a lookup",
                             reasoning_text="concatenate the sql query; sanitize input later "
                                            "to avoid injection",
                             before_sha=sha1, after_sha=sha2))
        rec.record_step(Step(step_id="oh-conv1-3", prompt="harden add",
                             reasoning_text="maybe verify the add edge cases",
                             before_sha=sha2, after_sha=sha3))
        rec.record_step(Step(step_id="human-abc1234", prompt="",
                             reasoning_text="hand-reviewed helper",
                             before_sha=sha3, after_sha=sha4, author="human"))
    derive_branches(config)
    return config, repo


def _rows_by_check(config: TraceConfig, findings: list[dict], tmp_path: Path) -> dict:
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(json.dumps({"results": findings}), encoding="utf-8")
    report = flag_findings(config, findings_path)
    assert report.findings_total == len(findings)
    assert len(report.rows) == len(findings)
    return {r["check_id"]: r for r in report.rows}


def test_symbol_mapping_and_story(recorded_repo, tmp_path):
    config, repo = recorded_repo
    rows = _rows_by_check(config, [
        _finding("rule.sqli", "src/calc.py", 11, 11),
        _finding("rule.add", "src/calc.py", 1, 1, severity="WARNING"),
    ], tmp_path)

    sqli = rows["rule.sqli"]
    assert sqli["symbol"] == "scratch.src.calc.unsafe_query"
    assert sqli["symbol_kind"] == "Function"
    assert sqli["location"] == "src/calc.py:11"
    assert sqli["severity"] == "ERROR"
    assert sqli["author"] == "agent"
    assert sqli["locked"] is False
    assert sqli["touch_count"] == 1
    assert [s["step_id"] for s in sqli["steps"]] == ["oh-conv1-2"]
    assert any("sanitize" in s for s in sqli["reasoning_snippets"])

    add = rows["rule.add"]
    assert add["symbol"] == "scratch.src.calc.add"
    assert add["touch_count"] == 2
    assert [s["step_id"] for s in add["steps"]] == ["oh-conv1-1", "oh-conv1-3"]
    assert add["branch_summary"]["attempts"] >= 1


def test_sensitive_reasoning_signal(recorded_repo, tmp_path):
    config, repo = recorded_repo
    rows = _rows_by_check(config, [
        _finding("rule.sqli", "src/calc.py", 11, 11),
        _finding("rule.cache", "src/calc.py", 6, 6),
    ], tmp_path)

    sens = rows["rule.sqli"]["heuristics"]["sensitive_reasoning"]
    assert sens["value"] is True
    assert {"sql", "sanitize", "injection"} <= set(sens["matched"])

    clean = rows["rule.cache"]["heuristics"]["sensitive_reasoning"]
    assert clean["value"] is False
    assert clean["matched"] == []


def test_one_shot_confident_and_review_first(recorded_repo, tmp_path):
    config, repo = recorded_repo
    rows = _rows_by_check(config, [
        _finding("rule.cache", "src/calc.py", 6, 6),
        _finding("rule.sqli", "src/calc.py", 11, 11),
        _finding("rule.add", "src/calc.py", 1, 1),
    ], tmp_path)

    # cache_key: one confident pass, no security vocabulary -> the case to surface.
    cache = rows["rule.cache"]["heuristics"]
    assert cache["one_shot_confident"]["value"] is True
    assert cache["review_first"] is True
    assert "hallucinated safety" in cache["note"]

    # unsafe_query: one pass, but the reasoning did consider security -> no warning.
    sqli = rows["rule.sqli"]["heuristics"]
    assert sqli["one_shot_confident"]["value"] is True
    assert sqli["review_first"] is False
    assert sqli["note"] is None

    # add: touched twice AND hedged reasoning -> not one-shot.
    add = rows["rule.add"]["heuristics"]
    assert add["one_shot_confident"]["value"] is False
    assert {"maybe", "verify"} <= set(add["one_shot_confident"]["hedging_matched"])
    assert add["review_first"] is False


def test_human_author_and_lock(recorded_repo, tmp_path):
    config, repo = recorded_repo
    rows = _rows_by_check(config, [
        _finding("rule.human", "src/human.py", 1, 2),
    ], tmp_path)
    row = rows["rule.human"]
    assert row["symbol"] == "scratch.src.human.reviewed_by_human"
    assert row["author"] == "human"
    assert row["locked"] is True


def test_unrecorded_file_still_produces_row(recorded_repo, tmp_path):
    config, repo = recorded_repo
    rows = _rows_by_check(config, [
        _finding("rule.orphan", "src/other.py", 1, 1),
    ], tmp_path)
    row = rows["rule.orphan"]
    assert row["symbol"] == "scratch.src.other.orphan"
    assert row["steps"] == []
    assert row["touch_count"] == 0
    assert row["author"] is None
    # Never recorded means we cannot call it a confident single pass.
    assert row["heuristics"]["one_shot_confident"]["value"] is False


def test_cli_flag_json_and_text(recorded_repo, tmp_path, capsys):
    from codegraph_trace.cli import main

    config, repo = recorded_repo
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        json.dumps({"results": [
            _finding("rule.cache", "src/calc.py", 6, 6),
            _finding("rule.sqli", "src/calc.py", 11, 11),
        ]}),
        encoding="utf-8",
    )

    rc = main(["flag", "--findings", str(findings_path), "--json",
               "--repo", str(repo), "--graph-db", str(config.graph_db_path)])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["findings_total"] == 2
    assert {r["check_id"] for r in data["rows"]} == {"rule.cache", "rule.sqli"}

    rc = main(["flag", "--findings", str(findings_path),
               "--repo", str(repo), "--graph-db", str(config.graph_db_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Semgrep triage report" in out
    assert "scratch.src.calc.unsafe_query" in out
    assert "possible hallucinated safety" in out
    assert "heuristics:" in out.lower()


def test_cli_flag_save_persists_report(recorded_repo, tmp_path, capsys):
    """--save writes the report to .codegraph-trace/findings-report.json (the panel's
    has-finding filter reads it); stdout stays pure JSON with --json."""
    from codegraph_trace.cli import main

    config, repo = recorded_repo
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        json.dumps({"results": [_finding("rule.sqli", "src/calc.py", 11, 11)]}),
        encoding="utf-8",
    )

    rc = main(["flag", "--findings", str(findings_path), "--json", "--save",
               "--repo", str(repo), "--graph-db", str(config.graph_db_path)])
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)  # stdout is still valid JSON
    assert data["findings_total"] == 1

    saved_path = config.trace_dir / "findings-report.json"
    assert saved_path.is_file()
    saved = json.loads(saved_path.read_text(encoding="utf-8"))
    assert saved["findings_total"] == 1
    assert saved["rows"][0]["check_id"] == "rule.sqli"


def test_missing_findings_file(recorded_repo, capsys):
    from codegraph_trace.cli import main

    config, repo = recorded_repo
    rc = main(["flag", "--findings", str(repo / "nope.json"), "--repo", str(repo),
               "--graph-db", str(config.graph_db_path)])
    assert rc == 1
    assert "not found" in capsys.readouterr().err


def test_format_report_empty():
    from codegraph_trace.flag import FlagReport

    assert "No Semgrep findings" in format_report(FlagReport(rows=[], findings_total=0))
