"""Build a small, inspectable TRACER history without a model or API key.

Run from the artifact root after installing ./tracer:
    python tracer/examples/quickstart.py
The example creates a fresh temporary Git repository and prints its location.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "commit.gpgsign=false", *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def trace(repo: Path, *args: str) -> None:
    subprocess.run(
        [sys.executable, "-m", "codegraph_trace.cli", *args, "--repo", str(repo)],
        check=True,
    )


def main() -> None:
    repo = Path(tempfile.mkdtemp(prefix="tracer-demo-"))
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.name", "TRACER Demo")
    git(repo, "config", "user.email", "demo@example.invalid")
    git(repo, "config", "core.autocrlf", "false")
    (repo / ".gitignore").write_text(".codegraph-trace/\n", encoding="utf-8")
    git(repo, "add", ".gitignore")
    git(repo, "commit", "-m", "Initialize demo")
    before = git(repo, "rev-parse", "HEAD")

    attempts = [
        (
            "attempt-1",
            "def unique(items):\n    return list(set(items))\n",
            "Use a set to remove duplicate values.",
            "Remove duplicate values.",
        ),
        (
            "attempt-2",
            "def unique(items):\n    return list(dict.fromkeys(items))\n",
            "Preserve first-seen order while removing duplicates; replace the set approach.",
            "Keep the original order too.",
        ),
    ]
    print(f"Demo repository: {repo}\n", flush=True)
    for step_id, source, rationale, prompt in attempts:
        (repo / "unique.py").write_text(source, encoding="utf-8")
        git(repo, "add", "unique.py")
        git(repo, "commit", "-m", step_id)
        after = git(repo, "rev-parse", "HEAD")
        trace(
            repo, "record", step_id, "--author", "agent", "--prompt", prompt,
            "--reasoning", rationale, "--before", before, "--after", after,
            "--no-embeddings",
        )
        before = after

    trace(repo, "branches", "derive")
    trace(repo, "history", "unique.py")
    trace(repo, "branches", "show", "unique.py")
    print(f"\nKeep exploring: codegraph-trace history unique.py --repo {repo}")
    print(f"Optional panel: codegraph-trace panel --repo {repo}")
    print("The demo repository is kept for inspection; remove it when finished.")


if __name__ == "__main__":
    main()
