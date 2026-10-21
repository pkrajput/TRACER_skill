"""Normalize recorded SWE-agent traces without executing any recorded command.

Views are deliberately separate from the evaluator-facing manifest. No security
labels, CVE metadata, golden patches, or upstream fixes are imported into a view.
Source snapshots recovered here are file-level observations, not complete Git
trees. Shell commands invalidate continuity; they are never replayed.
"""
from __future__ import annotations

import argparse
import ast
import collections
import gzip
import hashlib
import json
import re
import sys
import textwrap
from pathlib import Path, PurePosixPath
from typing import Any

VERSION = "recorded-history-v1"
NUMBERED = re.compile(r"^\s*(\d+)\t(.*)$")
EVALUATOR_MARKERS = re.compile(
    r"\b(?:SecPass|FuncPass|FAIL_TO_PASS|PASS_TO_PASS)\b|"
    r"(?:[\"'](?:test_patch|security_patch|gold_patch)[\"']\s*:)|"
    r"(?:susvibes[/\\]eval|/workspace/fix-run\.sh)", re.I)
FUTURE_READ = re.compile(
    r"\bgit\s+(?:-[^\s]+\s+)*(?:show|log|reflog|rev-list|blame)\b|"
    r"\b(?:curl|wget)\b[^\n]*(?:github|cve|advisory)|"
    r"(?:^|[\s/])\.git/(?:objects|logs)/", re.I)
TRUNCATION = re.compile(r"<response clipped>|\[.*truncat.*\]|<truncated>|"
                        r"has been truncated|output was truncated", re.I)


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode()


def sha(data: bytes | str) -> str:
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()


def read_bytes(path: Path) -> bytes:
    data = path.read_bytes()
    return gzip.decompress(data) if data.startswith(b"\x1f\x8b") else data


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n")


def write_gzip_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Empty filename and mtime=0 make outputs independent of machine and clock.
    with path.open("wb") as out:
        with gzip.GzipFile(filename="", fileobj=out, mode="wb", mtime=0) as z:
            z.write(canonical(value))


def content_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    if isinstance(value, list):
        return "\n".join(x.get("text", "") for x in value if isinstance(x, dict))
    return str(value)


def project_path(value: Any) -> str | None:
    if not isinstance(value, str) or "\x00" in value:
        return None
    path = PurePosixPath(value)
    if ".." in path.parts or not value.startswith("/project/"):
        return None
    return str(path.relative_to("/project"))


def numbered_lines(text: str) -> list[tuple[int, str]]:
    return [(int(m.group(1)), m.group(2)) for line in text.splitlines()
            if (m := NUMBERED.match(line))]


def full_view(args: dict, observation: str) -> tuple[str | None, str]:
    """Decode only explicitly unbounded, complete numbered file views.

    Display text cannot establish tabs/line endings in the original file. The
    returned source is labelled display-normalized and is useful for ASTs only.
    """
    if args.get("command") != "view" or args.get("view_range") is not None:
        return None, "not_unbounded_view"
    expected_header = f"result of running `cat -n` on {args.get('path')}:"
    if expected_header not in observation:
        return None, "not_numbered_file_view"
    if TRUNCATION.search(observation):
        return None, "truncated_observation"
    lines = numbered_lines(observation)
    if not lines or [n for n, _ in lines] != list(range(1, len(lines) + 1)):
        return None, "incomplete_or_noncontiguous_line_numbers"
    return "\n".join(line for _, line in lines) + "\n", "unbounded_numbered_view"


def snippet_agrees(source: str, observation: str) -> bool:
    lines = source.splitlines()
    observed = numbered_lines(observation)
    return bool(observed) and all(0 < n <= len(lines) and lines[n - 1] == text
                                  for n, text in observed)


def apply_editor(before: str | None, args: dict, observation: str) -> tuple[str | None, str]:
    """Pure string reconstruction, requiring success and a matching observed snippet."""
    cmd = args.get("command")
    if cmd == "create":
        if "File created successfully at:" not in observation or not isinstance(args.get("file_text"), str):
            return None, "create_not_acknowledged"
        return args["file_text"].expandtabs(), "successful_create_payload_not_byte_verified"
    if cmd not in {"str_replace", "insert"}:
        return None, "unsupported_editor_operation"
    if "has been edited" not in observation:
        return None, "edit_not_acknowledged"
    if before is None:
        return None, "no_continuous_prior_file_state"
    if cmd == "str_replace":
        old, new = args.get("old_str"), args.get("new_str", "")
        if not isinstance(old, str) or not old or not isinstance(new, str):
            return None, "invalid_replacement"
        old, new = old.expandtabs(), new.expandtabs()
        if before.count(old) != 1:
            return None, "replacement_not_unique"
        after = before.replace(old, new, 1)
    else:
        at, new = args.get("insert_line"), args.get("new_str")
        lines = before.split("\n")
        if type(at) is not int or not 0 <= at <= len(lines) or not isinstance(new, str):
            return None, "invalid_insertion"
        after = "\n".join(lines[:at] + new.expandtabs().split("\n") + lines[at:])
    if not snippet_agrees(after, observation):
        return None, "post_edit_snippet_not_confirmed"
    return after, "deterministic_editor_edit_and_matching_observed_snippet"


def dotted(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def structural_index(source: str, path: str) -> dict:
    """Syntax-only structural facts; name-shaped calls are not resolved flow edges."""
    if not path.endswith((".py", ".pyi")):
        return {"parse_status": "not_python", "symbols": [], "calls": [], "guards": []}
    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError, RecursionError) as error:
        return {"parse_status": "syntax_error", "error_type": type(error).__name__,
                "error_line": getattr(error, "lineno", None), "symbols": [], "calls": [], "guards": []}
    symbols, calls, guards = [], [], []

    def visit(node: ast.AST, scope: tuple[str, ...]) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            scope = (*scope, node.name)
            symbols.append({"name": node.name, "qualified_name": ".".join(scope),
                            "kind": type(node).__name__, "start_line": node.lineno,
                            "end_line": node.end_lineno,
                            "ast_sha256": sha(ast.dump(node, include_attributes=False))})
        if isinstance(node, ast.Call):
            calls.append({"scope": ".".join(scope) or "<module>",
                          "callee_syntax": dotted(node.func), "line": node.lineno,
                          "resolved": False})
        if isinstance(node, (ast.If, ast.While, ast.Assert)):
            guards.append({"scope": ".".join(scope) or "<module>", "line": node.lineno,
                           "kind": type(node).__name__, "test_syntax": ast.unparse(node.test),
                           "ast_sha256": sha(ast.dump(node.test, include_attributes=False))})
        for child in ast.iter_child_nodes(node):
            visit(child, scope)

    visit(tree, ())
    return {"parse_status": "parsed", "semantic_flow_available": False,
            "symbols": symbols, "calls": calls, "guards": guards}


def structural_delta(before: dict | None, after: dict) -> dict:
    old = {s["qualified_name"]: s["ast_sha256"] for s in (before or {}).get("symbols", [])}
    new = {s["qualified_name"]: s["ast_sha256"] for s in after.get("symbols", [])}
    return {"introduced_symbols": sorted(new.keys() - old.keys()),
            "removed_symbols": sorted(old.keys() - new.keys()),
            "changed_symbols": sorted(k for k in old.keys() & new.keys() if old[k] != new[k]),
            "comparable_prior_state": before is not None,
            "same_name_linkage_only": True}


def normalize(messages: list[dict], raw_hash: str, *, cutoff_message: int | None = None) -> dict:
    """Return immutable provenance events and reconstruction audit for one trace.

    The first suspected evaluator/future-history read truncates the investigator
    history. Later contaminated rationale is therefore not inadvertently kept.
    Detection is a conservative audit aid, not a proof that no semantic leakage
    exists. Recorded source/test observations remain equally available in B3/B4.
    """
    if not isinstance(messages, list) or not all(isinstance(m, dict) for m in messages):
        raise ValueError("Expected list of recorded message objects")
    cutoff = len(messages) if cutoff_message is None else max(0, min(cutoff_message, len(messages)))
    exclusions, events, states, reconstruction, edit_records = [], [], [], [], []
    active: dict[str, dict] = {}
    actions: dict[str, list[dict]] = collections.defaultdict(list)
    assistant_rationale: dict[int, list[str]] = collections.defaultdict(list)
    all_action_payloads, separate_reasoning_fields = [], collections.Counter()

    def event(kind: str, index: int, data: dict, suffix: str = "") -> dict:
        obj = {"event_id": f"m{index:06d}:{kind}{suffix}", "kind": kind,
               "channel": "recorded_agent", "message_index": index,
               "source_trace_sha256": raw_hash, **data}
        events.append(obj)
        return obj

    for i, message in enumerate(messages):
        if i >= cutoff:
            exclusions.append({"message_index": i, "reason": "after_evidence_cutoff"})
            continue
        role, content = message.get("role"), content_text(message.get("content"))
        calls = message.get("tool_calls") or []
        if not isinstance(calls, list):
            raise ValueError(f"Non-list tool_calls at message {i}")
        combined = content + "\n" + json.dumps(calls, ensure_ascii=False)
        # Commands in the initial task instructions are quoted constraints, not
        # actions. Future-history detection is applied only to actual tools.
        leak = EVALUATOR_MARKERS.search(combined)
        future = any(FUTURE_READ.search(str(t.get("function", {}).get("arguments", ""))) for t in calls)
        if role not in {"system", "user", "assistant", "tool"} or leak or future:
            reason = "suspected_evaluator_feedback" if leak or role not in {"system", "user", "assistant", "tool"} else "suspected_upstream_or_future_history_read"
            exclusions.append({"message_index": i, "reason": reason,
                               "matched_marker": leak.group(0) if leak else None})
            cutoff = i
            continue
        if role in {"system", "user"}:
            event("context", i, {"role": role, "content": content})
        elif role == "assistant":
            if content.strip():
                obj = event("rationale", i, {"source_field": "content", "text": content,
                                             "rationale_kind": "exposed_assistant_prose_not_private_cot"})
                assistant_rationale[i].append(obj["event_id"])
            for field in ("reasoning_content", "reasoning", "thinking"):
                text = content_text(message.get(field))
                if text.strip():
                    separate_reasoning_fields[field] += 1
                    obj = event("rationale", i, {"source_field": field, "text": text,
                                                 "rationale_kind": "published_explicit_reasoning_field"}, f":{field}")
                    assistant_rationale[i].append(obj["event_id"])
            for j, call in enumerate(calls):
                fn = call.get("function") or {}
                arg_raw = fn.get("arguments")
                try:
                    args = json.loads(arg_raw) if isinstance(arg_raw, str) else arg_raw
                    if not isinstance(args, dict):
                        raise ValueError("arguments not object")
                except (ValueError, TypeError):
                    args = None
                obj = event("action", i, {"tool_call_id": call.get("id"),
                                           "tool_name": fn.get("name"), "arguments_raw": arg_raw,
                                           "arguments": args, "source_call_index": j}, f":{j}")
                all_action_payloads.append(obj)
                actions[str(call.get("id"))].append(obj)
                if fn.get("name") != "str_replace_editor" and fn.get("name") != "submit":
                    reconstruction.append({"event_id": obj["event_id"], "reason": "unreplayed_tool_may_change_files",
                                           "invalidated_paths": sorted(active)})
                    active.clear()
        else:
            call_id = str(message.get("tool_call_id"))
            matching = actions.get(call_id, [])
            # Tool IDs may repeat across a transcript. Match the most recent
            # preceding unconsumed action, never a future action.
            action = next((a for a in reversed(matching) if not a.get("observation_event_id")), None)
            obs = event("observation", i, {"tool_call_id": message.get("tool_call_id"), "content": content,
                                          "action_event_id": action["event_id"] if action else None})
            if action is None:
                reconstruction.append({"event_id": obs["event_id"], "reason": "unmatched_tool_observation"})
                continue
            action["observation_event_id"] = obs["event_id"]
            args = action["arguments"]
            if action["tool_name"] != "str_replace_editor" or not isinstance(args, dict):
                continue
            path = project_path(args.get("path"))
            if not path:
                reconstruction.append({"event_id": obs["event_id"], "reason": "not_project_file_path",
                                       "original_path": args.get("path")})
                continue
            before_state = active.get(path)
            if args.get("command") != "view":
                fragments = {key: args[key] for key in ("old_str", "new_str", "file_text") if isinstance(args.get(key), str)}
                edit_records.append({"edit_id": action["event_id"], "path": path,
                                     "message_index": i, "action_event_id": action["event_id"],
                                     "observation_event_id": obs["event_id"], "command": args.get("command"),
                                     "fragments": fragments,
                                     "success_acknowledged": "has been edited" in content or "File created successfully at:" in content,
                                     "fragment_structure": {key: structural_index(textwrap.dedent(text), path)
                                                            for key, text in fragments.items()},
                                     "complete_file_state": False,
                                     "rationale_event_ids": assistant_rationale[action["message_index"]]})
            source, status = full_view(args, content) if args.get("command") == "view" else apply_editor(
                before_state["source"] if before_state else None, args, content)
            if source is None:
                reconstruction.append({"event_id": obs["event_id"], "path": path, "reason": status})
                if args.get("command") != "view":
                    # Even an unsuccessful/unsupported edit can have partial
                    # effects; do not carry forward an assumed exact state.
                    active.pop(path, None)
                continue
            index = structural_index(source, path)
            sid = f"{obs['event_id']}:{sha(path)[:10]}"
            previous = before_state["state_id"] if before_state else None
            state = {"state_id": sid, "channel": "recorded_agent", "path": path,
                     "source": source, "source_sha256": sha(source), "source_event_id": obs["event_id"],
                     "action_event_id": action["event_id"], "message_index": i,
                     "source_trace_sha256": raw_hash, "previous_continuous_state_id": previous,
                     "source_fidelity": status, "byte_identical_source_verified": False,
                     "complete_repository_state": False,
                     "rationale_event_ids": assistant_rationale[action["message_index"]],
                     "structure": index,
                     "structural_delta": structural_delta(before_state["structure"] if before_state else None, index)}
            states.append(state)
            active[path] = state
    # All generated views are based only on the original transcript. Source
    # record metadata and all published/local oracle outcomes stay elsewhere.
    return {"schema_version": VERSION, "source_trace_sha256": raw_hash,
            "original_message_count": len(messages), "cutoff_message": cutoff,
            "events": events, "states": states, "edit_records": edit_records, "exclusions": exclusions,
            "reconstruction_audit": reconstruction,
            "separate_reasoning_fields": dict(separate_reasoning_fields),
            "path_mapping": {"accepted_absolute_prefix": "/project/", "mapped_prefix": "",
                             "relative_paths_in_actions": "unresolved_no_cwd_inference",
                             "parent_segments": "rejected", "basename_fallback": False},
            "all_git_history": [], "git_history_status": "separate_adapter_required"}


def build_view(normalized: dict, *, rationale: bool, arm: str | None = None) -> dict:
    """Construct B3/B4 with identical non-rationale event/state payloads."""
    arm = arm or ("B4" if rationale else "B3")
    if arm not in {"B2", "B3", "B4"} or rationale != (arm == "B4"):
        raise ValueError("Only B4 permits original rationale")
    events = [e for e in normalized["events"] if rationale or e["kind"] != "rationale"]
    omit = {"rationale_event_ids"} | ({"structure", "structural_delta"} if arm == "B2" else set())
    states = [{k: v for k, v in state.items() if k not in omit}
              for state in normalized["states"]]
    edit_omit = {"rationale_event_ids"} | ({"fragment_structure"} if arm == "B2" else set())
    edits = [{k: v for k, v in edit.items() if k not in edit_omit}
             for edit in normalized.get("edit_records", [])]
    view = {"schema_version": VERSION, "arm": arm,
            "source_trace_sha256": normalized["source_trace_sha256"],
            "cutoff_message": normalized["cutoff_message"], "events": events,
            "states": states, "edit_records": edits, "git_history": [],
            "scope": "recorded_agent_history_only; no_evaluator_metadata",
            "source_state_scope": "observed_or_reconstructed_files_not_complete_trees"}
    if rationale:
        view["rationale_links"] = {s["state_id"]: s["rationale_event_ids"]
                                   for s in normalized["states"] if s["rationale_event_ids"]}
        view["rationale_links"].update({e["edit_id"]: e["rationale_event_ids"]
                                        for e in normalized.get("edit_records", []) if e["rationale_event_ids"]})
    return view


def shared_payload(view: dict) -> dict:
    return {"events": [e for e in view["events"] if e["kind"] != "rationale"],
            "states": view["states"], "cutoff_message": view["cutoff_message"],
            "edit_records": view.get("edit_records", []),
            "git_history": view["git_history"]}


def process_cohort(queue: Path, source_root: Path, output: Path, *, limit: int | None = None) -> dict:
    adapter_hash = sha(Path(__file__).read_bytes())
    candidates = [json.loads(x) for x in queue.read_text().splitlines() if x.strip()]
    if limit is not None:
        candidates = candidates[:limit]
    output.mkdir(parents=True, exist_ok=True)
    summaries, models = [], collections.defaultdict(collections.Counter)
    fields, exclusions, reconstruct = collections.Counter(), collections.Counter(), collections.Counter()
    for n, row in enumerate(candidates, 1):
        trace = row["trajectory"]
        path = (source_root / trace["local_path"]).resolve()
        if not path.is_relative_to(source_root.resolve()):
            raise ValueError("Source path escapes source root")
        raw = read_bytes(path)
        digest = sha(raw)
        if digest != trace["sha256"]:
            raise ValueError(f"Trace hash mismatch: {path}")
        messages = json.loads(raw)
        normalized = normalize(messages, digest)
        b2 = build_view(normalized, rationale=False, arm="B2")
        b3, b4 = build_view(normalized, rationale=False), build_view(normalized, rationale=True)
        shared = sha(canonical(shared_payload(b3)))
        if shared != sha(canonical(shared_payload(b4))):
            raise AssertionError("B3/B4 action/state mismatch")
        case = sha(row["source_record_id"])[:24]
        target = output / "cases" / case
        files = {"normalized": target / "normalized.json.gz", "B2": target / "B2.json.gz", "B3": target / "B3.json.gz",
                 "B4": target / "B4.json.gz"}
        for key, value in (("normalized", normalized), ("B2", b2), ("B3", b3), ("B4", b4)):
            write_gzip_json(files[key], value)
        raw_assistant_count = sum(bool(content_text(m.get("content")).strip()) for m in messages if m.get("role") == "assistant")
        events = collections.Counter(e["kind"] for e in normalized["events"])
        python_states = [s for s in normalized["states"] if s["structure"]["parse_status"] == "parsed"]
        modified_states = [s for s in python_states if s["source_fidelity"] != "unbounded_numbered_view"]
        clean = not any(e["reason"] != "after_evidence_cutoff" for e in normalized["exclusions"])
        summary = {"case_key": case, "source_record_id": row["source_record_id"],
                   "model": row["generator"]["model"], "instance_id": row["instance_id"],
                   "source_trace_sha256": digest, "raw_assistant_prose_messages": raw_assistant_count,
                   "published_private_cot_available": False,
                   "explicit_reasoning_field_counts": normalized["separate_reasoning_fields"],
                   "cutoff_message": normalized["cutoff_message"], "original_messages": len(messages),
                   "event_counts": dict(events), "recovered_file_states": len(normalized["states"]),
                   "recorded_editor_edits": len(normalized["edit_records"]),
                   "parsed_python_states": len(python_states), "parsed_python_edit_states": len(modified_states),
                   "distinct_recovered_python_paths": len({s["path"] for s in python_states}),
                   "whole_repository_state_verified": False,
                   "automatic_leakage_marker_scan_clean": clean,
                   "manual_leakage_audit_complete": False,
                   "rationale_contrast_available": events["rationale"] > 0,
                   "eligible_for_scored_h4": False,
                   "eligibility_pending": ["source_state_and_alert_linkage", "independent_security_label", "manual_leakage_audit"],
                   "shared_actions_observations_states_sha256": shared,
                   "view_paths": {k: str(p.relative_to(output)) for k, p in files.items()},
                   "view_sha256": {k: sha(p.read_bytes()) for k, p in files.items()},
                   "exclusion_counts": dict(collections.Counter(e["reason"] for e in normalized["exclusions"]))}
        summaries.append(summary)
        count = models[summary["model"]]
        count["traces"] += 1
        count["raw_traces_with_assistant_prose"] += bool(raw_assistant_count)
        count["view_traces_with_rationale"] += events["rationale"] > 0
        count["traces_with_parsed_python_state"] += bool(python_states)
        count["traces_with_parsed_python_edit_state"] += bool(modified_states)
        count["parsed_python_states"] += len(python_states)
        count["parsed_python_edit_states"] += len(modified_states)
        count["recorded_editor_edits"] += len(normalized["edit_records"])
        count["traces_with_suspected_leakage_markers"] += not clean
        for field, number in normalized["separate_reasoning_fields"].items():
            fields[field] += number
        exclusions.update(summary["exclusion_counts"])
        reconstruct.update(x["reason"] for x in normalized["reconstruction_audit"])
        if n % 100 == 0 or n == len(candidates):
            print(json.dumps({"processed": n, "total": len(candidates)}), flush=True)
    index = output / "index.jsonl"
    index.write_text("".join(json.dumps(s, sort_keys=True) + "\n" for s in summaries))
    report = {"schema_version": VERSION, "source_queue_sha256": sha(queue.read_bytes()),
              "adapter_source_sha256": adapter_hash, "case_count": len(summaries),
              "models": {k: dict(v) for k, v in models.items()}, "explicit_reasoning_fields": dict(fields),
              "exclusion_counts": dict(exclusions), "reconstruction_event_counts": dict(reconstruct),
              "index_sha256": sha(index.read_bytes()), "target_code_executed": False,
              "archived_commands_replayed": False, "paid_model_calls": 0,
              "source_bytes_read": "hash_verified_against_pinned_acquisition_manifest",
              "path_mapping": {"accepted_absolute_prefix": "/project/", "mapped_prefix": "",
                               "unresolved_events": reconstruct["not_project_file_path"],
                               "basename_fallback": False, "relative_paths": "unresolved"},
              "limitations": ["Exposed assistant prose is not authenticated private CoT",
                              "File observations are display normalized, not complete byte-verified trees",
                              "Unknown commands invalidate current file reconstruction continuity",
                              "Syntax-shaped call names are not resolved semantic data flow",
                              "Automatic leakage screening requires manual validation before H4",
                              "No Git history or evaluator outcomes are included in investigator views"]}
    write_json(output / "summary.json", report)
    return report


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", type=Path, default=root / "experiment_setup/primary_candidate_queue.jsonl")
    parser.add_argument("--source-root", type=Path, default=root / "public_trajectories/susvibes_leaderboard")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    print(json.dumps(process_cohort(args.queue, args.source_root, args.output, limit=args.limit), indent=2))


if __name__ == "__main__":
    main()
