"""Independent Git, archived agent AST edits, and exposed rationale channels.

No golden implementation, CVE label, security test, or benchmark outcome is read.
Git ancestry alone does not prevent masked-function answer leakage: callers must
explicitly attest that pre-reference history is allowed for a selected target.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path
import re
import textwrap

from .gumtree import digest, summarize_pair
from .rationale import build_rationale
from ..runtime.git_history.query import GitHistoryView
from ..runtime.history.adapter import read_bytes, normalize, build_view
from ..runtime.history.query import current_fragment_anchors


def _brief(record: dict) -> dict:
    result = {key: value for key, value in record.items() if key != 'operations'}
    result['node_changes'] = [
        {'operation': op['operation'], 'node_type': op['node_type'],
         **{side: {k: op[side][k] for k in ['scope', 'line', 'end_line', 'field', 'label'] if k in op[side]}
            if op.get(side) else None for side in ['before', 'after']}}
        for op in record.get('operations', [])[:12]]
    result['node_changes_omitted'] = max(0, record.get('relevant_operation_count',0)-len(result['node_changes']))
    return result


def parseable_fragment(text):
    """Restore only omitted first-line indentation; preserve all other lines.

    Some editor excerpts start at 'def' inside an indented class. Trying the
    recorded sibling-definition indent is explicit normalization, not an old
    repository reconstruction. The original fragment hashes remain recorded.
    """
    ordinary=textwrap.dedent(text)
    try:ast.parse(ordinary);return ordinary,0
    except (SyntaxError,ValueError):pass
    lines=text.splitlines(True)
    if lines and re.match(r'^(?:async\s+)?def\s|^class\s',lines[0]):
        widths=sorted({len(m.group(1)) for line in lines[1:] if (m:=re.match(r'^( +)(?:async\s+)?(?:def|class)\s',line))})
        for width in widths:
            candidate=textwrap.dedent(' '*width+text)
            try:ast.parse(candidate);return candidate,width
            except (SyntaxError,ValueError):pass
    return ordinary,0


def parseable_pair(before,after):
    a,ai=parseable_fragment(before);b,bi=parseable_fragment(after);omitted=None
    try:ast.parse(a);ast.parse(b)
    except SyntaxError:
        old_lines=before.rstrip().splitlines();new_lines=after.rstrip().splitlines()
        # Editor replacement context can end at the next untouched def header.
        # Remove it only when identical on both sides and both remainders parse;
        # never synthesize a missing body or repair changed statements.
        if old_lines and new_lines and old_lines[-1]==new_lines[-1] and re.match(r'^\s*(?:async\s+)?def\s+.+:\s*$',old_lines[-1]):
            aa,ii=parseable_fragment('\n'.join(old_lines[:-1]));bb,jj=parseable_fragment('\n'.join(new_lines[:-1]))
            try:ast.parse(aa);ast.parse(bb)
            except SyntaxError:pass
            else:a,b,ai,bi,omitted=aa,bb,ii,jj,old_lines[-1]
    return a,b,{'before_first_line_indent_added':ai,'after_first_line_indent_added':bi,
                'identical_incomplete_trailing_context_omitted':omitted}


def _bound_records(records: list[dict], max_chars: int) -> tuple[list[dict], int]:
    # Reserve a first history hint for each target before giving one target
    # several large transitions. Targets arrive in changed-code priority order.
    groups={}
    for record in records:
        names=tuple(a['current_symbol'] for a in record.get('current_symbol_anchors',[])) or (record.get('symbol_filter'),)
        groups.setdefault((record['path'],names),[]).append(record)
    kept,size=[],0;allowance=max_chars//max(1,len(groups))
    def compact(record):
        value=dict(record)
        if len(json.dumps(value,ensure_ascii=False))<=allowance:return value
        value['budget_abbreviated']=True
        value['unabridged_record_sha256']=digest(json.dumps(record,sort_keys=True))
        if 'matcher' in value:value['matcher_manifest_sha256']=value.pop('matcher')['manifest_sha256']
        value['node_changes_omitted']=value.get('node_changes_omitted',0)+len(value.get('node_changes',[]));value['node_changes']=[]
        value['symbol_hints']=[{**h,'hint':h['hint'][:260],'hint_abbreviated':len(h['hint'])>260} for h in value.get('symbol_hints',[])[:1]]
        return value
    # Most recent recorded transition first within each target, then older ones.
    queues=[sorted(values,key=lambda r:r.get('after_message',0),reverse=True) for values in groups.values()]
    for round_index in range(max([len(q) for q in queues],default=0)):
        for queue in queues:
            if round_index>=len(queue):continue
            record=compact(queue[round_index]);length=len(json.dumps(record,ensure_ascii=False))
            if size+length<=max_chars:kept.append(record);size+=length
    return kept, len(records) - len(kept)


def agent_history(view: dict, targets: list[dict], *, source_root: Path | None = None,
                  max_pairs_per_target: int = 3, max_history_chars: int = 16000,
                  max_rationale_chars: int = 6000) -> tuple[dict, dict]:
    """Compress only recorded source pairs; never replay archived shell commands."""
    if view.get("arm") != "B4":
        raise ValueError("Use the hash-verified B4 view to extract independent evidence channels")
    if min(max_pairs_per_target, max_history_chars, max_rationale_chars) < 0:
        raise ValueError("History budgets must be nonnegative")
    cutoff = int(view["cutoff_message"])
    records, gaps, seen = [], [], set()
    states = {s["state_id"]: s for s in view["states"] if int(s["message_index"]) < cutoff}
    for target in targets:
        path, symbol = GitHistoryView._path(target["path"]), target.get("symbol")
        timeline = sorted((s for s in states.values() if s["path"] == path), key=lambda s: s["message_index"])
        current = None
        if source_root is not None:
            candidate = (Path(source_root) / path).resolve()
            if candidate.is_relative_to(Path(source_root).resolve()) and candidate.is_file():
                try:
                    current = candidate.read_text()
                except UnicodeError:
                    pass
        # Most recent actual observed transitions, with discontinuity explicitly labelled.
        transitions = list(zip(timeline, timeline[1:]))
        if symbol and symbol != "<module>":
            def signatures(state):
                return sorted((s["qualified_name"], s.get("ast_sha256"))
                              for s in state.get("structure", {}).get("symbols", [])
                              if s["qualified_name"] == symbol or s["qualified_name"].startswith(symbol + "."))
            transitions = [(a, b) for a, b in transitions if signatures(a) != signatures(b)]
        transitions = transitions[-max_pairs_per_target:] if max_pairs_per_target else []
        for before, after in transitions:
            identity = (before["state_id"], after["state_id"], symbol)
            if identity in seen:
                continue
            seen.add(identity)
            rec = summarize_pair(before["source"], after["source"], path,
                                 after["action_event_id"], symbol=symbol)
            if rec.get("relevant_operation_count", 0) or rec["status"] not in {"ok", "unchanged"}:
                rec.update(history_channel="recorded_agent", before_state_id=before["state_id"],
                           after_state_id=after["state_id"], before_message=before["message_index"],
                           after_message=after["message_index"], source_trace_sha256=view["source_trace_sha256"],
                           continuous_transition=after.get("previous_continuous_state_id") == before["state_id"],
                           source_fidelity=after.get("source_fidelity"), complete_repository_state=False)
                records.append(_brief(rec))
        # The final source is an observed artifact, never synthesized by replaying a shell action.
        if timeline and current is not None and current != timeline[-1]["source"]:
            last = timeline[-1]
            rec = summarize_pair(last["source"], current, path, "final-artifact:" + digest(current)[:16], symbol=symbol)
            if rec.get("relevant_operation_count", 0):
                rec.update(history_channel="recorded_agent", before_state_id=last["state_id"],
                           before_message=last["message_index"], after_message=cutoff,
                           source_trace_sha256=view["source_trace_sha256"],
                           source_fidelity="recorded_observation_compared_to_exported_final_source",
                           continuous_transition=False, complete_repository_state=False,
                           attribution="net_change_only; intermediate commands and intent are not reconstructed")
                records.append(_brief(rec))
        edits = [e for e in view.get("edit_records", []) if e["path"] == path and
                 int(e["message_index"]) < cutoff and e.get("success_acknowledged")]
        relevant_edits=edits
        if symbol:
            relevant_edits=[e for e in edits if (current is not None and current_fragment_anchors(current,path,symbol,e)) or any(
                re.search(r'\bdef\s+'+re.escape(symbol.split('.')[-1])+r'\s*\(',text) for text in e.get('fragments',{}).values())]
        for edit in (relevant_edits[-max_pairs_per_target:] if max_pairs_per_target else []):
            fragments = edit.get("fragments", {})
            if not {"old_str", "new_str"} <= fragments.keys():
                continue
            # Do not duplicate an edit already represented by an observed whole-file pair.
            if any(r["event_id"] == edit["action_event_id"] and (r.get('symbol_filter')==symbol or
                   any(a.get('current_symbol')==symbol for a in r.get('current_symbol_anchors',[]))) for r in records):
                continue
            anchors = current_fragment_anchors(current, path, symbol, edit) if current is not None and symbol else []
            before,after,normalization=parseable_pair(fragments['old_str'],fragments['new_str'])
            if symbol and not anchors and current is not None:
                # Historical edit may have been revised later. Retain an
                # explicitly weaker name association instead of losing it.
                from .citations import symbols as source_symbols
                current_matches=[s for s in source_symbols(current) if s['symbol'].split('.')[-1]==symbol.split('.')[-1]]
                historical=[s for text in [before,after] for s in source_symbols(text) if s['symbol'].split('.')[-1]==symbol.split('.')[-1]]
                if len(current_matches)==1 and historical:
                    anchors=[{'current_symbol':symbol,'link':'unique_current_name_to_recorded_fragment',
                              'historical_scope_identity_proven':False,'exact_current_text_match':False}]
            if symbol and not anchors:
                gaps.append({'path':path,'event_id':edit['edit_id'],'target_symbol':symbol,'reason':'no_current_symbol_link_to_recorded_fragment'});continue
            from .citations import symbols as source_symbols
            fragment_names={s['symbol'] for text in [before,after] for s in source_symbols(text)
                            if symbol and s['symbol'].split('.')[-1]==symbol.split('.')[-1]}
            fragment_filter=next(iter(fragment_names)) if len(fragment_names)==1 else None
            rec = summarize_pair(before,after,path,edit['action_event_id'],symbol=fragment_filter)
            if rec.get("relevant_operation_count", 0):
                rec.update(history_channel="recorded_agent", source_trace_sha256=view["source_trace_sha256"],
                           after_message=edit["message_index"], source_fidelity="acknowledged_editor_fragment_pair",
                           continuous_transition=True, complete_file_state=False, complete_repository_state=False,
                           current_symbol_anchors=anchors,
                           raw_fragment_sha256={k:digest(fragments[k]) for k in ['old_str','new_str']},
                           fragment_normalization=normalization,
                           historical_scope_identity_proven=False)
                records.append(_brief(rec))
            elif rec["status"] not in {"ok", "unchanged"}:
                gaps.append({"path": path, "event_id": edit["edit_id"], "reason": rec["status"]})
        if not timeline and not edits:
            gaps.append({"path": path, "reason": "no_recorded_file_state_or_acknowledged_editor_edit"})
    records, omitted = _bound_records(records, max_history_chars)
    temporal = {"status": "available" if records else "no_parseable_relevant_edits", "records": records,
                "records_omitted_by_budget": omitted, "gaps": gaps,
                "source_trace_sha256": view["source_trace_sha256"], "cutoff_message": cutoff,
                "archived_commands_executed": False,
                "note": "Syntactic changes guide inspection; they do not establish semantic flow or a vulnerability."}
    rationale = build_rationale(view, targets, max_chars=max_rationale_chars, source_root=source_root)
    return temporal, rationale


def git_history(repository: Path | None, base_commit: str | None, targets: list[dict], *,
                pre_reference_allowed: bool = False, max_pairs_per_target: int = 3) -> dict:
    """Never use dates or branch tips as cutoffs; deny masked benchmark history by default."""
    if not pre_reference_allowed:
        return {"status": "withheld_pending_masked_reference_leakage_audit", "records": [],
                "reason": "Pre-reference ancestors may contain the benchmark's withheld function implementations."}
    if repository is None or base_commit is None:
        return {"status": "not_available", "records": []}
    view = GitHistoryView(repository, base_commit, arm="B3")
    records = []
    for target in targets:
        path, symbol = view._path(target["path"]), target.get("symbol")
        timeline, lineage = view._lineage(path)
        for commit in timeline[-max_pairs_per_target:]:
            # Actual first-parent pair, not an unlabelled comparison of selected snapshots.
            parents = view._metadata(commit)["parents"]
            if not parents:
                continue
            parent = view._allowed(parents[0], commit)
            before, after = view._file(parent, path), view._file(commit, path)
            if before["status"] != "available" or after["status"] != "available":
                continue
            rec = summarize_pair(before["source"], after["source"], path, "git:" + commit, symbol=symbol)
            if rec.get("relevant_operation_count", 0):
                rec.update(history_channel="git", before_commit=parent, after_commit=commit,
                           cutoff_commit=base_commit, ancestor_of_cutoff_verified=True,
                           source_fidelity="exact_git_blob", continuous_transition=True,
                           agent_reasoning_available=False)
                records.append(_brief(rec))
    return {"status": "available" if records else "no_relevant_changes", "records": records,
            "provenance": view.provenance(), "commit_messages_exposed": False,
            "raw_implementations_exposed": False,
            "masked_reference_history_explicitly_allowed_by_caller": True}


def build_history_evidence(history_root: Path, case_key: str, targets: list[dict], *,
                           source_root: Path | None = None, git_repository: Path | None = None,
                           base_commit: str | None = None, pre_reference_allowed: bool = False,
                           max_pairs_per_target: int = 3, max_history_chars: int = 16000,
                           max_rationale_chars: int = 6000) -> dict:
    """Load a pinned history view and return two independently usable arm blocks."""
    if not re.fullmatch(r"[0-9a-f]{24}", case_key):
        raise ValueError("Expected the 24-character manifest case key")
    history_root = Path(history_root).resolve()
    matches = [json.loads(line) for line in (history_root / "index.jsonl").read_text().splitlines()
               if line.strip() and json.loads(line).get("case_key") == case_key]
    if len(matches) != 1:
        raise ValueError("History index does not uniquely identify the case")
    row = matches[0]
    if not row.get("automatic_leakage_marker_scan_clean"):
        raise ValueError("Original history contains evaluator/future-history markers requiring review")
    path = (history_root / row["view_paths"]["B4"]).resolve()
    if not path.is_relative_to(history_root) or digest(path.read_bytes()) != row["view_sha256"]["B4"]:
        raise ValueError("History view path or SHA-256 mismatch")
    view = json.loads(read_bytes(path))
    if view["source_trace_sha256"] != row["source_trace_sha256"]:
        raise ValueError("Original trajectory identity mismatch")
    agent, rationale = agent_history(view, targets, source_root=source_root,
                                     max_pairs_per_target=max_pairs_per_target,
                                     max_history_chars=max_history_chars,
                                     max_rationale_chars=max_rationale_chars)
    return {"schema": "independent-history-channels-v1", "case_key": case_key,
            "temporal": {"agent": agent, "git": git_history(git_repository, base_commit, targets,
                         pre_reference_allowed=pre_reference_allowed, max_pairs_per_target=max_pairs_per_target)},
            "rationale": rationale,
            "provenance": {"history_view_sha256": row["view_sha256"]["B4"],
                           "source_trace_sha256": row["source_trace_sha256"],
                           "case_record_id": row["source_record_id"]}}


def build_case_history(case: dict, targets: list[dict], source_root: Path | None = None, *,
                       max_pairs_per_target: int = 3, max_history_chars: int = 16000,
                       max_rationale_chars: int = 6000) -> dict:
    """Case-manifest variant, including newly acquired trajectories without an index.

    Re-normalizing the hash-verified original prevents an altered view from adding
    evidence. The adapter cuts off before evaluator/future-history markers. Any
    contaminated tail is excluded and its existence reported, never exposed.
    """
    path = Path(case.get("archived_history_path") or case["history_paths"]["B4"])
    if case.get("archived_history_path"):
        if digest(path.read_bytes()) != case.get("archived_history_sha256"):
            raise ValueError("Frozen archived history view SHA-256 mismatch")
        view = json.loads(read_bytes(path))
        if view.get("arm") != "B4" or view.get("source_trace_sha256") != case["trajectory_sha256"]:
            raise ValueError("Frozen history view does not identify the original trajectory")
        normalized = None
    else:
        raw = read_bytes(Path(case["trajectory_path"]))
        if digest(raw) != case["trajectory_sha256"]:
            raise ValueError("Original trajectory SHA-256 mismatch")
        normalized = normalize(json.loads(raw), case["trajectory_sha256"])
        expected = build_view(normalized, rationale=True)
        view = json.loads(read_bytes(path))
        if view != expected:
            raise ValueError("History view differs from its verified original trajectory")
    agent, rationale = agent_history(view, targets, source_root=source_root,
                                     max_pairs_per_target=max_pairs_per_target,
                                     max_history_chars=max_history_chars,
                                     max_rationale_chars=max_rationale_chars)
    if normalized is None:
        screening = dict(case["archived_history_screening"])
        screening.update(cutoff_message=view["cutoff_message"], archived_normalized_view=True)
    else:
        exclusions = [e for e in normalized["exclusions"] if e["reason"] != "after_evidence_cutoff"]
        screening = {"status": "truncated_before_suspected_leakage" if exclusions else "no_automatic_markers_detected",
                     "cutoff_message": normalized["cutoff_message"], "original_message_count": len(json.loads(raw)),
                     "exclusion_reasons": sorted({e["reason"] for e in exclusions}),
                     "manual_semantic_leakage_audit_complete": False}
    return {"schema": "independent-history-channels-v1", "case_key": case["case_key"],
            "temporal": {"agent": agent, "git": git_history(None, None, targets)},
            "rationale": rationale,
            "provenance": {"history_view_sha256": digest(path.read_bytes()),
                           "source_trace_sha256": case["trajectory_sha256"],
                           "case_record_id": case["record_id"], "screening": screening}}
