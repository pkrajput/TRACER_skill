"""Read-only retrieval over an already constructed B3 or B4 evidence view.

This is a recorded-history component, not a security investigator. Returned call
edges are syntactic names, not CodeQL semantic flow. File states never imply an
entire repository checkpoint. The view capability controls rationale access.
"""
from __future__ import annotations

import argparse
import difflib
import json
from pathlib import Path
import textwrap

try:
    from .adapter import canonical, read_bytes, sha, structural_index
except ImportError:
    from adapter import canonical, read_bytes, sha, structural_index


def current_fragment_anchors(source: str, path: str, symbol: str, edit: dict, structure=None) -> list[dict]:
    """Link unique recorded text to a current symbol, not an invented old tree.

    An exact current match is a retrieval anchor only. It cannot establish that
    the enclosing scope had the same identity at the time of the recorded edit.
    Repeated fragments and unacknowledged writes do not establish this link.
    """
    if not edit.get('success_acknowledged'):
        return []
    structure = structure if structure is not None else structural_index(source, path)
    targets = [s for s in structure['symbols'] if s['qualified_name'] == symbol]
    if len(targets) != 1:
        return []
    target = targets[0]
    anchors = []
    for field, fragment in edit.get('fragments', {}).items():
        if not fragment.strip() or len(fragment.strip()) < 12 or source.count(fragment) != 1:
            continue
        offset = source.index(fragment)
        first = source.count('\n', 0, offset) + 1
        last = source.count('\n', 0, offset + len(fragment.rstrip('\n'))) + 1
        # Context surrounding another function's change is not a target edit.
        # Map only changed lines of the matched side into the current source.
        spans = [(0, len(fragment.splitlines()))]
        fragments = edit.get('fragments', {})
        if {'old_str', 'new_str'} <= fragments.keys() and field in {'old_str', 'new_str'}:
            diff = difflib.SequenceMatcher(None, fragments['old_str'].splitlines(),
                                           fragments['new_str'].splitlines(), autojunk=False)
            spans = [(i, j) if field == 'old_str' else (a, b)
                     for op, i, j, a, b in diff.get_opcodes() if op != 'equal']
        changed = [{'start_line': first + a, 'end_line': first + b - 1}
                   for a, b in spans if b > a and first + a <= target['end_line']
                   and first + b - 1 >= target['start_line']]
        if changed:
            anchors.append({'field': field, 'start_line': first, 'end_line': last,
                            'changed_line_spans': changed,
                            'current_symbol': symbol, 'current_source_sha256': sha(source),
                            'link': 'unique_exact_fragment_changed_lines_in_current_symbol',
                            'historical_scope_identity_proven': False})
    return anchors


class HistoryView:
    def __init__(self, view: dict):
        if view.get("arm") not in {"B2", "B3", "B4"}:
            raise ValueError("Expected a B2, B3 or B4 investigator view")
        self.view = view
        self.events = {e["event_id"]: e for e in view["events"]}
        self.states = {s["state_id"]: s for s in view["states"]}
        self.edits = {e["edit_id"]: e for e in view.get("edit_records", [])}
        self.current_structures = {}
        if view["arm"] in {"B2", "B3"} and any(e["kind"] == "rationale" for e in self.events.values()):
            raise ValueError("Masked view contains forbidden rationale events")

    def _require_structure(self):
        if self.view["arm"] == "B2":
            raise ValueError("B2 supplies raw histories; structured retrieval is disabled")

    @classmethod
    def load(cls, path: Path) -> "HistoryView":
        return cls(json.loads(read_bytes(path)))

    def _timeline(self, path: str, before_message: int | None = None) -> list[dict]:
        return [s for s in self.states.values() if s["path"] == path and
                (before_message is None or s["message_index"] <= before_message)]

    def symbol_at(self, path: str, symbol: str, *, state_id: str | None = None,
                  before_message: int | None = None) -> dict:
        self._require_structure()
        choices = self._timeline(path, before_message)
        if state_id is not None:
            choices = [s for s in choices if s["state_id"] == state_id]
        if not choices:
            return {"status": "no_observed_state", "path": path, "symbol": symbol}
        state = choices[-1]
        found = [s for s in state["structure"]["symbols"] if s["qualified_name"] == symbol]
        lines = state["source"].splitlines()
        return {"status": "found" if found else "symbol_not_observed_in_selected_state",
                "state_id": state["state_id"], "path": path, "symbol": symbol,
                "message_index": state["message_index"], "source_sha256": state["source_sha256"],
                "source_fidelity": state["source_fidelity"], "complete_repository_state": False,
                "matches": [{**s, "source": "\n".join(lines[s["start_line"] - 1:s["end_line"]])} for s in found]}

    def history_for_path(self, path: str, *, before_message: int | None = None,
                         max_states: int = 8, include_source: bool = False) -> dict:
        states = self._timeline(path, before_message)
        selected = states[-max(0, max_states):] if max_states > 0 else []
        event_ids = {event_id for s in selected for event_id in (s["source_event_id"], s["action_event_id"])}
        edits = [e for e in self.edits.values() if e["path"] == path and
                 (before_message is None or e["message_index"] <= before_message)]
        edits = edits[-max(0, max_states):] if max_states > 0 else []
        event_ids.update(event_id for e in edits for event_id in (e["action_event_id"], e["observation_event_id"]))
        rationale_ids = set()
        for state in selected:
            rationale_ids.update(self.view.get("rationale_links", {}).get(state["state_id"], []))
        for edit in edits:
            rationale_ids.update(self.view.get("rationale_links", {}).get(edit["edit_id"], []))
        rows = [{k: v for k, v in s.items() if include_source or k != "source"} for s in selected]
        return {"path": path, "available_state_count": len(states), "returned_state_count": len(rows),
                "states": rows, "edit_records": edits,
                "events": [e for e in self.events.values() if e["event_id"] in event_ids],
                "rationale": self.rationale_for(sorted(rationale_ids)), "arm": self.view["arm"],
                "continuity_note": "Only previous_continuous_state_id links assert uninterrupted file observations"}

    def callers_at(self, path: str, *, state_id: str, callee: str) -> dict:
        self._require_structure()
        state = self.states.get(state_id)
        if state is None or state["path"] != path:
            return {"status": "no_observed_state", "calls": []}
        return {"status": "syntax_only", "state_id": state_id, "semantic_flow_available": False,
                "calls": [c for c in state["structure"]["calls"] if c["callee_syntax"] == callee]}

    def changed_edges(self, before: str, after: str) -> dict:
        self._require_structure()
        a, b = self.states.get(before), self.states.get(after)
        if a is None or b is None or a["path"] != b["path"]:
            return {"status": "states_missing_or_different_files"}
        if a["message_index"] >= b["message_index"]:
            return {"status": "invalid_temporal_order"}
        def edges(state):
            return {(c["scope"], c["callee_syntax"]) for c in state["structure"]["calls"]}
        old, new = edges(a), edges(b)
        order = lambda edge: (edge[0], edge[1] or "")
        return {"status": "syntax_only", "path": a["path"], "before": before, "after": after,
                "continuous_transition": b["previous_continuous_state_id"] == before,
                "added": sorted(new - old, key=order), "removed": sorted(old - new, key=order),
                "semantic_flow_available": False}

    def guard_lineage(self, path: str, symbol: str, *, before_message: int | None = None) -> dict:
        self._require_structure()
        return {"path": path, "symbol": symbol, "lineage_kind": "same_file_and_syntactic_symbol_name",
                "observations": [{"state_id": s["state_id"], "message_index": s["message_index"],
                                  "previous_continuous_state_id": s["previous_continuous_state_id"],
                                  "guards": [g for g in s["structure"]["guards"] if g["scope"] == symbol]}
                                 for s in self._timeline(path, before_message)]}

    def rationale_for(self, event_ids: list[str]) -> dict:
        if self.view["arm"] in {"B2", "B3"}:
            return {"status": "masked_by_arm", "events": []}
        return {"status": "available_original_recorded_text",
                "events": [self.events[eid] for eid in event_ids if eid in self.events and
                           self.events[eid]["kind"] == "rationale"]}

    def search(self, query: str, *, max_results: int = 10,
               before_message: int | None = None) -> dict:
        """Literal, case-insensitive search of permitted recorded source states."""
        needle = query.casefold()
        if not needle:
            return {"matches": []}
        matches = []
        for state in self.states.values():
            if before_message is not None and state["message_index"] > before_message:
                continue
            path_match = needle in state["path"].casefold()
            for n, line in enumerate(state["source"].splitlines(), 1):
                if needle in line.casefold() or path_match:
                    matches.append({"path": state["path"], "state_id": state["state_id"],
                                    "message_index": state["message_index"], "line": n,
                                    "text": line[:400], "path_match": path_match})
                    if len(matches) >= max_results:
                        return {"matches": matches, "limit_reached": True}
                    if path_match:
                        break
        return {"matches": matches, "limit_reached": False}

    def relevant_symbol_history(self, path: str, symbol: str | None = None, *,
                                before_message: int | None = None, max_states: int = 4,
                                max_history_chars: int = 16000,
                                max_rationale_chars: int = 4000,
                                selection: str = "latest_file_states",
                                current_source: str | None = None) -> dict:
        """Bounded evidence for an investigator; B3/B4 share the same history.

        B2 gives the same selected file-state IDs as raw source fragments and
        recorded action/observation text, without structural links. B3/B4 give
        symbol spans, syntactic calls/guards, and recorded editor provenance.
        B4 appends rationale separately, leaving the common block unchanged.
        Individual snippets may be clipped; every clip is marked. Bounds are
        characters, not claimed provider token counts.
        """
        if selection not in {"latest_file_states", "symbol_changes"}:
            raise ValueError("Unknown history selection policy")
        if selection == "symbol_changes" and not symbol:
            raise ValueError("Symbol-change selection requires a named target")
        max_states = min(max(0, max_states), 20)
        max_history_chars = min(max(0, max_history_chars), 100000)
        max_rationale_chars = min(max(0, max_rationale_chars), 20000)
        timeline = self._timeline(path, before_message)
        selected = timeline[-max_states:] if max_states else []
        edit_choices = [e for e in self.edits.values() if e["path"] == path and
                        (before_message is None or e["message_index"] <= before_message)]
        selected_edits = edit_choices[-max_states:] if max_states else []
        selection_details = {"policy": selection}
        anchors_by_edit = {}
        if selection == "symbol_changes":
            # Use the same deterministic source-only selection in B2/B3/B4.
            # B2 still exposes raw records, never the derived AST facts. This
            # controls evidence selection when testing representation/rationale.
            signatures, parsed = [], []
            for state in timeline:
                structure = state.get("structure") or structural_index(state["source"], path)
                parsed.append(structure["parse_status"] == "parsed")
                signatures.append(tuple(sorted(
                    (s["qualified_name"], s["ast_sha256"])
                    for s in structure["symbols"]
                    if s["qualified_name"] == symbol)))
            changes = [i for i in range(1, len(timeline))
                       if parsed[i - 1] and parsed[i] and signatures[i - 1] != signatures[i]]
            selected_indices = set()
            # Keep both endpoints of the newest relevant transitions. Changes
            # across observation gaps are comparisons, not proven edit lineage.
            for i in reversed(changes):
                pair = {i - 1, i}
                if len(selected_indices | pair) <= max_states:
                    selected_indices.update(pair)
            if not selected_indices and max_states:
                observed = [i for i, sig in enumerate(signatures) if parsed[i] and sig]
                if observed:
                    selected_indices.add(observed[-1])
            selected = [timeline[i] for i in sorted(selected_indices)]
            # A complete enclosing declaration in an edit can identify the
            # target even when the trace never displayed a complete file. Do
            # not infer a class from a standalone method with the same leaf name.
            fragment_matches = []
            for edit in edit_choices:
                structures = edit.get('fragment_structure') or {
                    key: structural_index(textwrap.dedent(value), path)
                    for key, value in edit['fragments'].items()}
                signatures_by_side = {side: tuple(s['ast_sha256'] for s in structure['symbols']
                    if s['qualified_name'] == symbol) for side, structure in structures.items()}
                identifies = any(signatures_by_side.values())
                unchanged = ('old_str' in structures and 'new_str' in structures and
                    structures['old_str']['parse_status'] == structures['new_str']['parse_status'] == 'parsed' and
                    signatures_by_side['old_str'] == signatures_by_side['new_str'])
                if identifies and not unchanged:
                    fragment_matches.append(edit)
            # A viewed file can contain the target while its associated edit
            # changes a different symbol. Action coincidence is not linkage.
            relevant_edits = list(fragment_matches)
            if current_source is not None:
                current_key = (path, sha(current_source))
                if current_key not in self.current_structures:
                    self.current_structures[current_key] = structural_index(current_source, path)
                anchors_by_edit = {e['edit_id']: current_fragment_anchors(current_source, path, symbol, e, self.current_structures[current_key])
                                   for e in edit_choices}
                relevant_edits = [e for e in edit_choices if e in relevant_edits or anchors_by_edit[e['edit_id']]]
            selected_edits = relevant_edits[-max_states:] if max_states else []
            selection_details.update({
                "observed_symbol_change_count": len(changes),
                "unparseable_state_count": sum(not p for p in parsed),
                "symbol_observed": any(signatures),
                "lineage_kind": "same_path_and_syntactic_name_no_rename_inference",
                "paired_transition_available": any({i - 1, i} <= selected_indices for i in changes),
                "fragment_only_edits_not_used_to_infer_complete_states": True})
            selection_details['explicit_symbol_fragment_edit_count'] = len(fragment_matches)
            selection_details['current_anchored_edit_count'] = sum(bool(v) for v in anchors_by_edit.values())
            selection_details['historical_scope_from_current_anchor_not_proven'] = True
        per_state = max_history_chars // max(1, len(selected) + len(selected_edits))
        items, rationale_ids = [], set()
        for state in selected:
            lines = state["source"].splitlines()
            item = {"state_id": state["state_id"], "path": path, "message_index": state["message_index"],
                    "source_sha256": state["source_sha256"], "source_fidelity": state["source_fidelity"],
                    "previous_continuous_state_id": state["previous_continuous_state_id"]}
            if self.view["arm"] == "B2":
                text = state["source"]
                item["evidence_kind"] = "raw_file_and_editor_history"
            else:
                structure = state["structure"]
                matches = [s for s in structure["symbols"] if symbol is None or
                           s["qualified_name"] == symbol]
                # Existing static baseline tools choose the query symbol; a
                # missing old symbol is an observation, not an invented body.
                item["symbols"] = matches
                item["structural_delta"] = state["structural_delta"]
                scopes = {s["qualified_name"] for s in matches}
                item["calls"] = [c for c in structure["calls"] if c["scope"] in scopes]
                item["guards"] = [g for g in structure["guards"] if g["scope"] in scopes]
                text = "\n\n".join("\n".join(lines[s["start_line"] - 1:s["end_line"]]) for s in matches)
                if symbol is None and not matches:
                    text = state["source"]
                item["evidence_kind"] = "syntax_linked_file_history"
            # Keep only compact action provenance in the common block. Original
            # unbounded event payloads remain accessible via history_for_path.
            action = self.events.get(state["action_event_id"], {})
            item["action"] = {"event_id": state["action_event_id"],
                              "tool_name": action.get("tool_name"),
                              "command": (action.get("arguments") or {}).get("command")}
            if self.view["arm"] == "B2":
                original = action.get("arguments_raw", "")
                item["action_arguments"] = str(original)[:max(0, per_state // 3)]
                item["action_arguments_clipped"] = len(str(original)) > per_state // 3
            text_cap = max(0, per_state - len(json.dumps(item, ensure_ascii=False)))
            item["source_fragment"] = text[:text_cap]
            item["source_fragment_clipped"] = len(text) > text_cap
            items.append(item)
            rationale_ids.update(self.view.get("rationale_links", {}).get(state["state_id"], []))
        edit_items = []
        for edit in selected_edits:
            item = {k: edit[k] for k in ("edit_id", "path", "message_index", "command", "success_acknowledged", "complete_file_state")}
            if self.view["arm"] != "B2":
                item['current_source_anchors'] = anchors_by_edit.get(edit['edit_id'], [])
                item["declared_fragment_symbols"] = {field: value["symbols"] for field, value in edit.get("fragment_structure", {}).items()}
                item["fragment_parse_status"] = {field: value["parse_status"] for field, value in edit.get("fragment_structure", {}).items()}
                structures = edit.get('fragment_structure') or {
                    field: structural_index(textwrap.dedent(text), path) for field, text in edit['fragments'].items()}
                item['fragment_syntax'] = {field: {'parse_status': value['parse_status'],
                    'guards': value['guards'][:20], 'calls': value['calls'][:30]}
                    for field, value in structures.items()}
                item['fragment_syntax_note'] = 'Recorded before/after snippets; relative lines and local scopes; not full historical data flow'
                item["fragment_scope_note"] = "Dedented snippets; containing class/function scope may be unavailable"
                if selection == 'symbol_changes':
                    item['target_fragment_matches'] = {
                        field: [s for s in value['symbols'] if s['qualified_name'] == symbol]
                        for field, value in edit.get('fragment_structure', {}).items()}
            cap = max(0, per_state - len(json.dumps(item))) // max(1, len(edit["fragments"]))
            item["fragments"] = {field: text[:cap] for field, text in edit["fragments"].items()}
            item["fragments_clipped"] = any(len(text) > cap for text in edit["fragments"].values())
            edit_items.append(item)
            rationale_ids.update(self.view.get("rationale_links", {}).get(edit["edit_id"], []))
        shared = {"path": path, "symbol": symbol, "available_state_count": len(timeline),
                  "selection": selection_details,
                  "selected_state_count": len(items), "states": items,
                  "recorded_edit_count": len(edit_choices), "edit_records": edit_items,
                  "semantic_flow_available": False, "complete_repository_states": False}
        original_rationale = self.rationale_for(sorted(rationale_ids))
        rationale = {"status": original_rationale["status"], "events": []}
        remaining = max_rationale_chars
        for event in original_rationale["events"]:
            if remaining <= 0:
                break
            text = event["text"]
            rationale["events"].append({"event_id": event["event_id"], "source_field": event["source_field"],
                                        "text": text[:remaining], "clipped": len(text) > remaining})
            remaining -= min(remaining, len(text))
        return {"arm": self.view["arm"], "history": shared,
                "shared_history_sha256": sha(canonical(shared)), "rationale": rationale,
                "bounds": {"max_history_chars": max_history_chars,
                           "max_rationale_chars": max_rationale_chars,
                           "note": "Schema overhead and structural lists may exceed text budget; caller enforces final prompt tokens"}}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--view", required=True, type=Path)
    parser.add_argument("--operation", choices=["history_for_path", "symbol_at", "guard_lineage", "changed_edges", "callers_at", "rationale_for", "search", "relevant_symbol_history"], required=True)
    parser.add_argument("--arguments", default="{}", help="JSON keyword arguments")
    args = parser.parse_args()
    history = HistoryView.load(args.view)
    result = getattr(history, args.operation)(**json.loads(args.arguments))
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
