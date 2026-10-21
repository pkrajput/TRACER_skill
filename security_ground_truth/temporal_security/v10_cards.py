"""Label-blind v10 treatment cards and deterministic AST completeness cues."""
from __future__ import annotations

import ast
import copy
import hashlib
import json
import re
import textwrap

from .change_audit import cards
from .change_symmetry import temporal_support
from .flow_context import annotate
from .rationale import public_rationale
from .v9_cards import reasoning_cards

POLICY = 'v10-harness-assisted-probes-preloaded-symbols-ast-cues'


def snapshot(common):
    result = {k: copy.deepcopy(common[k]) for k in [
        'functional_request', 'scanner_flow_context', 'source_environment',
        'remaining_alerts_not_initially_presented', 'scope', 'preloaded_source_ranges',
        'preload_selection'] if k in common}
    group_fields = {'group_id', 'path', 'symbol', 'start_line', 'end_line', 'source',
                    'source_abbreviated', 'alert_ids', 'calls', 'guards',
                    'calls_omitted_from_initial', 'guards_omitted_from_initial'}
    preloaded = {(x['path'], x['symbol']) for x in common.get('preloaded_source_ranges', [])
                 if x.get('relationship', '').startswith('selected_target')}
    groups = []
    for group in common.get('current_code_groups', []):
        row = {k: copy.deepcopy(v) for k, v in group.items() if k in group_fields}
        if (group['path'], group['symbol']) in preloaded:
            row.pop('source', None)
            row['source_reference'] = 'preloaded_source_ranges contains the exact complete current symbol'
            row['source_abbreviated'] = False
        groups.append(row)
    result['current_code_groups'] = groups
    alert_fields = {'alert_id', 'tool', 'rule_id', 'path', 'line', 'message', 'linked_group_ids'}
    result['scanner_alerts'] = [{k: copy.deepcopy(v) for k, v in a.items() if k in alert_fields}
                                for a in common.get('scanner_alerts', [])]
    result['scanner_counts'] = {k: v for k, v in common.get('scanner_counts', {}).items()
                                if k in {'scanner_alerts', 'scanner_alerts_linked',
                                         'scanner_alerts_in_selected_context', 'selected_groups'}}
    result['protocol_revision'] = POLICY
    result['selection_note'] = 'Every arm receives identical selected snapshot source, preloaded exact ranges, SAST facts and runtime gates.'
    return result


def _tree(source):
    try:
        return ast.parse(textwrap.dedent(source))
    except SyntaxError:
        return None


def _call_name(call):
    try:
        return ast.unparse(call.func)
    except Exception:
        return ''


def _source_for_group(common, group):
    for row in common.get('preloaded_source_ranges', []):
        if row.get('path') == group['path'] and row.get('symbol') == group['symbol']:
            return row['source']
    return group.get('source', '')


def ast_invariant_cues(common, history, *, temporal, reasoning):
    """Emit only syntax/API-pattern questions; never consult benchmark labels."""
    groups = common.get('current_code_groups', [])
    rows = []
    by_path = {}
    for group in groups:
        by_path.setdefault(group['path'], []).append(group)

    # Partial parsed-object comparison and parser defaults are local patterns.
    for group in groups:
        source = _source_for_group(common, group)
        tree = _tree(source)
        if not tree:
            continue
        calls = {_call_name(n) for n in ast.walk(tree) if isinstance(n, ast.Call)}
        attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        compared_attrs = {n.attr for compare in ast.walk(tree) if isinstance(compare, ast.Compare)
                          for n in ast.walk(compare) if isinstance(n, ast.Attribute)}
        cues = []
        if (any(name.endswith(('urlparse', 'urlsplit')) for name in calls)
                and 'netloc' in compared_attrs and 'path' in attrs and 'scheme' not in compared_attrs):
            cues.append('The code compares netloc and path of a parsed URL but omits scheme. Check whether scheme equality is required, for example when an https base URL encounters an http link.')
        html_calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and
                      (_call_name(n).endswith('HTMLParser') or _call_name(n) in {'super', 'super().__init__'})]
        html_subclass = any(isinstance(n, ast.ClassDef) and any(
            isinstance(base, ast.Name) and base.id == 'HTMLParser' or
            isinstance(base, ast.Attribute) and base.attr == 'HTMLParser' for base in n.bases) for n in ast.walk(tree))
        if (html_subclass or html_calls) and all(not any(k.arg == 'convert_charrefs' for k in call.keywords) for call in html_calls):
            intent_text = source + ' ' + common.get('functional_request', '')
            if reasoning:
                intent_text += ' ' + ' '.join(e.get('text', '') for e in (history.get('rationale') or {}).get('events', [])
                                                if any(link.get('path') == group['path'] for link in e.get('links', [])))
            if re.search(r'preserv\w*.{0,30}(?:entit|char.?ref)|(?:entit|char.?ref).{0,30}preserv', intent_text, re.I):
                cues.append('The rationale or docstring says entity references are preserved, while HTMLParser() omits convert_charrefs=False. Python HTMLParser defaults convert_charrefs=True; check decoded entities and any broad-exception raw-text fallback.')
        leaf = group['symbol'].split('.')[-1].lower()
        called_attrs = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
        if leaf in {'load', 'read', 'lookup', 'get'} and called_attrs & {'create', 'save'}:
            cues.append('This read/load path calls state-creation or persistence (create/save). Check whether missing or corrupt records should be handled without mutating state.')
        if re.search(r'is_select|read.?only|select', leaf, re.I):
            has_tokens = any(isinstance(n, ast.Attribute) and n.attr == 'tokens' for n in ast.walk(tree))
            if any(isinstance(n, (ast.For, ast.comprehension)) for n in ast.walk(tree)) and not has_tokens:
                cues.append('The SQL/read-only classifier iterates top-level syntax without an observed nested token.tokens traversal. Check WITH/CTE bodies and nested statements for side effects.')
        text = source.lower()
        component_builder = (re.search(r'host|schema|target|command|argv', text) and
                             (any(op in source for op in [' + ', "f'", 'f"', '.format(', '.extend('])
                              or re.search(r'process_?targets|build.*(?:command|cmdline|url)', leaf, re.I)))
        if component_builder:
            cues.append('A URL/connection/command component is assembled from host, schema, targets or argv. Check unvalidated delimiters such as /, ?, and leading - at the real consumer.')
        if 'visit_attribute' in leaf or 'restrictedpython' in text:
            cues.append('The attribute filter handles Python object access. Check generator/coroutine/frame introspection names such as gi_frame, gi_code, cr_frame and f_back, including prefix-based variants.')
        if cues:
            rows.append({'path': group['path'], 'symbol': group['symbol'], 'cues': cues,
                         'basis': 'deterministic current AST/API pattern plus enabled rationale/docstring where stated'})

    # Compare changed sibling byte-to-int paths and their explicit length guards.
    primary = {(x['path'], x['symbol']) for x in common.get('change_audit_bases', [])}
    for path, siblings in by_path.items():
        analyzed = []
        for group in siblings:
            if (path, group['symbol']) not in primary:
                continue
            source = _source_for_group(common, group)
            tree = _tree(source)
            if not tree:
                continue
            converted = set()
            guarded = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and _call_name(node).endswith('bytes2int') and node.args and isinstance(node.args[0], ast.Name):
                    converted.add(node.args[0].id)
                if isinstance(node, ast.Compare):
                    pieces = list(ast.walk(node))
                    for call in [x for x in pieces if isinstance(x, ast.Call) and isinstance(x.func, ast.Name) and x.func.id == 'len']:
                        if call.args and isinstance(call.args[0], ast.Name):
                            guarded.add(call.args[0].id)
            analyzed.append((group, converted, guarded))
        guarded_siblings = [(g, c, q) for g, c, q in analyzed if c & q]
        for group, converted, guarded in analyzed:
            missing = converted - guarded
            if not missing or not guarded_siblings:
                continue
            peer = guarded_siblings[0][0]
            cue = ('Sibling parameter guard asymmetry: %s checks input length before bytes2int, while %s calls bytes2int(%s) '
                   'without an observed same-input length check. Verify whether the latter requires a canonical signature/key-length pre-check.' %
                   (peer['symbol'], group['symbol'], ', '.join(sorted(missing))))
            rows.append({'path': path, 'symbol': group['symbol'], 'cues': [cue],
                         'basis': 'deterministic sibling AST comparison'})

    return {'cards': rows, 'labels_used': False,
            'synthesis': 'deterministic AST/API review cues; questions rather than vulnerability conclusions',
            'enabled_evidence': {'temporal': temporal, 'reasoning': reasoning}}


def arm_input(common, history, arm):
    temporal = arm in {'C1', 'C3'}
    reasoning = arm in {'C2', 'C3'}
    result = snapshot(common)
    result['temporal_history'] = history.get('temporal', {}) if temporal else {'status': 'withheld_by_arm'}
    result['developer_rationale'] = public_rationale(history.get('rationale') or {}) if reasoning else {'status': 'withheld_by_arm'}
    if temporal:
        result['temporal_change_cards'] = cards(common, history, True, False,
                                                max_bytes=common.get('temporal_card_max_bytes', 17000))
        result['sibling_change_comparisons'] = copy.deepcopy(common.get('sibling_change_comparisons', {}))
        result['sibling_temporal_comparison_links'] = {p['comparison_id']: temporal_support(p, history)
            for p in common.get('sibling_change_comparisons', {}).get('pairs', [])}
    if reasoning:
        result['reasoning_shortcut_cards'] = reasoning_cards(common, history)
    if temporal or reasoning:
        result['ast_invariant_completeness_cards'] = ast_invariant_cues(
            common, history, temporal=temporal, reasoning=reasoning)
    if arm == 'C3':
        by_symbol = {(r['path'], r['symbol']): r for r in result['reasoning_shortcut_cards']['cards']}
        rows = []
        for card in result['temporal_change_cards']['cards']:
            intent = by_symbol.get((card['path'], card['symbol']), {})
            rows.append({'path': card['path'], 'symbol': card['symbol'],
                'temporal_card_group_id': card.get('group_id'), 'reasoning_card_id': intent.get('card_id'),
                'sibling_comparison_ids': card.get('sibling_guard_comparison_ids', []),
                'intent_event_ids': [e['event_id'] for e in intent.get('excerpts', [])],
                'status': 'candidate_divergence_to_test' if intent.get('excerpts') else 'temporal_omission_question_no_recorded_intent'})
        result['intent_implementation_divergence_cards'] = {'cards': rows, 'proven_divergences': False,
            'synthesis': 'source-linked joins, not model-generated vulnerability claims'}
    if (temporal or reasoning) and common.get('scanner_flow_context'):
        result['flow_history_associations'] = annotate(common['scanner_flow_context'], history, temporal, reasoning,
                                                        max_bytes=common.get('flow_association_max_bytes', 6000))
    return result


def verify_arms(common, history, max_bytes=100000):
    arms = {arm: arm_input(common, history, arm) for arm in ['C0', 'C1', 'C2', 'C3']}
    shared = snapshot(common)
    for value in arms.values():
        assert all(value[key] == shared_value for key, shared_value in shared.items())
        serialized = json.dumps(value).lower()
        assert not any(name in serialized for name in ['golden_patch', 'security_patch', 'expected_pf'])
    assert 'ast_invariant_completeness_cards' not in arms['C0']
    assert 'ast_invariant_completeness_cards' in arms['C1']
    assert 'ast_invariant_completeness_cards' in arms['C2']
    assert 'ast_invariant_completeness_cards' in arms['C3']
    assert arms['C0']['temporal_history'] == {'status': 'withheld_by_arm'}
    assert arms['C0']['developer_rationale'] == {'status': 'withheld_by_arm'}
    sizes = {arm: len(json.dumps(value).encode()) for arm, value in arms.items()}
    assert max(sizes.values()) <= max_bytes, sizes
    return {'arm_bytes': sizes,
            'shared_snapshot_sha256': hashlib.sha256(json.dumps(shared, sort_keys=True).encode()).hexdigest(),
            'arm_isolation_verified': True, 'C0_ast_cues_absent': True,
            'treatment_ast_cues_present': True}
