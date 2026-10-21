"""Revision-isolated v11 treatment cards with refined AST completeness cues."""
from __future__ import annotations

import ast
import copy
import hashlib
import json
import re

from . import v10_cards


POLICY = 'v11-refutation-read-coaching-refined-cues'

_V10_HTML_ENTITY_CUE = (
    'The rationale or docstring says entity references are preserved, while '
    'HTMLParser() omits convert_charrefs=False. Python HTMLParser defaults '
    'convert_charrefs=True; check decoded entities and any broad-exception '
    'raw-text fallback.'
)
_V10_COMPONENT_CUE = (
    'A URL/connection/command component is assembled from host, schema, targets '
    'or argv. Check unvalidated delimiters such as /, ?, and leading - at the '
    'real consumer.'
)

HTML_ENTITY_CUE = (
    'Entity-preserving HTMLParser code must account for the exact raw spelling '
    'of references. When convert_charrefs=False is used with '
    'handle_entityref(name) or handle_charref(name), the callback name does not '
    'say whether the input had a trailing semicolon; do not append a synthetic '
    '";" unconditionally. Preserve malformed text such as &gotcha without '
    'turning it into &gotcha;, or strip tags while preserving the exact original '
    'entity substrings.'
)
URI_COMPONENT_CUE = (
    'This resolver builds URI/JDBC data from structured connection fields. '
    'Check inside the resolver, before URL assembly, that URI structural '
    'delimiters are rejected in their source fields, including "/" in host and '
    '"?" in schema; whitespace checks on a later CLI argument are not the same '
    'boundary validation.'
)
FORM_HELP_TEXT_CUE = (
    "A form builder copies a model field's help_text into field options. Check "
    'that help_text is passed through conditional_escape by default, and is left '
    'as HTML only when an explicit allow-HTML setting such as '
    'WAGTAILFORMS_HELP_TEXT_ALLOW_HTML is enabled.'
)
CLI_TARGET_CUE = (
    'Target strings passed to a CLI binary must be rejected by target validation '
    'when they begin with "-" (so they cannot become flags) or contain '
    'characters outside the allowed target grammar. shlex parsing and list-form '
    'process arguments do not replace this validation; enforce it before command '
    'assembly or execution.'
)

_LOCAL_BASIS = (
    'deterministic current AST/API pattern plus enabled rationale/docstring '
    'where stated'
)
_CROSS_BACKEND_BASIS = 'deterministic cross-file changed-backend AST comparison'


def snapshot(common):
    """Reuse the v10 shared snapshot while identifying the v11 revision."""
    result = v10_cards.snapshot(common)
    result['protocol_revision'] = POLICY
    return result


def _tree(source):
    return v10_cards._tree(source)


def _call_name(call):
    return v10_cards._call_name(call)


def _source_for_group(common, group):
    return v10_cards._source_for_group(common, group)


def _string_value(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    # Python < 3.8 compatibility for archived inputs.
    if isinstance(node, ast.Str):
        return node.s
    return None


def _subscript_key(node):
    if not isinstance(node, ast.Subscript):
        return None
    value = node.slice
    if isinstance(value, ast.Index):  # pragma: no cover - Python < 3.9 AST
        value = value.value
    return _string_value(value)


def _names(tree):
    names = {node.id.lower() for node in ast.walk(tree) if isinstance(node, ast.Name)}
    names.update(node.attr.lower() for node in ast.walk(tree) if isinstance(node, ast.Attribute))
    names.update(node.arg.lower() for node in ast.walk(tree) if isinstance(node, ast.arg))
    return names


def _strings(tree):
    return {value.lower() for node in ast.walk(tree)
            if (value := _string_value(node)) is not None}


def _preservation_intent(common, history, group, source, reasoning):
    text = source + ' ' + common.get('functional_request', '')
    if reasoning:
        text += ' ' + ' '.join(
            event.get('text', '')
            for event in (history.get('rationale') or {}).get('events', [])
            if any(link.get('path') == group['path'] for link in event.get('links', []))
        )
    return bool(re.search(
        r'preserv\w*.{0,30}(?:entit|char.?ref)|(?:entit|char.?ref).{0,30}preserv',
        text,
        re.I,
    ))


def _html_entity_pattern(common, history, group, source, tree, reasoning):
    calls = {_call_name(node) for node in ast.walk(tree) if isinstance(node, ast.Call)}
    html_subclass = any(
        isinstance(node, ast.ClassDef) and any(
            (isinstance(base, ast.Name) and base.id == 'HTMLParser')
            or (isinstance(base, ast.Attribute) and base.attr == 'HTMLParser')
            for base in node.bases
        )
        for node in ast.walk(tree)
    )
    html_constructor = any(
        name.endswith('HTMLParser') or name in {'super', 'super().__init__'}
        for name in calls
    )
    handlers = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    parser_pattern = html_subclass or html_constructor
    entity_handler = bool(handlers & {'handle_entityref', 'handle_charref'})
    return (
        (parser_pattern or entity_handler)
        and _preservation_intent(common, history, group, source, reasoning)
    )


def _uri_component_pattern(group, tree):
    names = _names(tree)
    strings = _strings(tree)
    semantic_fields = names | strings
    structured_connection = {'host', 'schema'} <= semantic_fields
    url_result = bool({'url', 'uri', 'jdbc_url'} & strings)
    leaf = group['symbol'].split('.')[-1].lower()
    resolver_name = bool(re.search(
        r'(?:resolve|build|make|create).*(?:jdbc|uri|url|connection)'
        r'|(?:jdbc|uri|url|connection).*(?:resolve|build|make|create)',
        leaf,
    ))
    assembles = any(
        isinstance(node, ast.JoinedStr)
        or (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add))
        or (isinstance(node, ast.Call) and _call_name(node).endswith('.format'))
        for node in ast.walk(tree)
    )
    return structured_connection and assembles and (url_result or resolver_name)


def _contains_help_text(node):
    return any(
        isinstance(part, ast.Attribute) and part.attr == 'help_text'
        for part in ast.walk(node)
    )


def _form_help_text_pattern(tree):
    # A class group contains all of its methods as nested AST nodes. Attribute
    # the cue to the exact callable group instead of duplicating it on the
    # containing class card.
    callables = [node for node in tree.body
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for node in (part for callable_node in callables for part in ast.walk(callable_node)):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if (any(_subscript_key(target) == 'help_text' for target in targets)
                    and _contains_help_text(node.value)):
                return True
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if _string_value(key) == 'help_text' and _contains_help_text(value):
                    return True
    return False


def _cli_target_pattern(group, tree):
    names = _names(tree)
    strings = _strings(tree)
    leaf = group['symbol'].split('.')[-1].lower()
    has_target = any('target' in name for name in names | strings) or 'target' in leaf
    processes_targets = bool(re.search(r'(?:process|validate|parse).*targets?', leaf))
    calls_target_processor = any(
        isinstance(node, ast.Call)
        and re.search(r'(?:process|validate|parse).*targets?', _call_name(node).lower())
        for node in ast.walk(tree)
    )
    cli_terms = ('binary', 'command', 'cmdline', 'argv', 'shlex', 'popen', 'options')
    cli_context = any(any(term in value for term in cli_terms)
                      for value in names | strings | {leaf})
    builds_sequence = any(
        isinstance(node, (ast.List, ast.ListComp))
        or (isinstance(node, ast.Call) and _call_name(node).endswith(('.extend', '.append')))
        for node in ast.walk(tree)
    )
    return has_target and (
        processes_targets
        or (calls_target_processor and cli_context)
        or (cli_context and builds_sequence)
    )


def _append_cue(rows, group, cue, basis=_LOCAL_BASIS):
    key = (group['path'], group['symbol'])
    for row in rows:
        if (row['path'], row['symbol']) == key:
            if cue not in row['cues']:
                row['cues'].append(cue)
            if basis not in row.get('basis', ''):
                row['basis'] = '; '.join(filter(None, [row.get('basis'), basis]))
            return
    rows.append({
        'path': group['path'],
        'symbol': group['symbol'],
        'cues': [cue],
        'basis': basis,
    })


def _session_load_groups(common, groups):
    primary = {
        (row['path'], row['symbol'])
        for row in common.get('change_audit_bases', [])
    }
    matches = []
    for group in groups:
        if (group['path'], group['symbol']) not in primary:
            continue
        parts = group['symbol'].lower().split('.')
        if len(parts) >= 2 and parts[-1] == 'load' and 'session' in parts[-2]:
            matches.append(group)
    if len({group['path'] for group in matches}) < 2:
        return []
    return matches


def _session_load_cue(groups):
    backends = ', '.join(sorted({group['path'].rsplit('/', 1)[-1] for group in groups}))
    return (
        'Multiple session load backends are modified together (%s). Review them '
        'as one contract: no load() path, including an inherited fallback, '
        'should call self.create() for a missing, expired, or corrupt session. '
        'Reset state and return {} without creating a record, while preserving '
        'invalid-key handling in _get_or_create_session_key.' % backends
    )


def ast_invariant_cues(common, history, *, temporal, reasoning):
    """Refine v10's label-blind cues using deterministic current-source patterns."""
    base = v10_cards.ast_invariant_cues(
        common,
        history,
        temporal=temporal,
        reasoning=reasoning,
    )
    rows = []
    for row in base['cards']:
        retained = [cue for cue in row['cues']
                    if cue not in {_V10_HTML_ENTITY_CUE, _V10_COMPONENT_CUE}]
        if retained:
            copied = copy.deepcopy(row)
            copied['cues'] = retained
            rows.append(copied)

    groups = common.get('current_code_groups', [])
    for group in groups:
        source = _source_for_group(common, group)
        tree = _tree(source)
        if not tree:
            continue
        if _html_entity_pattern(common, history, group, source, tree, reasoning):
            _append_cue(rows, group, HTML_ENTITY_CUE)
        if _uri_component_pattern(group, tree):
            _append_cue(rows, group, URI_COMPONENT_CUE)
        if _form_help_text_pattern(tree):
            _append_cue(rows, group, FORM_HELP_TEXT_CUE)
        if _cli_target_pattern(group, tree):
            _append_cue(rows, group, CLI_TARGET_CUE)

    session_groups = _session_load_groups(common, groups)
    if session_groups:
        cue = _session_load_cue(session_groups)
        for group in session_groups:
            _append_cue(rows, group, cue, _CROSS_BACKEND_BASIS)

    return {
        **base,
        'cards': rows,
        'synthesis': (
            'deterministic AST/API review cues with cross-target completeness; '
            'questions rather than vulnerability conclusions'
        ),
    }


def arm_input(common, history, arm):
    """Keep v10's arm structure while substituting only v11 policy and cues."""
    result = v10_cards.arm_input(common, history, arm)
    result['protocol_revision'] = POLICY
    if arm in {'C1', 'C2', 'C3'}:
        result['ast_invariant_completeness_cards'] = ast_invariant_cues(
            common,
            history,
            temporal=arm in {'C1', 'C3'},
            reasoning=arm in {'C2', 'C3'},
        )
    else:
        result.pop('ast_invariant_completeness_cards', None)
    return result


def verify_arms(common, history, max_bytes=100000):
    arms = {arm: arm_input(common, history, arm) for arm in ['C0', 'C1', 'C2', 'C3']}
    shared = snapshot(common)
    for value in arms.values():
        assert all(value[key] == shared_value for key, shared_value in shared.items())
        serialized = json.dumps(value).lower()
        assert not any(name in serialized for name in ['golden_patch', 'security_patch', 'expected_pf'])
    treatment_fields = {
        'temporal_change_cards',
        'sibling_change_comparisons',
        'sibling_temporal_comparison_links',
        'reasoning_shortcut_cards',
        'ast_invariant_completeness_cards',
        'intent_implementation_divergence_cards',
        'flow_history_associations',
    }
    assert treatment_fields.isdisjoint(arms['C0'])
    for arm in ['C1', 'C2', 'C3']:
        assert 'ast_invariant_completeness_cards' in arms[arm]
    assert arms['C0']['temporal_history'] == {'status': 'withheld_by_arm'}
    assert arms['C0']['developer_rationale'] == {'status': 'withheld_by_arm'}
    sizes = {arm: len(json.dumps(value).encode()) for arm, value in arms.items()}
    assert max(sizes.values()) <= max_bytes, sizes
    return {
        'arm_bytes': sizes,
        'shared_snapshot_sha256': hashlib.sha256(
            json.dumps(shared, sort_keys=True).encode()
        ).hexdigest(),
        'arm_isolation_verified': True,
        'C0_ast_cues_absent': True,
        'C0_treatment_cards_absent': True,
        'treatment_ast_cues_present': True,
    }
