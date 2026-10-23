"""Build v10 inputs from the verified, label-blind v9 preparation facts."""
from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path

from security_ground_truth.runtime.common import sha256, write_json
from . import citations
from .v10_cards import POLICY, arm_input, verify_arms

MAX_MESSAGE_BYTES = 100000
TARGET_LIMIT = 12
CALLER_SOURCE_BUDGET = 30000


def _call_leaf(node):
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _scope_for_line(scopes, line):
    matches = [scope for scope in scopes if scope['start_line'] <= line <= scope['end_line']]
    return min(matches, key=lambda x: x['end_line'] - x['start_line']) if matches else None


def _entry(source, path, scope, relationship, target_symbol=None):
    lines = source.splitlines()
    lo, hi = scope['start_line'], scope['end_line']
    return {'path': path, 'symbol': scope['symbol'], 'start_line': lo, 'end_line': hi,
            'source': '\n'.join(lines[lo - 1:hi]), 'source_sha256': citations.source_hash(source),
            'relationship': relationship, **({'target_symbol': target_symbol} if target_symbol else {})}


def build_preloads(common, source_root):
    """Preload every selected primary callable plus immediate in-file callers."""
    source_root = Path(source_root)
    selected = []
    for base in common.get('change_audit_bases', []):
        if base.get('symbol') == '<module>':
            continue
        key = (base['path'], base['symbol'])
        if key not in selected:
            selected.append(key)
    selected = selected[:TARGET_LIMIT]
    rows = []
    seen = set()
    callers_omitted = []
    caller_bytes = 0
    for path, symbol in selected:
        source = (source_root / path).read_text()
        scopes = citations.symbols(source)
        matches = [scope for scope in scopes if scope['symbol'] == symbol]
        if len(matches) != 1:
            raise ValueError('Selected target cannot be resolved exactly: %s:%s' % (path, symbol))
        target = matches[0]
        key = (path, target['start_line'], target['end_line'])
        if key not in seen:
            rows.append(_entry(source, path, target, 'selected_target'))
            seen.add(key)
        else:
            for row in rows:
                if (row['path'], row['start_line'], row['end_line']) == key:
                    row['relationship'] = 'selected_target_and_immediate_in_file_caller'
                    break
        tree = ast.parse(source)
        leaf = symbol.split('.')[-1]
        callers = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _call_leaf(node) == leaf:
                scope = _scope_for_line(scopes, node.lineno)
                if scope and scope['symbol'] != symbol:
                    callers.append(scope)
        callers.sort(key=lambda x: (x['start_line'], x['symbol']))
        for caller in callers:
            key = (path, caller['start_line'], caller['end_line'])
            if key in seen:
                continue
            entry = _entry(source, path, caller, 'immediate_in_file_caller', symbol)
            size = len(json.dumps(entry).encode())
            if caller_bytes + size > CALLER_SOURCE_BUDGET:
                callers_omitted.append({'path': path, 'symbol': caller['symbol'], 'target_symbol': symbol,
                                        'reason': 'shared caller-source budget'})
                continue
            rows.append(entry)
            seen.add(key)
            caller_bytes += size
    return rows, {'selected_target_policy': 'all selected primary callable targets, capped at %d' % TARGET_LIMIT,
                  'selected_targets': len(selected),
                  'preloaded_ranges': len(rows),
                  'immediate_callers_omitted': callers_omitted,
                  'caller_source_budget_bytes': CALLER_SOURCE_BUDGET}


def upgrade(common, history, case):
    """Upgrade already verified v9 facts without reading labels or test patches."""
    common = copy.deepcopy(common)
    common['protocol_revision'] = POLICY
    source_root = Path(case['baseline']) / 'source'
    preloads, selection = build_preloads(common, source_root)
    common['preloaded_source_ranges'] = preloads
    common['preload_selection'] = selection
    # Primary sources now have a single exact delivery in preloaded_source_ranges.
    preloaded = {(x['path'], x['symbol']) for x in preloads if x['relationship'].startswith('selected_target')}
    for group in common.get('current_code_groups', []):
        if (group['path'], group['symbol']) in preloaded:
            group['source'] = ''
            group['source_abbreviated'] = False
    # Treatment cards are allowed more room than v9, but the transport cap is
    # shared and enforced across all four arms below.
    common['temporal_card_max_bytes'] = min(18000, common.get('temporal_card_max_bytes', 18000))
    sizes = {arm: len(json.dumps(arm_input(common, history, arm)).encode())
             for arm in ['C0', 'C1', 'C2', 'C3']}
    if max(sizes.values()) > MAX_MESSAGE_BYTES:
        for group in common.get('current_code_groups', []):
            if (group['path'], group['symbol']) not in preloaded and len(group.get('source', '')) > 700:
                group['source'] = group['source'][:700]
                group['source_abbreviated'] = True
        sizes = {arm: len(json.dumps(arm_input(common, history, arm)).encode())
                 for arm in ['C0', 'C1', 'C2', 'C3']}
    if max(sizes.values()) > MAX_MESSAGE_BYTES:
        common['flow_association_max_bytes'] = 2500
        common['temporal_card_max_bytes'] = 12000
        sizes = {arm: len(json.dumps(arm_input(common, history, arm)).encode())
                 for arm in ['C0', 'C1', 'C2', 'C3']}
    if max(sizes.values()) > MAX_MESSAGE_BYTES:
        raise ValueError('v10 evidence exceeds 100000-byte shared message cap: ' + repr(sizes))
    verified = verify_arms(common, history, MAX_MESSAGE_BYTES)
    verified['preloaded_ranges'] = len(preloads)
    delivered={(x['path'],x['symbol']) for x in preloads}
    expected={(x['path'],x['symbol']) for x in common.get('change_audit_bases', []) if x.get('symbol')!='<module>'}
    verified['all_selected_targets_preloaded'] = expected <= delivered
    return common, history, verified


def prepare_from_v9(case, v9_input, output):
    """Materialize a new immutable input directory; never overwrite v9."""
    v9_input = Path(v9_input)
    output = Path(output)
    if output.exists():
        raise ValueError('Refusing to overwrite v10 input directory')
    output.mkdir(parents=True)
    common = json.loads((v9_input / 'common.json').read_text())
    history = json.loads((v9_input / 'history.json').read_text())
    common, history, verified = upgrade(common, history, case)
    write_json(output / 'common.json', common)
    write_json(output / 'history.json', history)
    for arm in ['C0', 'C1', 'C2', 'C3']:
        write_json(output / (arm + '.json'), arm_input(common, history, arm))
    write_json(output / 'ready.json', {
        'case_key': case['case_key'], 'protocol_revision': POLICY,
        'source_v9_common_sha256': sha256(v9_input / 'common.json'),
        'source_v9_history_sha256': sha256(v9_input / 'history.json'),
        'security_labels_used': False, 'model_calls': 0, **verified})
    return common, history, verified
