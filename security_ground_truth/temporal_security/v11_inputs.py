"""Build v11 inputs from the frozen, label-blind v10 pilot inputs."""
from __future__ import annotations

import copy
import json
from pathlib import Path

from security_ground_truth.runtime.common import sha256, write_json
from .v11_cards import POLICY, arm_input, ast_invariant_cues, verify_arms


MAX_MESSAGE_BYTES = 100000
ARMS = ('C0', 'C1', 'C2', 'C3')
PRIMARY_TARGET_POLICY = 'v11-label-blind-current-source-completeness-pattern-v1'


def select_primary_preloaded_target(common, history):
    """Choose one shared coaching target from label-blind current-source facts.

    The completeness detector already identifies a security-relevant changed
    scope without benchmark labels.  Preserve its first source-ordered match:
    a changed class can carry the complete cross-method contract (for example,
    parser construction plus callbacks), while a nested method would expose
    only part of that evidence.  Cases with no match retain the frozen v10
    selected-target order as a deterministic fallback.
    """
    selected = [row for row in common.get('preloaded_source_ranges', [])
                if row.get('relationship', '').startswith('selected_target')]
    if not selected:
        raise ValueError('v11 read coaching requires at least one selected-target preload')
    selected_keys = {(row['path'], row['symbol']) for row in selected}
    cue_keys = []
    for row in ast_invariant_cues(
            common, history, temporal=False, reasoning=False).get('cards', []):
        key = (row.get('path'), row.get('symbol'))
        if key in selected_keys and key not in cue_keys:
            cue_keys.append(key)
    path, symbol = (cue_keys or [(selected[0]['path'], selected[0]['symbol'])])[0]
    return {'path': path, 'symbol': symbol, 'selection_policy': PRIMARY_TARGET_POLICY,
            'pattern_matched': bool(cue_keys)}


def upgrade(common, history):
    """Change only the protocol revision and treatment cards/cues."""
    common = copy.deepcopy(common)
    history = copy.deepcopy(history)
    common['protocol_revision'] = POLICY
    common['primary_preloaded_target'] = select_primary_preloaded_target(common, history)

    sizes = {arm: len(json.dumps(arm_input(common, history, arm)).encode()) for arm in ARMS}
    if max(sizes.values()) > MAX_MESSAGE_BYTES:
        preloaded = {(x['path'], x['symbol']) for x in common.get('preloaded_source_ranges', [])
                     if x.get('relationship', '').startswith('selected_target')}
        for group in common.get('current_code_groups', []):
            if ((group['path'], group['symbol']) not in preloaded
                    and len(group.get('source', '')) > 700):
                group['source'] = group['source'][:700]
                group['source_abbreviated'] = True
        sizes = {arm: len(json.dumps(arm_input(common, history, arm)).encode()) for arm in ARMS}
    if max(sizes.values()) > MAX_MESSAGE_BYTES:
        common['flow_association_max_bytes'] = 2500
        common['temporal_card_max_bytes'] = 12000
        sizes = {arm: len(json.dumps(arm_input(common, history, arm)).encode()) for arm in ARMS}
    if max(sizes.values()) > MAX_MESSAGE_BYTES:
        raise ValueError('v11 evidence exceeds 100000-byte shared message cap: ' + repr(sizes))

    verified = verify_arms(common, history, MAX_MESSAGE_BYTES)
    preloads = common.get('preloaded_source_ranges', [])
    delivered = {(x['path'], x['symbol']) for x in preloads}
    expected = {(x['path'], x['symbol']) for x in common.get('change_audit_bases', [])
                if x.get('symbol') != '<module>'}
    verified['preloaded_ranges'] = len(preloads)
    verified['all_selected_targets_preloaded'] = expected <= delivered
    verified['primary_preloaded_target'] = copy.deepcopy(common['primary_preloaded_target'])
    verified['primary_preloaded_target_validated'] = (
        (common['primary_preloaded_target']['path'], common['primary_preloaded_target']['symbol'])
        in {(x['path'], x['symbol']) for x in preloads
            if x.get('relationship', '').startswith('selected_target')})
    return common, history, verified


def prepare_from_v10(case, v10_input, output):
    """Materialize a new immutable input directory without changing v10."""
    v10_input = Path(v10_input)
    output = Path(output)
    if output.exists():
        raise ValueError('Refusing to overwrite v11 input directory')
    output.mkdir(parents=True)
    common_path = v10_input / 'common.json'
    history_path = v10_input / 'history.json'
    common = json.loads(common_path.read_text())
    history = json.loads(history_path.read_text())
    common, history, verified = upgrade(common, history)
    write_json(output / 'common.json', common)
    write_json(output / 'history.json', history)
    for arm in ARMS:
        write_json(output / (arm + '.json'), arm_input(common, history, arm))
    write_json(output / 'ready.json', {
        'case_key': case['case_key'], 'protocol_revision': POLICY,
        'source_v10_common_sha256': sha256(common_path),
        'source_v10_history_sha256': sha256(history_path),
        'security_labels_used': False, 'model_calls': 0, **verified})
    return common, history, verified
