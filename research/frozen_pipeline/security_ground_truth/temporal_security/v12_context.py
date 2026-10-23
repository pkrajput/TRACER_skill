"""Bound actual serialized messages, preserving the primary evidence and active work.

Full inputs, actions and observations remain in the cell archive. Compaction is
presentation only; omitted source is never registered as read.
"""
from __future__ import annotations

import copy
import json

INITIAL_TARGET = 72000
TURN_HEADROOM = 25000


def encoded_size(value):
    return len(json.dumps(value, ensure_ascii=True).encode())


def initial_size(value):
    return encoded_size([('user', initial_text(value))])


def initial_text(value):
    return json.dumps(value,ensure_ascii=False,separators=(',',':'))


def compact_state(state, maximum=12000):
    state = copy.deepcopy(state)
    warnings=state.get('edited_branch_warnings',[])
    if encoded_size(warnings)>2000:
        state['edited_branch_warnings_summary']={
            'count':len(warnings),'full_warnings_archived':True,
            'action':'Use target-reaching post-edit checks; omitted warning detail is not evidence of coverage.'}
        state['edited_branch_warnings']=[]
    grouped = {}
    for row in state.pop('hypotheses', []):
        # Different properties on the same symbol remain different hypotheses.
        signature = tuple(str(row.get(k)) for k in (
            'path', 'target_symbol', 'security_property', 'mechanism', 'decision',
            'used_for_repair', 'assessment_on_current_patch'))
        if 'security_property' not in row:
            signature=('legacy_identity',row['id'])
        if signature in grouped:
            grouped[signature].setdefault('equivalent_ids', []).append(row['id'])
        else:
            grouped[signature] = row
    rows = list(grouped.values())
    state['hypotheses'] = rows
    state['protocol_summary_compacted'] = True
    if encoded_size(state) > maximum:
        for row in rows:
            row.pop('cited_rationale_events', None)
            row.pop('scanner_linked_ids', None)
            if 'security_property' in row:
                row['security_property'] = str(row['security_property'])[:160]
            row.pop('mechanism',None)
    if encoded_size(state) > maximum:
        # Keep identities/statuses, especially repair obligations, never silently
        # turn an unassessed hypothesis into a refutation.
        state['hypotheses'] = [{k: r[k] for k in (
            'id', 'equivalent_ids', 'decision', 'used_for_repair',
            'assessment_on_current_patch') if k in r} for r in rows]
    return state


def rolling_messages(initial, previous, current, ceiling):
    """Retain recent compact tool context without duplicating historical state."""
    kept=[]
    for index in range(len(previous)-2,0,-2):
        pair=previous[index:index+2]
        if len(pair)!=2 or pair[0][0]!='model' or pair[1][0]!='user':continue
        try:
            prior_answer=json.loads(pair[0][1])
            payload=json.loads(pair[1][1])
            prior_action={'actions':[{k:a[k] for k in ('action','path','hypothesis_id','decision') if k in a}
                for a in prior_answer.get('actions',[]) if isinstance(a,dict)],
                'historical_action_summary':True,'full_action_archived':True}
            old={'observations':[feedback(v,1200) for v in payload.get('observations',[])],
                 'historical_feedback':True,'current_protocol_state_in_latest_message':True}
            pair=[('model',json.dumps(prior_action)),('user',json.dumps(old,ensure_ascii=False))]
        except (ValueError,TypeError):continue
        if encoded_size([initial,*pair,*kept,*current])<=ceiling:
            kept=pair+kept
        if len(kept)>=8:break
    return [initial,*kept,*current]


def feedback(value, limit):
    if 'events' in value and 'text_chars_remaining' in value:
        # Exact retrieval exposure must match the RationaleSession ledger.
        return value
    if encoded_size(value) <= limit:
        return value
    if isinstance(value.get('recovery'), dict):
        # Citation recovery carries exact current lines. Remove duplicated
        # metadata first, so useful anchors survive ordinary feedback packing.
        # Never truncate a source line while keeping its citation range.
        recovery = copy.deepcopy(value['recovery'])
        if recovery.get('unique_current_edit_context') == recovery.get('source'):
            recovery.pop('unique_current_edit_context', None)
        recovery.pop('auto_fix_hint', None)
        reduced = {k: copy.deepcopy(value[k]) for k in
                   ('status', 'error_type') if k in value}
        reduced.update(error=str(value.get('error', ''))[:400], recovery=recovery)
        if encoded_size(reduced) <= limit:
            return reduced
    # An abbreviated recovery does not advertise omitted quotations as visible.
    fields = ('status', 'error', 'error_type', 'hypothesis_id', 'decision',
              'path', 'target_reached', 'source_identity', 'candidate_patch_sha256',
              'functional_result', 'dynamic_boundary_qualification')
    out = {k: copy.deepcopy(value[k]) for k in fields if k in value}
    out.update(abbreviated=True, full_feedback_archived=True,
               recovery_instruction='Use the recorded hypothesis ID; assess pending work. Re-read omitted source before citing it.')
    for k in ('source', 'stdout', 'stderr', 'mechanism', 'security_property'):
        if k in value and isinstance(value[k], str):
            out[k] = value[k][:max(100, limit // 6)]
    if 'events' in value:
        # Retrieval exposure is recorded only for exact text: do not fabricate
        # a shortened rationale quotation or make it appear fully delivered.
        out['rationale_response_omitted'] = True
    for k in ('observations', 'target_caller_frames'):
        if k in value:
            out[k] = value[k][:3]
    while encoded_size(out) > limit:
        candidates = [k for k in out if k not in {'hypothesis_id', 'status', 'decision'}
                      and isinstance(out[k], (str, list, dict)) and len(str(out[k])) > 80]
        if not candidates:
            break
        k = max(candidates, key=lambda n: encoded_size(out[n]))
        if isinstance(out[k], str):
            out[k] = out[k][:max(40, len(out[k]) // 2)]
        else:
            out.pop(k)
    return out


def pack(initial_message, answer, observations, state, ceiling):
    """Return a replacement initial message and one bounded current exchange.

    Historical exchanges are separately compacted; archived trajectories remain
    complete. This function does not slice JSON or silently remove the primary
    source. The input builder reserves 25KB for this exchange.
    """
    initial = initial_message
    compact = compact_state(state)
    abbreviated_action = {'actions': [{k: a[k] for k in ('action', 'path', 'hypothesis_id', 'decision')
                           if k in a} for a in answer.get('actions', []) if isinstance(a, dict)],
              'full_actions_archived': True}
    actions=([answer] if encoded_size(answer)<=4000 else [])+[abbreviated_action]
    for action in actions:
        for limit in (4500, 2000, 1000, 400):
            current = [('model', json.dumps(action)), ('user', json.dumps({
                'observations': [feedback(o, limit) for o in observations],
                'protocol_state': compact}, ensure_ascii=False))]
            if encoded_size([initial, *current]) <= ceiling:
                return initial, current
    # Defensive fallback for imported old large bundles: trim only non-primary
    # preload bodies. The immutable full input stays archived; source identities
    # and the primary body are preserved. Future citations still require reads.
    value = json.loads(initial[1])
    primary = value.get('primary_preloaded_target') or state.get('read_discipline',{}).get('primary_target') or {}
    rows = value.get('preloaded_source_ranges', [])
    removable = sorted((r for r in rows if
                        (r.get('path'), r.get('symbol')) !=
                        (primary.get('path'), primary.get('symbol'))),
                       key=lambda r: len(r.get('source', '')), reverse=True)
    for row in removable:
        rows.remove(row)
        value.setdefault('runtime_omitted_preloads', []).append({
            k: row[k] for k in ('path', 'symbol', 'start_line', 'end_line') if k in row})
        initial = ('user', initial_text(value))
        if encoded_size([initial, *current]) <= ceiling:
            return initial, current
    # Qualified v12 bundles cannot reach this branch. Fail qualification locally
    # rather than dispatching a bundle that cannot preserve its primary evidence.
    raise ValueError('v12 invariant violated: primary evidence plus compact active state cannot fit')
