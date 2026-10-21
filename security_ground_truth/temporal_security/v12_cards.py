"""Version-isolated v12 cues; C0 remains a clean shared snapshot."""
import copy
import hashlib
import json
from . import v11_cards
from .v12_protocol import POLICY
from .v12_context import initial_size

LIFECYCLE_CUE = (
    'Verify whether __init__ invokes this validation at object construction '
    'time, not only during later job execution. Review the whole accepted input '
    'grammar: leading prefix flags (-) and disallowed target/URI characters '
    'are independent constraints. Trace the public caller to the validation '
    'helper; a successful direct-helper probe does not cover construction.'
)


def cues(common, history, temporal, reasoning):
    result = v11_cards.ast_invariant_cues(common, history, temporal=temporal, reasoning=reasoning)
    for row in result['cards']:
        if any(c in row['cues'] for c in (v11_cards.URI_COMPONENT_CUE, v11_cards.CLI_TARGET_CUE)):
            row['cues'].append(LIFECYCLE_CUE)
    return result


def arm_input(common, history, arm):
    # Older renderers intentionally share read-only history dictionaries. v12
    # compaction must operate on its own view, never mutate another arm or the
    # archived unabridged evidence.
    value = copy.deepcopy(v11_cards.arm_input(common, history, arm))
    value['protocol_revision'] = POLICY
    value['primary_preloaded_target'] = copy.deepcopy(common['primary_preloaded_target'])
    if arm != 'C0':
        value['ast_invariant_completeness_cards'] = copy.deepcopy(
            common.get('v12_precomputed_cues', {}).get(arm) or
            cues(common, history, arm in {'C1','C3'}, arm in {'C2','C3'}))
    for key, replacement in common.get('v12_shared_overrides', {}).items():
        value[key] = copy.deepcopy(replacement)
    if common.get('v12_compression', 0):
        for channel in ('agent','git'):
            block=value.get('temporal_history',{}).get(channel,{})
            if 'records' not in block:continue
            rows=[]
            for record in block['records']:
                row={k:copy.deepcopy(record[k]) for k in (
                    'event_id','path','history_channel','source_fidelity','continuous_transition',
                    'before_sha256','after_sha256','symbol_filter','guard_deltas','fallback_deltas',
                    'symbol_hints','current_symbol_anchors','unabridged_record_sha256') if k in record}
                row['semantic_flow_proven']=False
                row['full_provenance_archived']=True
                rows.append(row)
            block['records']=rows
        # Quotes remain verbatim. Repeated index metadata is archived, not model
        # evidence; the full RationaleSession still validates exact citations.
        rationale=value.get('developer_rationale',{})
        if 'events' in rationale:
            rationale['events']=[{k:copy.deepcopy(e[k]) for k in (
                'event_id','span_id','text','start_char','end_char','message_index',
                'links','mentioned_target_symbols') if k in e} for e in rationale['events']]
    if common.get('v12_compression',0)>=2:
        for group in value['current_code_groups']:
            for field in ('calls','guards'):
                if field in group:
                    group[field+'_omitted_from_initial']=max(0,len(group[field])-2)
                    group[field]=group[field][:2]
        for card in value.get('temporal_change_cards',{}).get('cards',[]):
            card.pop('patch_facts',None)
            card['current_source_detail_location']='current_code_groups/preloaded_source_ranges/read'
        for card in value.get('reasoning_shortcut_cards',{}).get('cards',[]):
            for excerpt in card.get('excerpts',[]):
                # The exact quote also remains in developer_rationale. Keep its
                # event and character offsets for the join, without duplication.
                excerpt.pop('quote',None)
                excerpt['quote_location']='developer_rationale or rationale retrieval'
    if common.get('v12_compression',0)>=3:
        # Large class/module targets stay complete. Replace duplicate indexes
        # with explicit joins; preserve every selected target, event and quote.
        for group in value['current_code_groups']:
            if group.get('source'):
                # The full primary body is separately preloaded. Other source
                # fragments remain retrievable and must not count as read.
                group['source']='';group['source_abbreviated']=True
            for field in ('calls','guards'):
                group[field+'_omitted_from_initial']=group.get(field+'_omitted_from_initial',0)+len(group.pop(field,[]))
        value['structure_detail_location']='Full preloaded source or structure(path); syntax lists omitted identically in all arms.'
        selection=value.get('preload_selection',{})
        omitted=selection.pop('v12_omitted_preload_ranges',[])
        selection['omitted_preload_count']=len(omitted)
        selection['omitted_range_inventory_location']='archived common.json; use read for any source not delivered above'
        for channel in ('agent','git'):
            temporal=value.get('temporal_history',{}).get(channel,{})
            if not temporal.get('records'):continue
            temporal['provenance_detail_location']='Full hashed records in archived history.json; hints and added/removed guards below remain verbatim. These are syntax, not proven semantic flows.'
            for record in temporal['records']:
                for field in ('before_sha256','after_sha256','history_channel','semantic_flow_proven','full_provenance_archived'):
                    record.pop(field,None)
                for field in ('guard_deltas','fallback_deltas'):
                    record.get(field,{}).pop('basis',None)
                for anchor in record.get('current_symbol_anchors',[]):
                    anchor.pop('current_source_sha256',None);anchor.pop('field',None)
        rationale=value.get('developer_rationale',{})
        if rationale.get('events'):
            rationale['link_interpretation']='Path associations are not proven symbol intent or execution; exact anchors, when present, are syntactic links. Full action provenance is archived.'
            for event in rationale['events']:
                links=[]
                for link in event.get('links',[]):
                    item={k:link[k] for k in ('path','scope','edited_symbol_mentions') if link.get(k)}
                    if link.get('current_symbol_anchors'):
                        item['current_symbol_anchors']=[{k:a[k] for k in ('current_symbol','start_line','end_line','link','historical_scope_identity_proven') if k in a} for a in link['current_symbol_anchors']]
                    links.append(item)
                event['links']=links
        associations=value.get('flow_history_associations',{})
        if associations.get('nodes'):
            associations['detail_location']='Temporal hints and changes are in temporal_history at the same event_id. Associations do not prove semantic flow or exploitability.'
            for node in associations['nodes']:
                for event in node.get('temporal',[]):
                    for field in ('changes','hints','interpretation'):event.pop(field,None)
        block=value.get('temporal_change_cards',{})
        if block:
            block['target_lookup']='Resolve group_id to current_code_groups for path/symbol. Event detail is in temporal_history; source detail is in preloads/read.'
            for card in block.get('cards',[]):
                for field in ('path','symbol','recorded_intent','detail_abbreviated','current_source_detail_location'):
                    card.pop(field,None)
                for channel in card.get('temporal_changes',{}).values():
                    for event in channel.get('events',[]):event.pop('detail_location',None)
        block=value.get('reasoning_shortcut_cards',{})
        if block:
            block['target_lookup']='card_id is reason:<group_id>; resolve path/symbol in current_code_groups. Exact quotes/offsets are in developer_rationale or rationale retrieval.'
            for card in block.get('cards',[]):
                card.pop('path',None);card.pop('symbol',None)
                for excerpt in card.get('excerpts',[]):
                    excerpt.pop('span_id',None);excerpt.pop('quote_location',None)
        block=value.get('intent_implementation_divergence_cards',{})
        if block:
            block['target_lookup']='Join temporal_card_group_id to current_code_groups and temporal_change_cards; the reasoning card ID is reason:<group_id>. Sibling links are on the temporal card.'
            for card in block.get('cards',[]):
                for field in ('path','symbol','reasoning_card_id','sibling_comparison_ids'):
                    card.pop(field,None)
    return value


def verify_arms(common, history, ceiling):
    values = {a: arm_input(common, history, a) for a in ('C0','C1','C2','C3')}
    c0 = values['C0']
    withheld = {'status': 'withheld_by_arm'}
    assert c0['temporal_history'] == c0['developer_rationale'] == withheld
    assert values['C1']['developer_rationale'] == withheld
    assert values['C2']['temporal_history'] == withheld
    fields = {'temporal_change_cards','sibling_change_comparisons',
              'sibling_temporal_comparison_links','reasoning_shortcut_cards',
              'ast_invariant_completeness_cards','intent_implementation_divergence_cards',
              'flow_history_associations'}
    assert fields.isdisjoint(c0)
    shared = {k:v for k,v in c0.items() if k not in {'temporal_history','developer_rationale'}}
    forbidden={'cve_id','cwe_ids','security_patch','golden_patch','test_patch',
               'expected_pf','official_baseline_score'}
    def keys(value):
        if isinstance(value,dict):return set(value)|set().union(*(keys(v) for v in value.values()),set())
        if isinstance(value,list):return set().union(*(keys(v) for v in value),set())
        return set()
    for arm,value in values.items():
        assert all(value[k] == v for k,v in shared.items()), arm
        assert not (keys(value)&forbidden), (arm,keys(value)&forbidden)
    sizes = {a: initial_size(v) for a,v in values.items()}
    assert max(sizes.values()) <= min(72000, ceiling-25000), sizes
    return {'arm_isolation_verified': True, 'C0_treatment_cards_absent': True,
            'arm_initial_serialized_bytes': sizes,
            'arm_turn_headroom_bytes': {a:ceiling-s for a,s in sizes.items()},
            'shared_snapshot_sha256': hashlib.sha256(json.dumps(shared,sort_keys=True).encode()).hexdigest()}
