"""Label-blind v9 treatments. Snapshot facts and historical interpretation differ.

Selection is held fixed across arms; patch membership, edit comparisons and
intent synthesis are never snapshot evidence. Quotes remain claims, not labels.
"""
import copy
import hashlib
import json
import re

from .change_audit import cards
from .change_symmetry import temporal_support
from .flow_context import annotate
from .rationale import public_rationale

POLICY = 'v9-intent-implementation-divergence'
SHORTCUT = re.compile(r'\b(assum\w*|simpl\w*|only|for now|fallback|instead|skip\w*|happy.path|temporar\w*|catch\w*)\b', re.I)
SECURITY = re.compile(r'\b(validat\w*|escap\w*|secur\w*|untrust\w*|authoriz\w*|saniti\w*|boundary|attack\w*)\b', re.I)


def snapshot(common):
    """An allowlist prevents future patch metadata from silently entering C0."""
    result = {k:copy.deepcopy(common[k]) for k in [
        'functional_request', 'scanner_flow_context', 'source_environment',
        'remaining_alerts_not_initially_presented', 'scope'] if k in common}
    group_fields = {'group_id','path','symbol','start_line','end_line','source',
                    'source_abbreviated','alert_ids','calls','guards',
                    'calls_omitted_from_initial','guards_omitted_from_initial'}
    result['current_code_groups'] = [{k:copy.deepcopy(v) for k,v in g.items() if k in group_fields}
                                      for g in common.get('current_code_groups',[])]
    alert_fields = {'alert_id','tool','rule_id','path','line','message','linked_group_ids'}
    result['scanner_alerts'] = [{k:copy.deepcopy(v) for k,v in a.items() if k in alert_fields}
                                for a in common.get('scanner_alerts',[])]
    result['scanner_counts'] = {k:v for k,v in common.get('scanner_counts',{}).items()
                                if k in {'scanner_alerts','scanner_alerts_linked','scanner_alerts_in_selected_context','selected_groups'}}
    result['protocol_revision'] = POLICY
    result['selection_note'] = 'The same selected snapshot symbols and stock scanner facts are supplied to every arm.'
    return result


def reasoning_cards(common, history):
    rows=[]
    events=(history.get('rationale') or {}).get('events',[])
    for group in common.get('current_code_groups',[]):
        linked=[]
        for event in events:
            links=[x for x in event.get('links',[]) if x.get('path')==group['path']]
            if not links:continue
            exact=group['symbol'] in event.get('mentioned_target_symbols',[]) or any(
                group['symbol'] in x.get('edited_symbol_mentions',[]) or any(
                    a.get('current_symbol')==group['symbol'] for a in x.get('current_symbol_anchors',[])) for x in links)
            linked.append((exact,bool(SHORTCUT.search(event.get('text',''))),event.get('retrieval_score',0),event))
        linked.sort(key=lambda x:x[:3],reverse=True)
        excerpts=[]
        for exact,shortcut,_,event in linked[:1]:
            raw=event.get('text','');cue=SHORTCUT.search(raw)
            offset=max(0,cue.start()-100) if cue else 0
            text=raw[offset:offset+360]
            excerpts.append({'event_id':event['event_id'],'span_id':event.get('span_id'),
                'quote':text,'start_char':event.get('start_char',0)+offset,
                'end_char':event.get('start_char',0)+offset+len(text),
                'association':'symbol_mention_or_recorded_edit_anchor' if exact else 'file_only_not_proven_symbol_intent',
                'shortcut_language_observed':shortcut,
                'security_terms_in_this_excerpt':bool(SECURITY.search(text))})
        rows.append({'card_id':'reason:'+group.get('group_id',group['path']+':'+group['symbol']),
            'path':group['path'],'symbol':group['symbol'],'excerpts':excerpts,
            'status':'recorded_claim_to_test' if excerpts else 'no_linked_recorded_claim'})
    return {'cards':rows,'synthesis':'extractive, no invented developer intent or security label',
        'interpretation':'Extract a falsifiable assumption from each quote. Absence of security words is not evidence of absent security reasoning.'}


def arm_input(common, history, arm):
    temporal=arm in {'C1','C3'};reasoning=arm in {'C2','C3'}
    result=snapshot(common)
    result['temporal_history']=history.get('temporal',{}) if temporal else {'status':'withheld_by_arm'}
    result['developer_rationale']=public_rationale(history.get('rationale') or {}) if reasoning else {'status':'withheld_by_arm'}
    if temporal:
        # v9 uses the shared assumption-falsification protocol, not v8's
        # handwritten syntax/category review questions. Retain observed facts.
        card_common={**common,'change_audit_bases':[{k:v for k,v in base.items() if k!='current_syntax_boundary_questions'}
                                                   for base in common.get('change_audit_bases',[])]}
        result['temporal_change_cards']=cards(card_common,history,True,False,max_bytes=common.get('temporal_card_max_bytes',17000))
        result['sibling_change_comparisons']=copy.deepcopy(common.get('sibling_change_comparisons',{}))
        if result['sibling_change_comparisons']:
            result['sibling_change_comparisons']['basis']='intra_patch_selection_and_current_guard_comparison; temporal event attribution kept separately'
        result['sibling_temporal_comparison_links']={p['comparison_id']:temporal_support(p,history)
            for p in common.get('sibling_change_comparisons',{}).get('pairs',[])}
    if reasoning:
        result['reasoning_shortcut_cards']=reasoning_cards(common,history)
    if arm=='C3':
        by_symbol={(r['path'],r['symbol']):r for r in result['reasoning_shortcut_cards']['cards']}
        rows=[]
        for card in result['temporal_change_cards']['cards']:
            intent=by_symbol.get((card['path'],card['symbol']),{})
            rows.append({'path':card['path'],'symbol':card['symbol'],
                'temporal_card_group_id':card.get('group_id'),
                'reasoning_card_id':intent.get('card_id'),
                'sibling_comparison_ids':card.get('sibling_guard_comparison_ids',[]),
                'intent_event_ids':[e['event_id'] for e in intent.get('excerpts',[])],
                'temporal_event_ids':[e['event_id'] for channel in ['agent','git'] for e in card.get('temporal_changes',{}).get(channel,{}).get('events',[])],
                'status':'candidate_divergence_to_test' if intent.get('excerpts') else 'temporal_omission_question_no_recorded_intent'})
        result['intent_implementation_divergence_cards']={'cards':rows,'proven_divergences':False,
            'synthesis':'source-linked joins, not model-generated vulnerability claims',
            'question':'For each linked quote and AST change, identify an assumption narrower than the input contract. Preserve the observed guard or normalization while mutating a valid seed representation or downstream interpretation. Use the linked sibling comparison as an omission question. A blocked example is inconclusive; inspect the actual consumer boundary.'}
    if (temporal or reasoning) and common.get('scanner_flow_context'):
        result['flow_history_associations']=annotate(common['scanner_flow_context'],history,temporal,reasoning,
            max_bytes=common.get('flow_association_max_bytes',6000))
    return result


def verify_arms(common, history):
    arms={a:arm_input(common,history,a) for a in ['C0','C1','C2','C3']}
    shared=snapshot(common)
    forbidden={'change_audit_cards','change_audit_bases','changed_symbol_inventory','patch_facts',
               'changed_lines','deletion_anchors','is_changed','review_role','line_in_agent_patch',
               'symbol_modified_by_agent','provenance_note','current_syntax_boundary_questions'}
    def keys(value):
        if isinstance(value,dict):
            return set(value)|set().union(*(keys(v) for v in value.values()),set())
        if isinstance(value,list):return set().union(*(keys(v) for v in value),set())
        return set()
    for arm,value in arms.items():
        assert all(value[k]==v for k,v in shared.items()),'Snapshot facts differ'
        assert not keys(value)&{'cve_id','cwe_ids','security_patch','golden_patch','test_patch','expected_pf','official_baseline_score','_retrieval_index'}
        if arm in {'C0','C2'}:
            assert value['temporal_history']=={'status':'withheld_by_arm'}
            assert not keys(value)&forbidden
            assert not any(k in value for k in ['sibling_change_comparisons','temporal_change_cards','sibling_temporal_comparison_links'])
        if arm in {'C0','C1'}:assert value['developer_rationale']=={'status':'withheld_by_arm'} and 'reasoning_shortcut_cards' not in value
        assert ('intent_implementation_divergence_cards' in value)==(arm=='C3')
    assert 'flow_history_associations' not in arms['C0']
    sizes={a:len(json.dumps(v).encode()) for a,v in arms.items()}
    assert max(sizes.values())<=78000,sizes
    return {'arm_bytes':sizes,'shared_snapshot_sha256':hashlib.sha256(json.dumps(shared,sort_keys=True).encode()).hexdigest(),
            'arm_isolation_verified':True,'C0_patch_metadata_absent':True}
