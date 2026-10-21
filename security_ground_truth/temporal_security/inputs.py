"""Build a common label-blind plan before the four independent interventions."""
import json
import hashlib
from pathlib import Path
from security_ground_truth.runtime.common import write_json,sha256
from security_ground_truth.runtime.alert_identity import unique_alerts
from .planner import plan
from .history import build_case_history
from .engine import arm_input
from .flow_context import build_flows, flow_targets, POLICY
from .change_audit import POLICY as CHANGE_POLICY, current_facts, cards, boundary_questions
from .change_symmetry import profile,comparisons

def prepare(case, output, *, v12_base=False):
    output.mkdir(parents=True,exist_ok=True)
    preparation_sha256=hashlib.sha256(''.join(sha256(Path(__file__).with_name(n)) for n in
        ['inputs.py','planner.py','history.py','gumtree.py','rationale.py','change_audit.py','change_symmetry.py','flow_context.py','engine.py','v9_cards.py','v9_protocol.py','edit_validation.py','unseeded_gate.py']).encode()).hexdigest()
    if (output/'ready.json').exists():
        ready=json.loads((output/'ready.json').read_text())
        if ready.get('flow_policy') != POLICY or ready.get('change_policy')!=CHANGE_POLICY or ready.get('preparation_sha256')!=preparation_sha256:
            raise ValueError('Prepared inputs belong to another protocol; use a new output directory, never overwrite frozen v6 inputs')
        return json.loads((output/'common.json').read_text()),json.loads((output/'history.json').read_text())
    baseline=Path(case['baseline']);casepath=Path(case['case_path'])
    alerts=unique_alerts(json.loads((baseline/'alerts.json').read_text()))
    planned=plan(baseline/'source',(casepath/'agent_effective.patch').read_text(),alerts,max_groups=12,max_context_chars=30000)
    write_json(output/'plan.json',planned)
    selected=[]
    for row in planned['selected_groups']:
        selected.append({k:row[k] for k in ['group_id','path','symbol','start_line','end_line','source','source_abbreviated','alert_ids',
                                         'is_changed','review_role','changed_lines','deletion_anchors']})
        selected[-1].update(calls=row['calls'][:12],guards=row['guards'][:8])
    ledger=[r for r in planned['scanner_ledger'] if r['in_selected_context']]
    lookup={a['alert_id']:a for a in alerts}
    scoped_alerts=[lookup[r['alert_id']] for r in ledger[:40]]
    flows=build_flows(baseline/'source',scoped_alerts)
    # Changed symbols get history/rationale budgets before legacy scanner nodes.
    targets=[{'path':r['path'],'symbol':None if r['symbol']=='<module>' else r['symbol']} for r in selected if r['is_changed']]
    targets.extend(flow_targets(flows))
    targets.extend({'path':r['path'],'symbol':None if r['symbol']=='<module>' else r['symbol']} for r in selected if not r['is_changed'])
    targets=list({(r['path'],r['symbol']):r for r in targets}.values())
    evidence=build_case_history(case,targets,source_root=baseline/'source',max_pairs_per_target=2,max_history_chars=12000,max_rationale_chars=5000)
    write_json(output/'history.json',evidence)
    # Native scanner flow stays retrievable by ID; present bounded context initially.
    initial_alerts=[{k:r[k] for k in ['alert_id','tool','rule_id','path','line','message','linked_group_ids',
                                    'review_role','line_in_agent_patch','symbol_modified_by_agent','provenance_note']} for r in ledger[:40]]
    task=json.loads((casepath/'task.json').read_text())
    identity=json.loads((casepath/'image_identity.json').read_text())
    common={'protocol_revision':'v9-intent-implementation-divergence','functional_request':task['problem_statement'][:9000],
            'current_code_groups':selected,
            'change_audit_bases':[{'path':r['path'],'symbol':r['symbol'],'group_id':r['group_id'],
                'patch_facts':current_facts((baseline/'source'/r['path']).read_text(),r),
                'current_syntax_boundary_questions':boundary_questions(r)}
                for r in planned['selected_groups'] if r['review_role']=='primary_agent_modified'],
            'changed_symbol_inventory':[{k:r[k] for k in ['path','symbol','start_line','end_line']} for r in planned['changed_symbols'][:180]],
            'scanner_alerts':initial_alerts,'scanner_counts':planned['counts'],
            'sibling_change_comparisons':comparisons([profile((baseline/'source'/r['path']).read_text(),r)
                for r in planned['selected_groups'] if r['review_role']=='primary_agent_modified' and r['symbol']!='<module>']),
            'scanner_flow_context':flows,
            'remaining_alerts_not_initially_presented':max(0,len(ledger)-40),
            'source_environment':{'workdir':identity['workdir'],'public_functional_command':identity['command']},
            'scope':'Analyze current functionally working output; benchmark security outcome and reference implementation are unavailable.',
            'method_sequence':['compressed temporal AST evidence (where enabled)','current static/flow hypothesis',
                               'static assessment','PoC fallback only when static evidence is inconclusive',
                               'supported repair','post-edit reassessment','public functional validation','final candidate']}
    # Freeze the same card targets for all arms using the largest treatment.
    selected_cards=cards(common,evidence,True,True)
    card_ids={c['group_id'] for c in selected_cards['cards']}
    common['change_cards_omitted_by_shared_budget']=len(common['change_audit_bases'])-len(card_ids)
    common['change_audit_bases']=[c for c in common['change_audit_bases'] if c['group_id'] in card_ids]
    # Reduce common source context identically for all arms, never truncate only a treatment.
    for limit in [2200,1600,1000,600]:
        if len(json.dumps(arm_input(common,evidence,'C3')).encode())<=74000:break
        for g in common['current_code_groups']:
            if len(g['source'])>limit:g['source']=g['source'][:limit];g['source_abbreviated']=True
    size=len(json.dumps(arm_input(common,evidence,'C3')).encode())
    if size>78000:
        common['scanner_flow_context']=build_flows(baseline/'source',scoped_alerts,max_bytes=8000)
        size=len(json.dumps(arm_input(common,evidence,'C3')).encode())
    if size>78000:
        # Keep all targets and sibling comparisons. Large duplicate syntax lists
        # remain retrievable through structure; trim them identically in all arms.
        for group in common['current_code_groups']:
            for field in ['calls','guards']:
                group[field+'_omitted_from_initial']=max(0,len(group[field])-3)
                group[field]=group[field][:3]
        size=len(json.dumps(arm_input(common,evidence,'C3')).encode())
    for association_limit in [6000,4000,2000]:
        if size<=78000:break
        common['flow_association_max_bytes']=association_limit
        size=len(json.dumps(arm_input(common,evidence,'C3')).encode())
    # Compress duplicated card detail into event references, preserving all
    # selected symbols and the independent underlying temporal/rationale data.
    for card_limit in [14000,11000,8000]:
        if size<=78000:break
        common['temporal_card_max_bytes']=card_limit
        size=len(json.dumps(arm_input(common,evidence,'C3')).encode())
    if size>78000 and not v12_base:raise ValueError(f'Evidence exceeds shared context budget ({size} bytes); no request dispatched')
    write_json(output/'common.json',common)
    write_json(output/'ready.json',{'case_key':case['case_key'],'largest_initial_bytes':size,
               'original_patch_sha256':sha256(casepath/'agent_effective.patch'),
               'source_manifest_sha256':sha256(baseline/'source_manifest.json'),
               'common_sha256':sha256(output/'common.json'),'history_sha256':sha256(output/'history.json'),
               'security_labels_used':False,'flow_policy':POLICY,'change_policy':CHANGE_POLICY,
               'preparation_sha256':preparation_sha256})
    return common,evidence
