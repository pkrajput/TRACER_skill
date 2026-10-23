"""Evaluator-only retrospective audit. Never import this into a model runtime.

Reference fixes supply localization proxies here, after candidate generation.
No reference text is returned to an investigator and no archived code is executed.
"""
from collections import Counter, defaultdict
import difflib
import hashlib
import json
from pathlib import Path
import re
import sqlite3

from .citations import symbols
from security_ground_truth.repair_check.repair import eligible
from security_ground_truth.runtime.common import sha256, write_json, utcnow

ARMS=('C0','C1','C2','C3')
ROOTS={
    'deepseek':Path('/raid/prateek/ghost_code/security_experiments/20261018/temporal_security_v12'),
    'gemini':Path('/raid/prateek/ghost_code/security_experiments/20261019/gemini_v12_r2'),
}
LEDGERS={
    'deepseek':Path('/raid/prateek/ghost_code/security_experiments/20261014/investigator/budget.sqlite'),
    'gemini':Path('/raid/prateek/ghost_code/security_experiments/20261019/gemini_v12/provider/budget.sqlite'),
}
DEFAULT=Path('/raid/prateek/ghost_code/security_experiments/20261019/v12_local_funnel_recovery')


def read(path, default=None):
    return json.loads(Path(path).read_text()) if Path(path).exists() else default


def ledger_snapshot():
    result={}
    for name,path in LEDGERS.items():
        with sqlite3.connect('file:'+str(path)+'?mode=ro',uri=True) as db:
            count,total=db.execute('SELECT COUNT(*),COALESCE(SUM(micro_usd),0) FROM requests').fetchone()
        result[name]={'requests':count,'accounted_micro_usd':total}
    return result


def reference_targets(case,source_overrides=None):
    """Map actual changed reference lines to qualified base AST scopes.

    Hunk-header names are a documented fallback for missing/unparseable base
    sources. Never apply base line numbers directly to agent-modified source.
    """
    cp=Path(case['case_path']);patch=read(cp/'task.json')['security_patch']
    lines=defaultdict(set);hints=defaultdict(set);path=None;line=None
    for row in patch.splitlines():
        if row.startswith('--- '):
            path=row[4:].split('\t')[0];path=path[2:] if path.startswith('a/') else path;line=None
        elif row.startswith('@@ '):
            m=re.match(r'@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@(.*)',row)
            line=int(m[1]) if m else None
            hint=re.search(r'\b(?:def|class) (\w+)',m[2]) if m else None
            if path and hint:hints[path].add(hint[1])
        elif path and line is not None:
            if row.startswith('-') and not row.startswith('---'):
                lines[path].add(max(1,line));line+=1
            elif row.startswith('+') and not row.startswith('+++'):
                lines[path].add(max(1,line))
            elif row.startswith(' '):line+=1
    result={}
    for path,changed in lines.items():
        if not eligible(path):continue
        base=cp/'base_file_data'/path
        source=(source_overrides or {}).get(path)
        reconstructed=source is not None
        if source is None:source=base.read_text(errors='replace') if base.exists() else ''
        scopes=symbols(source)
        names=set();unmapped=[]
        for line in changed:
            matches=[s for s in scopes if s['start_line']<=line<=s['end_line']]
            if matches:names.add(min(matches,key=lambda s:s['end_line']-s['start_line'])['symbol'])
            else:unmapped.append(line)
        fallback=set()
        if not names:fallback=hints[path]
        result[path]={'qualified_symbols':sorted(names),'fallback_leaf_symbols':sorted(fallback),
            'changed_base_lines':sorted(changed),'unmapped_base_lines':unmapped,
            'base_source_sha256':sha256(base) if base.exists() else None,
            'mapped_source_sha256':hashlib.sha256(source.encode()).hexdigest(),
            'basis':('reconstructed_vulnerable_ast' if reconstructed else 'qualified_base_ast') if names else 'hunk_header_only' if fallback else 'file_only'}
    return result


def symbol_match(path,name,targets):
    ref=targets.get(path,{})
    if not name:return False
    return name in ref.get('qualified_symbols',[]) or name.split('.')[-1] in ref.get('fallback_leaf_symbols',[])


def hypothesis_location(hypothesis,case):
    target=hypothesis.get('target_symbol') or {}
    if isinstance(target,dict) and target.get('symbol'):return target['symbol']
    path=hypothesis.get('path','');src=(Path(case['baseline'])/'source'/path)
    if not eligible(path) or not src.exists():return None
    line=hypothesis.get('line');matches=[s for s in symbols(src.read_text(errors='replace'))
        if isinstance(line,int) and s['start_line']<=line<=s['end_line']]
    return min(matches,key=lambda s:s['end_line']-s['start_line'])['symbol'] if matches else '<module>'


def scanner_coverage(case,targets):
    alerts=read(Path(case['baseline'])/'alerts.json',[]);cache={};file_hit=False;symbol_hit=False
    for alert in alerts:
        path=alert.get('path');line=alert.get('line')
        if path not in targets:continue
        file_hit=True
        if path not in cache:
            source=Path(case['baseline'])/'source'/path
            cache[path]=symbols(source.read_text(errors='replace')) if source.exists() else []
        enclosing=[s for s in cache[path] if isinstance(line,int) and s['start_line']<=line<=s['end_line']]
        name=min(enclosing,key=lambda s:s['end_line']-s['start_line'])['symbol'] if enclosing else '<module>'
        symbol_hit |= symbol_match(path,name,targets)
    return {'reference_file_scanner_hit':file_hit,'reference_symbol_scanner_hit':symbol_hit,
            'any_repository_scanner_alerts':bool(alerts)}


def replay_text_edits(case,trajectory):
    """Replay only recorded successful string replacements, never tool code."""
    original={};current={};edits=[];errors=[];source=Path(case['baseline'])/'source'
    for turn in trajectory:
        for action,obs in zip(turn.get('answer',{}).get('actions',[]),turn.get('observations',[])):
            if action.get('action')!='edit' or obs.get('status')!='edited':continue
            path=action.get('path','');p=(source/path).resolve()
            if not eligible(path) or not p.is_relative_to(source.resolve()) or not p.is_file():
                errors.append('Invalid replay path: '+path);continue
            if path not in original:original[path]=p.read_text();current[path]=original[path]
            old,new=action.get('old'),action.get('new')
            if not isinstance(old,str) or not old or not isinstance(new,str) or current[path].count(old)!=1:
                errors.append('Nonunique replay at turn '+str(turn.get('step'))+': '+path);continue
            current[path]=current[path].replace(old,new,1)
            edits.append({'turn':turn.get('step',0)+1,'path':path,'hypothesis_id':action.get('hypothesis_id'),
                          'changed_from_original':current[path]!=original[path]})
    chunks=[]
    for path,text in sorted(current.items()):
        for line in difflib.unified_diff(original[path].splitlines(True),text.splitlines(True),fromfile='a/'+path,tofile='b/'+path):
            chunks.append(line if line.endswith('\n') else line+'\n\\ No newline at end of file\n')
    return ''.join(chunks),edits,errors


def classify_discard(result,trajectory,discard_hash,checks):
    """Classify pre-finalization evidence on the discarded patch, not the no-op.

    Reasons overlap; primary_reason is mutually exclusive. Rescue excludes
    known failure of this patch and interrupted/provider-error attempts.
    """
    edits=[t.get('step',0)+1 for t in trajectory for a,o in zip(t.get('answer',{}).get('actions',[]),t.get('observations',[]))
           if a.get('action')=='edit' and o.get('status')=='edited']
    last_edit=max(edits,default=0)
    actions=[(t.get('step',0)+1,a,o) for t in trajectory for a,o in zip(t.get('answer',{}).get('actions',[]),t.get('observations',[]))]
    current=[f for f in result.get('public_functional_checks',[]) if f.get('candidate_patch_sha256')==discard_hash]
    terminal=[f for f in current if f.get('functional_result',{}).get('test_status')=='completed'
              and f.get('functional_result',{}).get('terminal_result',{}).get('recognized') is True]
    passed=any(f.get('functional_result',{}).get('pass') is True for f in terminal)
    failed=any(f.get('functional_result',{}).get('pass') is False for f in terminal)
    exhausted=any(t>=last_edit and a.get('action')=='functional' and o.get('status')=='functional_budget_exhausted' for t,a,o in actions)
    functional_after=any(t>=last_edit and a.get('action')=='functional' and o.get('status')=='executed' for t,a,o in actions)
    turn_limit=result.get('status')=='turn_limit' and result.get('model_calls',0)>=22
    gates=result.get('unseeded_final_gate_failures',[])
    missing_probe=bool(gates) and all('rerun_' in str(g) for g in gates)
    violation=any(c.get('candidate_patch_sha256')==discard_hash and any(
        o.get('property')=='unseeded_property_violated' and o.get('value') is True
        for o in c.get('feedback',{}).get('observations',[])) for c in checks)
    reassess=any('reassess_repaired_hypothesis_on_current_candidate' in str(o.get('error','')) for _,_,o in actions)
    interrupted=result.get('status')=='repair_error'
    flags={'functional_cap_after_last_edit':exhausted and not passed,
        'turn_limit_without_current_functional':turn_limit and not current,
        'turn_limit_without_functional_after_edit':turn_limit and not functional_after,
        'missing_probe_rerun':missing_probe,'recorded_post_edit_reassessment_rejection':reassess,
        'current_functional_pass':passed,'current_functional_fail':failed,
        'current_functional_incomplete':bool(current) and not terminal,
        'current_probe_reports_violation':violation,'repair_error':interrupted}
    if failed:reason='failed_public_functional_on_discarded_patch'
    elif violation:reason='probe_reports_remaining_violation'
    elif interrupted:reason='repair_error_interrupted_validation'
    elif current and not terminal:reason='functional_execution_incomplete'
    elif exhausted and not passed:reason='functional_two_slot_cap'
    elif turn_limit and not current:reason='turn_limit_before_current_functional'
    elif missing_probe:reason='missing_post_edit_probe_rerun'
    else:reason='other_or_unattributed'
    allowed={'functional_two_slot_cap','turn_limit_before_current_functional','missing_post_edit_probe_rerun'}
    eligible_rescue=reason in allowed and not (failed or violation or interrupted) and (not gates or missing_probe)
    return {'primary_reason':reason,'reason_flags':flags,'rescue_eligible':eligible_rescue,
        'last_successful_edit_turn':last_edit,'discarded_patch_functional_records':len(current),
        'discarded_patch_functional_terminal_records':len(terminal),'actual_final_gate_failures':gates,
        'post_edit_reassessment_alone_discards_patch':False}


def audit_cell(model,cell,case,targets,coverage,replay_out):
    result=read(cell/'result.json');trajectory=read(cell/'trajectory.json',[])
    hypotheses=read(cell/'hypotheses.json',{});assessments=read(cell/'assessments.json',[])
    by_file={ident for ident,h in hypotheses.items() if h.get('path') in targets}
    by_symbol={ident for ident in by_file if symbol_match(hypotheses[ident]['path'],hypothesis_location(hypotheses[ident],case),targets)}
    supported={a['hypothesis_id'] for a in assessments if a.get('decision')=='supported'}
    replay,edits,errors=replay_text_edits(case,trajectory)
    retained=cell/'candidate.patch';discarded=cell/'unvalidated_candidate.patch'
    has_discard=discarded.exists() and discarded.stat().st_size>0 and retained.stat().st_size==0
    patch=discarded if has_discard else retained
    replay_match=not errors and replay==patch.read_text()
    replay_path=None
    if replay and not replay_match:
        replay_out.mkdir(parents=True,exist_ok=True);p=replay_out/'replayed_working_tree.patch';p.write_text(replay);replay_path=str(p)
    row={'investigator':model,'case_key':case['case_key'],'arm':cell.name,'cell':str(cell),
        'instance_id':case['instance_id'],'generator':case['model_name'],'stratum':case['v12_stratum'],
        'repair_status':result['status'],'model_calls':result['model_calls'],'error':result.get('error'),
        'original_complete_present':(cell/'complete.json').exists(),'candidate_patch_sha256':sha256(retained),
        'candidate_patch_bytes':retained.stat().st_size,'discarded_patch_sha256':sha256(discarded) if has_discard else None,
        'discarded_patch_bytes':discarded.stat().st_size if has_discard else 0,
        'stage1_reference_file':bool(by_file),'stage1_reference_symbol':bool(by_symbol),
        'stage2_supported_reference_file':bool(by_file&supported),'stage2_supported_reference_symbol':bool(by_symbol&supported),
        'localized_hypotheses':sorted(by_symbol),'supported_localized_hypotheses':sorted(by_symbol&supported),
        'stage3_any_patch_written':any(e['changed_from_original'] for e in edits) or patch.stat().st_size>0,
        'stage3_reference_file_edited':any(e['path'] in targets and e['changed_from_original'] for e in edits),
        'successful_edits':edits,'stage4_discarded_to_zero':has_discard,
        'reference_targets':targets,**coverage,
        'input_has_scanner_alerts':bool(read(cell/'input.json',{}).get('scanner_alerts')),
        'text_replay_matches_final_buffer':replay_match,'text_replay_errors':errors,'replayed_patch':replay_path}
    if has_discard:
        row['discard']=classify_discard(result,trajectory,sha256(discarded),read(cell/'check_evidence.json',[]))
        if not replay_match:row['discard']['rescue_eligible']=False;row['discard']['identity_hold']='text_replay_mismatch'
    else:row['discard']=None
    row['artifact_sha256']={p.name:sha256(p) for p in [cell/'result.json',retained,cell/'trajectory.json',discarded,cell/'complete.json'] if p.exists()}
    return row


def prepare(root=DEFAULT):
    root=Path(root)
    if (root/'manifest.json').exists():return read(root/'manifest.json')
    root.mkdir(parents=True,exist_ok=True);cases=read(ROOTS['deepseek']/'cases.json');by={c['case_key']:c for c in cases}
    before=ledger_snapshot();cache={};rows=[]
    for model,base in ROOTS.items():
        if not (base/'STOP').exists():raise ValueError('Paid campaign STOP marker missing')
        files=sorted((base/'cells').glob('*/*/result.json'))
        expected={'deepseek':777,'gemini':935}[model]
        if len(files)!=expected:raise ValueError(f'Inventory drift: {model} {len(files)} != {expected}')
        for p in files:
            c=by[p.parent.parent.name];key=c['case_key']
            if key not in cache:
                targets=reference_targets(c);cache[key]=(targets,scanner_coverage(c,targets))
            rows.append(audit_cell(model,p.parent,c,*cache[key],root/'replays'/model/key/p.parent.name))
    if ledger_snapshot()!=before:raise ValueError('Model ledger changed during offline audit')
    write_json(root/'cases.json',cases);write_json(root/'audit.json',rows)
    manifest={'utc':utcnow(),'model_calls_authorized':0,'ledger_before':before,
        'cases_sha256':sha256(root/'cases.json'),'audit_sha256':sha256(root/'audit.json'),
        'cells':len(rows),'pending_original_evaluations':dict(Counter(r['investigator'] for r in rows if not r['original_complete_present'])),
        'discarded_cells':dict(Counter(r['investigator'] for r in rows if r['stage4_discarded_to_zero'])),
        'rescue_eligible':dict(Counter(r['investigator'] for r in rows if r['discard'] and r['discard']['rescue_eligible'])),
        'reference_use':'Evaluator-only localization proxy; no diagnoses or labels enter any model runtime.',
        'paid_roots_remain_stopped':True}
    write_json(root/'manifest.json',manifest);return manifest
