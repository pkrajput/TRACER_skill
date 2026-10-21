"""Evaluator-only matched v6/v7/v8 report; never imported by the investigator."""
import collections
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from security_ground_truth.runtime.common import write_json,utcnow,sha256
from security_ground_truth.repair_check.official_score import load_authors_classes
from .dev_pilot_report import read,score_cell,metrics,localization
from .unseeded_gate import control_program_qualified,before_control,after_control

V7=Path('/raid/prateek/ghost_code/security_experiments/20261018/temporal_security_v7_dev')


def dynamic_audit(cell):
    result=read(cell/'result.json',{});hypotheses=read(cell/'hypotheses.json',{});attempts=[];gates=[]
    for p in sorted(cell.glob('checks/*/input/check.py')):
        code=p.read_text();feedback=read(p.parent.parent/'feedback.json',{})
        if 'unseeded_ordinary_control_pass' not in code:continue
        attempts.append({'code_path':str(p),'code_sha256':hashlib.sha256(code.encode()).hexdigest(),
            'ordinary_control_program_qualified':control_program_qualified(code),'feedback':feedback,
            'candidate_patch_sha256':feedback.get('candidate_patch_sha256')})
    for ident,gate in result.get('unseeded_repair_gates',{}).items():
        if gate.get('mode')!='dynamic_control':continue
        checks=[{**c,'hypothesis_id':ident} for c in attempts if c['code_sha256']==gate['before_check_code_sha256']]
        computed=bool(checks) and all(c['ordinary_control_program_qualified'] for c in checks)
        before=any(c['candidate_patch_sha256']==gate['candidate_patch_sha256'] and before_control(c) for c in checks)
        after=after_control(gate,ident,checks,result.get('patch_sha256'))
        gates.append({'hypothesis_id':ident,'computed_control':computed,'before_qualified':before,
            'after_qualified_on_final_patch':after,'candidate_retained':hypotheses.get(ident,{}).get('path') in result.get('changed_paths',[]),
            'code_paths':[c['code_path'] for c in checks]})
    return {'attempts':attempts,'accepted_gates':gates,
            'constant_or_missing_control_attempts':sum(not x['ordinary_control_program_qualified'] for x in attempts),
            'accepted_constant_controls':sum(not x['computed_control'] for x in gates)}


def measured(cell):
    m=metrics(cell);blocked=0
    for t in read(cell/'trajectory.json',[]):
        observations=t.get('observations',[]) if isinstance(t,dict) else []
        if not isinstance(observations,list):observations=[]
        blocked+=sum(isinstance(o,dict) and o.get('status')=='blocked_repeated_action'
                     for o in observations)
    m['blocked_repeated_actions']=blocked;m['rejected']+=blocked
    m['unseeded_gate_rejections']+=sum(n for e,n in m['errors'].items() if e.startswith('Inspect the downstream caller/consumer'))
    m['citation_rejections']+=sum(n for e,n in m['errors'].items() if 'conclusive static assessment needs exact evidence' in e)
    m['source_citation_rejections']=m['citation_rejections']
    m['rationale_citation_rejections']=sum(n for e,n in m['errors'].items() if e.startswith('Cite an exact') and 'rationale event' in e)
    m['citation_rejections']+=m['rationale_citation_rejections']
    return m


def outcome(row):
    ev=row.get('evaluation')
    if not ev or not all(ev['terminal_completed'].values()):return 'incomplete'
    return 'F%d/S%d'%(ev['score']['func_pass'],ev['score']['sec_pass'])


def report(root):
    root=Path(root);manifest=read(root/'manifest.json');cases=read(root/'cases.json')
    ns=load_authors_classes(root/'upstream_logs.py');rows=[]
    for case in cases:
        for version,base in [('v6',Path(manifest['parent'])/'experiment'),('v7-dev',V7),('v8-dev',root)]:
            for arm in ['C0','C3']:
                cell=base/'cells'/case['case_key']/arm
                rows.append({'case_key':case['case_key'],'instance_id':case['instance_id'],'version':version,'arm':arm,
                    'cell':str(cell),'metrics':measured(cell),'evaluation':score_cell(cell,case,ns,allow_archived_noop=version=='v6'),
                    'localization':localization(cell,case),'dynamic_control':dynamic_audit(cell)})
    plan=read(root/'report_inputs/DEV_CALIBRATION.json')
    failed=[k for k,v in plan['selection_reasons'].items() if set(v)&{'seeded_failed_edit','unseeded_failed_edit'}]
    summary={}
    for version in ['v6','v7-dev','v8-dev']:
        for arm in ['C0','C3']:
            selected=[r for r in rows if r['version']==version and r['arm']==arm]
            gates=[g for r in selected for g in r['dynamic_control']['accepted_gates']]
            complete=[r for r in selected if outcome(r)!='incomplete']
            probes=collections.Counter();exceptions=collections.Counter()
            for row in selected:
                probes.update(row['metrics']['probes']);exceptions.update(row['metrics']['probe_exception_categories'])
            summary[version+':'+arm]={'cells':20,'completed_evaluations':len(complete),
                'func_pass':sum(r['evaluation']['terminal_completed']['func'] and r['evaluation']['score']['func_pass'] for r in selected if r['evaluation']),
                'sec_pass':sum(r['evaluation']['score']['sec_pass'] for r in complete),
                'failed12_sec_pass':sum(r['case_key'] in failed and r['evaluation']['score']['sec_pass'] for r in complete),
                'rejected_per_cell':sum(r['metrics']['rejected'] for r in selected)/20,
                **{k:sum(r['metrics'][k] for r in selected) for k in ['rejected','citation_rejections','source_citation_rejections','rationale_citation_rejections','unseeded_gate_rejections','blocked_repeated_actions']},
                'turn_limits':sum(r['metrics']['status']=='turn_limit' for r in selected),
                'repair_errors':sum(r['metrics']['status']=='repair_error' for r in selected),
                'old_current_read_errors':sum(r['metrics']['old_current_read_error'] for r in selected),
                'stale_citation_errors':sum(r['metrics']['explicit_stale_citations'] for r in selected),
                'repeated_errors_without_success':sum(r['metrics']['same_error_repeated_without_intervening_success'] for r in selected),
                'probes':dict(probes),'probe_exceptions':dict(exceptions),
                'accepted_dynamic_gates':len(gates),'computed_dynamic_controls':sum(g['computed_control'] for g in gates),
                'qualified_dynamic_before':sum(g['before_qualified'] for g in gates),
                'retained_dynamic_gates':sum(g['candidate_retained'] for g in gates),
                'qualified_dynamic_after':sum(g['candidate_retained'] and g['after_qualified_on_final_patch'] for g in gates),
                'accepted_constant_controls':sum(not g['computed_control'] for g in gates),
                'constant_control_attempts':sum(r['dynamic_control']['constant_or_missing_control_attempts'] for r in selected)}
    config=read(root/'config.json');scope=config['budget_scope']
    with sqlite3.connect('file:'+str(Path(manifest['ledger_root'])/'budget.sqlite')+'?mode=ro',uri=True) as db:
        costs=db.execute("SELECT micro_usd,details FROM requests WHERE json_extract(details,'$.budget_scope')=?",(scope['id'],)).fetchall()
        total=db.execute('SELECT SUM(micro_usd) FROM requests').fetchone()[0]
    known=[];unknown=[]
    for micro,raw in costs:
        value=(json.loads(raw).get('usage') or {}).get('cost')
        if isinstance(value,(int,float)):known.append(value)
        else:unknown.append(micro)
    budget={'provider_reported_usd':sum(known),'accounted_usd':sum(c[0] for c in costs)/1e6,
        'unknown_billing_requests':len(unknown),'unknown_reservations_usd':sum(unknown)/1e6,'requests':len(costs),
        'incremental_cap_usd':scope['cap_micro_usd']/1e6,'starting_accounted_usd':scope['initial_total_micro_usd']/1e6,
        'total_accounted_usd':total/1e6,'within_cap':sum(c[0] for c in costs)<=scope['cap_micro_usd'] and total<=scope['initial_total_micro_usd']+scope['cap_micro_usd']}
    review=read(root/'report/MECHANISM_REVIEW.json',{})
    dynamic_review=read(root/'report/DYNAMIC_CONTROL_REVIEW.json',{})
    data={'utc':utcnow(),'status':read(root/'status.json',{}).get('status'),'summary':summary,'rows':rows,
        'failed_edit_case_keys':failed,'budget':budget,'mechanism_review':review,'protected_overlap':0,
        'full_cohort_dispatched':False,'reporter_sha256':sha256(Path(__file__)),
        'mechanism_review_sha256':sha256(root/'report/MECHANISM_REVIEW.json') if (root/'report/MECHANISM_REVIEW.json').exists() else None,
        'dynamic_semantic_review':dynamic_review,
        'dynamic_semantic_review_sha256':sha256(root/'report/DYNAMIC_CONTROL_REVIEW.json') if (root/'report/DYNAMIC_CONTROL_REVIEW.json').exists() else None,
        'final_verification':read(root/'report/V8_FINAL_VERIFICATION.json',{})}
    write_json(root/'report/V8_DEV_COMPARISON.json',data)
    lines=['# v6 / v7-dev / v8-dev: matched development calibration','',
        f"Status: **{data['status']}**. Same 20 cases, C0/C3, 22 turns; 40 v8 cells and 80 fresh final functional/security executions. Protected 142 attempts / 48 tasks excluded. No bulk release.",'',
        'Prelaunch: all 20 cases rebuilt under `v8_local_mechanism_redesign/pilot_20_verified`; all 80 local C0/C1/C2/C3 bundles passed shared-fact and arm-isolation checks. Only C0/C3 were dispatched. All 160 local tests passed before the run. Generic sibling comparisons were shared across arms; C3 additionally received recorded temporal links and rationale. The frozen engine and inputs were not changed during the pilot.','',
        f"Investigator: `{config['model']}` via `{config['provider']}`, unchanged from v7. C0 has current code/SAST, sibling guard comparisons and conditional PoC. C3 adds separately recorded temporal edits and original rationale. Shared source facts, scanner-negative gate, budget and protocol are identical. Original baseline: FuncPass 20/20, SecPass 2/20.",'',
        f"The 20 attempts cover {len({c['instance_id'] for c in cases})} tasks. Archived generators in this fixed development subset: {dict(collections.Counter(c['model_name'] for c in cases))}.",'',
        '| Revision / arm | Complete eval | FuncPass | SecPass | Previously failed 12: SecPass | Rejected/cell | Citation errors | Unseeded-gate rejections | Turn limit |',
        '|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    for name,s in summary.items():lines.append(f"| {name} | {s['completed_evaluations']}/20 | {s['func_pass']}/20 | {s['sec_pass']}/20 | {s['failed12_sec_pass']}/12 | {s['rejected_per_cell']:.2f} | {s['citation_rejections']} | {s['unseeded_gate_rejections']} | {s['turn_limits']}/20 ({s['turn_limits']*5}%) |")
    if all(summary['v8-dev:'+a]['completed_evaluations']==20 for a in ['C0','C3']):
        c0=summary['v8-dev:C0'];c3=summary['v8-dev:C3']
        lines+=['',f"**Verified v8 outcome:** C0 FuncPass {c0['func_pass']}/20, SecPass {c0['sec_pass']}/20; C3 FuncPass {c3['func_pass']}/20, SecPass {c3['sec_pass']}/20. The previously failed twelve yield {c0['failed12_sec_pass']}/12 verified security passes in C0 and {c3['failed12_sec_pass']}/12 in C3. These are official benchmark outcomes, not investigator judgments."]
    lines+=['','Pass counts require recognized terminal completion and use the official benchmark allowances for pre-existing test failures; FuncPass does not mean zero raw test failures. Incomplete execution is reported separately; it is not a verified vulnerability label. Rejected counts include blocked repeated calls; gate counts include the new downstream-inspection edit rejection.','',
        f"Provider-reported cost: **${budget['provider_reported_usd']:.6f}**. Accounted incremental spend: **${budget['accounted_usd']:.6f} / $15.00**, including {len(unknown)} unknown-cost reservations (${budget['unknown_reservations_usd']:.6f}). Total ledger: **${budget['total_accounted_usd']:.6f}**; absolute ceiling $294.823291. Within cap: {budget['within_cap']}.",'',
        '## Execution friction and probe completion','',
        '| Revision / arm | Old current-read errors | Stale citations | Repeated errors without success | Repeats blocked | Completed probes / attempted | Django environment exceptions | Non-scalar exceptions |',
        '|---|---:|---:|---:|---:|---:|---:|---:|']
    for name,s in summary.items():
        p=s['probes'];e=s['probe_exceptions']
        lines.append(f"| {name} | {s['old_current_read_errors']} | {s['stale_citation_errors']} | {s['repeated_errors_without_success']} | {s['blocked_repeated_actions']} | {p.get('completed',0)}/{p.get('total',0)} | {p.get('django_environment_exceptions',0)} | {e.get('observation_serializer_rejected_non_scalar',0)} |")
    lines+=['','Counts are for these same 40 cells only; the earlier 2,589 citation-error figure covered a larger cohort and is not the matched denominator. This report includes rejected rationale quotations in citation errors consistently across all three revisions (the earlier v7 report counted source citations only). Separate source/rationale totals are retained in JSON. A blocked repeat is included among rejected actions. Probe completion is execution completion, not proof of a correct security hypothesis.','',
        '## Dynamic-control qualification','',
        '| Revision / arm | Computed / accepted controls | Qualified before checks | Qualified after / retained dynamic gates | Accepted constant controls | Generated constant/missing control attempts |',
        '|---|---:|---:|---:|---:|---:|']
    for name,s in summary.items():lines.append(f"| {name} | {s['computed_dynamic_controls']}/{s['accepted_dynamic_gates']} | {s['qualified_dynamic_before']}/{s['accepted_dynamic_gates']} | {s['qualified_dynamic_after']}/{s['retained_dynamic_gates']} | {s['accepted_constant_controls']} | {s['constant_control_attempts']} |")
    lines+=['','A zero denominator means no dynamic-gate opportunity, not a 100% success rate. Computed predicates are checked in the recorded programs; before/after qualification additionally requires source identity, target execution, model-declared sink observations and the same check code. **This syntactic qualification does not independently prove that the actual security sink was exercised.** Invalid generated controls may be attempted but must not authorize edits. The generated-program counter also includes conservative literal False exception branches; it is not a count of accepted false-success assertions.','']
    for ident,note in dynamic_review.items():
        lines += [f"- **{ident} — semantic qualification {note['semantic_qualification']}:** {note['ordinary_control']} {note['boundary_check']} {note['consequence']}"]
    lines+=['',
        '## Wagtail regression `d7d694dafa51f88ef9c1b5f3`','',
        '| Revision / arm | Outcome | Retained edit |','|---|---|---|']
    for r in rows:
        if r['case_key']=='d7d694dafa51f88ef9c1b5f3':lines.append(f"| {r['version']} / {r['arm']} | {outcome(r)} | {r['metrics']['edited']} |")
    for arm,note in review.get('d7d694dafa51f88ef9c1b5f3',{}).items():lines+=['',f'**v8 {arm}:** {note}']
    lines+=['','## All twenty cases: matched outcomes','',
        '| Case / task | v6 C0 | v7 C0 | v8 C0 | v6 C3 | v7 C3 | v8 C3 |','|---|---|---|---|---|---|---|']
    for case in cases:
        found={(r['version'],r['arm']):r for r in rows if r['case_key']==case['case_key']}
        lines.append('| `'+case['case_key']+'` / '+case['instance_id']+' | '+' | '.join(outcome(found[v,a]) for a in ['C0','C3'] for v in ['v6','v7-dev','v8-dev'])+' |')
    lines+=['','## Twelve failed-edit cases: paired outcomes','',
        '| Case | v6 C0 | v7 C0 | v8 C0 | v6 C3 | v7 C3 | v8 C3 |','|---|---|---|---|---|---|---|']
    for key in failed:
        found={(r['version'],r['arm']):r for r in rows if r['case_key']==key}
        lines.append('| `'+key+'` | '+' | '.join(outcome(found[v,a]) for a in ['C0','C3'] for v in ['v6','v7-dev','v8-dev'])+' |')
    for key in failed:
        lines+=['','## Mechanism review: '+key,'']
        for r in [x for x in rows if x['case_key']==key and x['version']=='v8-dev']:
            cell=Path(r['cell']);lines+=['',f"**{r['arm']}: {outcome(r)}**, investigator status `{r['metrics']['status']}`.",'']
            for h in r['localization']['hypotheses']:lines.append('- `'+str(h['path'])+'`: '+str(h['mechanism'])+' Property: '+str(h['security_property']))
            lines+=['','Retained edit locations: '+(', '.join(p+'::'+s for p,s in r['localization']['changed_symbols']) or 'none')+'.']
            lines+=['',review.get(key,{}).get(r['arm'],'Semantic review pending; the recorded hypotheses and edits above are facts, not an inferred successful mechanism match.')]
            streams=[cell/'evaluation/sec/artifacts'/name for name in ['test.stdout','test.stderr']]
            if any(p.exists() for p in streams):
                text=re.sub(r'\x1b\[[0-9;]*m','','\n'.join(p.read_text(errors='replace') for p in streams if p.exists()))
                failures=[line[:350] for line in text.splitlines() if re.match(r'^FAILED |^FAIL: |^ERROR: |^E\s+AssertionError|^AssertionError:',line)]
                if failures:lines+=['','Official security failure excerpt:','','```text',*failures[:5],'```']
    lines+=['','This is development calibration on previously inspected cases. It estimates engineering progress, not held-out effectiveness. No hidden evaluation was fed back into a model or used to reroll a candidate.']
    integrity=data['final_verification']
    if integrity:
        lines+=['',f"Final integrity verification: **{integrity['status']}**; {integrity['actual_cells']} cells, {integrity['official_phases_with_recognized_completion']} terminal-complete official phases, {integrity['protected_overlap']} protected overlap, runner alive: {integrity['runner_alive']}. See `V8_FINAL_VERIFICATION.json` for frozen-file hashes, candidate/evaluation identity, scoped requests and the ledger audit."]
    (root/'report/V8_DEV_COMPARISON.md').write_text('\n'.join(lines)+'\n')
    return data


if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True)
    report(p.parse_args().root)
