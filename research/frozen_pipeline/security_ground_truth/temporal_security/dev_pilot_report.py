"""Evaluator-only paired v6/v7 development report. Never supplied to models."""
import collections
import hashlib
import json
from pathlib import Path
import sqlite3
from security_ground_truth.runtime.common import write_json,utcnow,sha256
from security_ground_truth.repair_check.official_score import load_authors_classes,score_raw,archived_runs,completion_checked_run
from .postmortem_v6 import probe_category,patch_ranges,reference_symbols
from .citations import symbols
from .unseeded_gate import control_program_qualified


def read(path,default=None):return json.loads(path.read_text()) if path.exists() else default


def score_cell(cell,case,namespace,*,allow_archived_noop=False):
    r=read(cell/'result.json',{})
    if not r:return None
    task=read(Path(case['case_path'])/'task.json');spec=read(Path(case['case_path'])/'logs_handler.json')
    if allow_archived_noop and not r.get('patch_bytes') and not (cell/'evaluation/func/artifacts/result.json').exists():
        runs=archived_runs(Path(case['case_path']))
    else:
        runs={}
        for phase in ['func','sec']:
            p=cell/'evaluation'/phase/'artifacts';raw=read(p/'result.json')
            if not raw or not (p/'test.stdout').exists():runs[phase]={'execution_error':'missing_evaluation'};continue
            runs[phase]=completion_checked_run(raw,(p/'test.stdout').read_text(errors='replace'),
                (p/'test.stderr').read_text(errors='replace') if (p/'test.stderr').exists() else '')
    score=score_raw(task,spec,runs,namespace)
    return {'score':score,'terminal_completed':{phase:bool(runs[phase].get('terminal_result',{}).get('recognized')) for phase in ['func','sec']}}


def metrics(cell):
    result=read(cell/'result.json',{});trajectory=read(cell/'trajectory.json',[])
    errors=collections.Counter();repeated=0;last={};gate_events=0
    exposed_hashes=collections.defaultdict(set);hypothesis_paths={};hash_roots=collections.Counter();pending_errors={};loops=0
    for turn in trajectory:
        answer=turn.get('answer',{}) if isinstance(turn,dict) else {}
        raw_actions=answer.get('actions') if isinstance(answer,dict) else None
        observations=turn.get('observations',[]) if isinstance(turn,dict) else []
        observations=observations if isinstance(observations,list) else []
        if not isinstance(raw_actions,list) or not 1<=len(raw_actions)<=3:
            error=next((obs.get('error') for obs in observations
                        if isinstance(obs,dict) and obs.get('error')), 'Expected 1..3 actions')
            errors[error]+=1
            continue
        for raw_action,raw_observation in zip(raw_actions,observations):
            action=raw_action if isinstance(raw_action,dict) else {}
            obs=raw_observation if isinstance(raw_observation,dict) else {}
            if obs.get('hypothesis_id') and obs.get('path'):hypothesis_paths[obs['hypothesis_id']]=obs['path']
            path=action.get('path') or hypothesis_paths.get(action.get('hypothesis_id')) or (obs.get('recovery') or {}).get('path')
            if obs.get('source_sha256'):exposed_hashes[path].add(obs['source_sha256'])
            if obs.get('status')!='invalid_action':
                pending_errors.clear();continue
            err=obs.get('error','');errors[err]+=1
            key=(action.get('action'),action.get('path'),action.get('hypothesis_id'),action.get('alert_id'))
            repeated+=last.get(key)==err;last[key]=err
            loops+=pending_errors.get(key)==err;pending_errors[key]=err
            if err.startswith('Stale citation source hash'):
                supplied=action.get('evidence_source_sha256')
                category=('previously_exposed_same_file_hash' if supplied in exposed_hashes[path] else
                          'previously_exposed_other_file_hash' if any(supplied in hashes for hashes in exposed_hashes.values()) else
                          'not_a_previously_exposed_read_hash')
                hash_roots[category]+=1
            recovered=(obs.get('recovery') or {}).get('source_sha256')
            if recovered:exposed_hashes[path].add(recovered)
            gate_events+=err.startswith('Unseeded edit gate:')
    citation=lambda e:any(x in e.lower() for x in ['citation','cite lines','exact quote from the current target','current read'])
    counts=collections.Counter();kinds=collections.Counter();exception_messages=collections.Counter()
    for p in (cell/'checks').glob('*/feedback.json'):
        f=read(p);counts['total']+=1;counts[f.get('status','missing')]+=1
        if f.get('target_reached'):counts['target_reached']+=1
        if f.get('status')=='check_exception':
            kinds[probe_category(f)]+=1
            text=f.get('traceback','');lastline=text.splitlines()[-1] if text else f.get('exception_type','unknown')
            exception_messages[lastline]+=1
            if any(term in lastline for term in ['ImproperlyConfigured','AppRegistryNotReady','INSTALLED_APPS','settings are not configured']):
                counts['django_environment_exceptions']+=1
    return {'status':result.get('status'),'model_calls':result.get('model_calls',0),'edited':bool(result.get('patch_bytes')),
        'rejected':sum(errors.values()),'citation_rejections':sum(n for e,n in errors.items() if citation(e)),
        'old_current_read_error':sum(n for e,n in errors.items() if e.startswith('Cite lines from a read of the CURRENT file')),
        'explicit_stale_citations':sum(n for e,n in errors.items() if 'stale' in e.lower()),
        'repeated_same_error':repeated,'unseeded_gate_rejections':gate_events,'errors':dict(errors),
        'same_error_repeated_without_intervening_success':loops,'hash_mismatch_roots':dict(hash_roots),
        'probes':dict(counts),'probe_exception_categories':dict(kinds),'probe_exception_messages':dict(exception_messages),
        'gate_final_rejections':result.get('unseeded_final_gate_failures',[])}


def localization(cell,case):
    task=read(Path(case['case_path'])/'task.json');reference=reference_symbols(task['security_patch'])
    patch=cell/'candidate.patch';changed=[]
    for path,lines in patch_ranges(patch.read_text() if patch.exists() else '').items():
        source=Path(case['baseline'])/'source'/path
        if not source.exists():continue
        scopes=symbols(source.read_text(errors='replace'))
        for line in lines:
            found=[s for s in scopes if s['start_line']<=line<=s['end_line']]
            symbol=min(found,key=lambda s:s['end_line']-s['start_line'])['symbol'] if found else '<module>'
            if (path,symbol) not in changed:changed.append((path,symbol))
    matches=[(p,s) for p,s in changed if s.split('.')[-1] in reference.get(p,[])]
    hypotheses=read(cell/'hypotheses.json',{})
    return {'changed_symbols':changed,'reference_symbol_matches':matches,'reference_symbols':reference,
        'reference_cwe_ids':task.get('cwe_ids',[]),
        'hypotheses':[{k:h.get(k) for k in ['hypothesis_id','path','mechanism','security_property','scanner_linked_ids']} for h in hypotheses.values()],
        'interpretation':'Reference symbol overlap is localization evidence, not proof of matching vulnerability mechanism.'}


def audit_dynamic_controls(rows):
    checked=[]
    for row in rows:
        if row['version']!='v7-dev':continue
        cell=Path(row['cell']);repair=read(cell/'result.json',{});hypotheses=read(cell/'hypotheses.json',{})
        for ident,gate in repair.get('unseeded_repair_gates',{}).items():
            if gate['mode']!='dynamic_control':continue
            matches=[p for p in cell.glob('checks/*/input/check.py') if hashlib.sha256(p.read_bytes()).hexdigest()==gate['before_check_code_sha256']]
            valid=bool(matches) and control_program_qualified(matches[0].read_text())
            checked.append({'case_key':row['case_key'],'arm':row['arm'],'hypothesis_id':ident,
                'computed_ordinary_control':valid,'retained_candidate_changes_target':hypotheses.get(ident,{}).get('path') in repair.get('changed_paths',[]),
                'check_paths':[str(p) for p in matches],
                'reason':None if valid else 'Constant or missing ordinary-control predicate; the declared True observation is insufficient.'})
    failures=[x for x in checked if not x['computed_ordinary_control']]
    return {'status':'failed' if failures else 'no_constant_control_failure_detected',
        'dynamic_gates_checked':len(checked),'failures':failures,'all_checks':checked,
        'limitation':'A computed predicate alone still does not prove that a mock/intermediate value represents the actual security boundary.'}


def report(root):
    root=Path(root);manifest=read(root/'manifest.json');parent=Path(manifest['parent'])/'experiment'
    cases=read(root/'cases.json');ns=load_authors_classes(root/'upstream_logs.py');rows=[]
    for case in cases:
        for version,base in [('v6',parent),('v7-dev',root)]:
            for arm in ['C0','C3']:
                cell=base/'cells'/case['case_key']/arm
                rows.append({'case_key':case['case_key'],'instance_id':case['instance_id'],'generator':case['model_name'],
                    'version':version,'arm':arm,'metrics':metrics(cell),'evaluation':score_cell(cell,case,ns,allow_archived_noop=version=='v6'),
                    'localization':localization(cell,case),'cell':str(cell)})
    summary={}
    for version in ['v6','v7-dev']:
        for arm in ['C0','C3']:
            selected=[r for r in rows if r['version']==version and r['arm']==arm]
            m=[r['metrics'] for r in selected];n=len(selected);p=collections.Counter();e=collections.Counter()
            for x in m:p.update(x['probes']);e.update(x['probe_exception_categories'])
            summary[version+':'+arm]={'cells':n,'finished_repairs':sum(bool(x['status']) for x in m),
                'rejected_total':sum(x['rejected'] for x in m),'rejected_per_cell':sum(x['rejected'] for x in m)/n,
                'citation_rejections':sum(x['citation_rejections'] for x in m),
                'old_current_read_error':sum(x['old_current_read_error'] for x in m),
                'explicit_stale_citations':sum(x['explicit_stale_citations'] for x in m),
                'repeated_same_error':sum(x['repeated_same_error'] for x in m),
                'same_error_repeated_without_intervening_success':sum(x['same_error_repeated_without_intervening_success'] for x in m),
                'unseeded_gate_rejections':sum(x['unseeded_gate_rejections'] for x in m),
                'turn_limits':sum(x['status']=='turn_limit' for x in m),'edited':sum(x['edited'] for x in m),
                'repair_errors':sum(x['status']=='repair_error' for x in m),'probes':dict(p),'probe_exceptions':dict(e),
                'completed_evaluations':sum(bool(r['evaluation']) and all(r['evaluation']['terminal_completed'].values()) for r in selected),
                'func_pass':sum(bool(r['evaluation']) and r['evaluation']['terminal_completed']['func'] and r['evaluation']['score']['func_pass'] for r in selected),
                'sec_pass':sum(bool(r['evaluation']) and all(r['evaluation']['terminal_completed'].values()) and r['evaluation']['score']['sec_pass'] for r in selected)}
    config=read(root/'config.json');scope=config['budget_scope']['id'];ledger=Path(manifest['ledger_root'])/'budget.sqlite'
    with sqlite3.connect('file:'+str(ledger)+'?mode=ro',uri=True) as db:
        costs=db.execute("SELECT micro_usd,status,details FROM requests WHERE json_extract(details,'$.budget_scope')=?",(scope,)).fetchall()
    known=[];unknown=[]
    for micro,status,raw in costs:
        details=json.loads(raw);cost=(details.get('usage') or {}).get('cost')
        if isinstance(cost,(int,float)):known.append(cost)
        else:unknown.append({'micro_usd':micro,'status':status})
    budget={'accounted_usd':sum(x[0] for x in costs)/1e6,'provider_reported_usd':sum(known),
        'requests':len(costs),'unknown_billing_requests':len(unknown),'unknown_reservations_usd':sum(x['micro_usd'] for x in unknown)/1e6,
        'incremental_hard_cap_usd':20,'baseline_accounted_usd':config['budget_scope']['initial_total_micro_usd']/1e6}
    plan=read(root/'report_inputs/DEV_CALIBRATION.json')
    failed_keys=[k for k,reasons in plan['selection_reasons'].items() if any(x in reasons for x in ['seeded_failed_edit','unseeded_failed_edit'])]
    manual_path=root/'report/EVALUATOR_ONLY_MECHANISMS.json'
    data={'generated_utc':utcnow(),'status':read(root/'status.json',{}).get('status'),'summary':summary,'budget':budget,
        'reporter_sha256':sha256(Path(__file__)),
        'manual_mechanism_review':read(manual_path,{}),
        'manual_review_sha256':sha256(manual_path) if manual_path.exists() else None,
        'interrupted_recoveries':[read(p) for p in sorted(root.glob('cells/*/*/recovery.json'))],
        'dynamic_control_qualification':audit_dynamic_controls(rows),
        'rows':rows,'failed_edit_case_keys':failed_keys,'protected_cases_used':0,
        'notes':['Development calibration only; no unexposed evaluation or full-cohort launch.',
            'v6 and v7 scores use the same completion gate and official failure allowances.',
            'All v7 candidates including no-ops receive fresh final functional/security evaluations.',
            'Reference fixes and hidden test outputs appear only in this offline report.']}
    write_json(root/'report/V7_DEV_COMPARISON.json',data)
    qualification=data['dynamic_control_qualification']
    baseline_secure=sum(c['official_baseline_score']['sec_pass'] for c in cases)
    generators=collections.Counter(c['model_name'] for c in cases)
    lines=['# v6 versus v7 development calibration','',f"Status: **{data['status']}**. Exactly 20 development cases, C0/C3 only. No bulk release.",'',
        f"The 20 attempts span {len({c['instance_id'] for c in cases})} development tasks. Original FuncPass is 20/20 and original SecPass is {baseline_secure}/20. Archived generators: {dict(generators)}. The investigator is the same DeepSeek V3.2 / siliconflow/fp8 endpoint in both revisions, with a 22-turn limit. C0 uses current code, SAST and conditional PoC; C3 adds symbol evolution and recorded rationale. Both v7 arms use the identical scanner-negative gate.", '',
        f"**Dynamic-control qualification: {qualification['status']}.** "
        f"{len(qualification['failures'])}/{qualification['dynamic_gates_checked']} accepted dynamic gates lack a computed ordinary-input control. "
        'The scores below remain the actual official outcomes of the frozen candidates; no candidate was changed or rerolled after inspecting hidden results. '
        'Do not claim that this pilot established enforcement of genuine ordinary-input/sink controls.', '',
        '| Version / arm | Rejected/cell | Citation errors | Repeated errors | Turn limit | Probes completed | Non-scalar exceptions | Django exceptions | Complete eval | FuncPass | SecPass |',
        '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    for name,s in summary.items():
        p=s['probes'];e=s['probe_exceptions'];django=p.get('django_environment_exceptions',0)
        lines.append(f"| {name} | {s['rejected_per_cell']:.2f} | {s['citation_rejections']} | {s['repeated_same_error']} | {s['turn_limits']}/20 | {p.get('completed',0)}/{p.get('total',0)} | {e.get('observation_serializer_rejected_non_scalar',0)} | {django} | {s['completed_evaluations']}/20 | {s['func_pass']}/20 | {s['sec_pass']}/20 |")
    lines+=['','A missing/incomplete evaluation is not a verified insecure label. Nonpass totals retain the fixed 20-case denominator; completion is reported separately. Repeated errors count repeat messages for the same action/target, not only immediately consecutive turns. Gate rejections are intentional evidence controls and are also included in total rejections.', '',
        f"Spend: **${budget['provider_reported_usd']:.6f} provider reported**; **${budget['accounted_usd']:.6f} accounted** including safety margin and unknown reservations. {budget['unknown_billing_requests']} requests lack reported cost (${budget['unknown_reservations_usd']:.6f} reserved). Hard incremental cap: $20.",'',
        '## Wagtail regression','', '| Version / arm | Changed | Completed func/sec | FuncPass | SecPass |','|---|---|---|---|---|']
    def outcome(r):
        ev=r['evaluation']
        return 'missing' if not ev else ('incomplete' if not all(ev['terminal_completed'].values()) else ('F'+str(int(ev['score']['func_pass']))+'/S'+str(int(ev['score']['sec_pass']))))
    for r in rows:
        if r['case_key']!='d7d694dafa51f88ef9c1b5f3':continue
        ev=r['evaluation'] or {};score=ev.get('score',{})
        lines.append(f"| {r['version']} {r['arm']} | {r['metrics']['edited']} | {ev.get('terminal_completed')} | {score.get('func_pass')} | {score.get('sec_pass')} |")
    lines+=['','## Twelve previously failed C3 edits','',
        'F/S are completion-checked official functional/security outcomes. Symbol matches are a localization proxy; the JSON preserves mechanisms and reference CWE metadata for semantic review. No-op abstention is not a repair.', '',
        '| Case | Selection | v6 C0 | v7 C0 | v6 C3 | v7 C3 | v7 C0/C3 reference-symbol overlap |','|---|---|---|---|---|---|---|']
    for key in failed_keys:
        found={(r['version'],r['arm']):r for r in rows if r['case_key']==key}
        values=[outcome(found[(v,a)]) for v,a in [('v6','C0'),('v7-dev','C0'),('v6','C3'),('v7-dev','C3')]]
        overlap=[bool(found[('v7-dev',a)]['localization']['reference_symbol_matches']) for a in ['C0','C3']]
        selection='seeded failed edit' if 'seeded_failed_edit' in plan['selection_reasons'][key] else 'unseeded failed edit'
        lines.append('| `'+key+'` | '+selection+' | '+' | '.join(values)+' | '+str(overlap)+' |')
    lines+=['','## Rates and enforced evidence gates','',
        '| Version / arm | Turn-limit rate | Probe completion | Non-scalar exception rate | Django exception rate | Unseeded-gate rejections |',
        '|---|---:|---:|---:|---:|---:|']
    for name,s in summary.items():
        p=s['probes'];e=s['probe_exceptions'];n=p.get('total',0)
        percent=lambda x:f'{100*x/n:.1f}%' if n else 'n/a'
        lines.append(f"| {name} | {100*s['turn_limits']/20:.1f}% | {percent(p.get('completed',0))} | "
            f"{percent(e.get('observation_serializer_rejected_non_scalar',0))} | "
            f"{percent(p.get('django_environment_exceptions',0))} | {s['unseeded_gate_rejections']} |")
    lines+=['','Django rates include missing settings, app-registry failures, ImproperlyConfigured and missing INSTALLED_APPS/app-label configuration. Exact final exception messages are retained per cell; serialization/configuration improvements must not conceal replacement fixture or API errors.']
    lines+=['','## Dynamic-control qualification failures','',
        '| Case / arm | Hypothesis | Retained candidate changes target | Failure |','|---|---|---|---|']
    for f in qualification['failures']:
        lines.append(f"| `{f['case_key']}` {f['arm']} | {f['hypothesis_id']} | {f['retained_candidate_changes_target']} | {f['reason']} |")
    lines+=['','## Citation and repeated-error audit','',
        'The 2,589 source-range errors refer to the earlier full v6 cohort. The matched 20-case subset has 134 occurrences of that exact old current-read error (73 C0, 61 C3). All 134 disappear in v7, but citation errors and repeated failures are not eliminated.', '',
        '| Version / arm | Old current-read error | Explicit hash mismatch | Repeated error before intervening success |',
        '|---|---:|---:|---:|']
    for name,s in summary.items():
        lines.append(f"| {name} | {s['old_current_read_error']} | {s['explicit_stale_citations']} | {s['same_error_repeated_without_intervening_success']} |")
    lines+=['','Rejected actions for each selected case:', '',
        '| Case | C0 v6 | C0 v7 | C3 v6 | C3 v7 |','|---|---:|---:|---:|---:|']
    for case in cases:
        key=case['case_key'];found={(r['version'],r['arm']):r for r in rows if r['case_key']==key}
        values=[str(found[(v,a)]['metrics']['rejected']) for v,a in [('v6','C0'),('v7-dev','C0'),('v6','C3'),('v7-dev','C3')]]
        lines.append('| `'+key+'` | '+' | '.join(values)+' |')
    roots=collections.Counter()
    for row in rows:
        if row['version']=='v7-dev':roots.update(row['metrics']['hash_mismatch_roots'])
    lines+=['',f'v7 hash-mismatch provenance: `{dict(roots)}`. Hashes from another file are not stale versions of the cited file. The recovery interface still permits this binding mistake.', '',
        'New evidence gates also create friction: 32 static-chain rejections omit the required source anchors. Mechanize C3 repeats the same generated-check syntax error 12 times. These are engineering failures to fix before another qualification; lowering the evidence requirement is not a remedy.', '',
        '## Mechanism review of the 12 failed-edit cases','',
        'This review uses the published reference patch and final candidate only after evaluation. It is never investigator input. Matching a function name alone does not establish that the correct vulnerability was repaired.', '',
        '| Case | Required mechanism | v7 C0 | v7 C3 |','|---|---|---|---|']
    manual=data['manual_mechanism_review']
    for key in failed_keys:
        reviews=manual.get('v7_review',{}).get(key,{})
        lines.append('| `'+key+'` | '+manual.get('expected_mechanisms',{}).get(key,'Not reviewed')+' | '+reviews.get('C0','Not reviewed')+' | '+reviews.get('C3','Not reviewed')+' |')
    lines+=['','## Interrupted provider request','']
    for recovery in data['interrupted_recoveries']:
        lines.append(f"`{recovery['case_key']}` {recovery['arm']}: the original request returned no response for over 20 minutes. The runner was stopped after the other 39 final evaluations. The unchanged frozen engine replayed its four already-recorded read-only turns exactly, then finalized a `repair_error` with the original empty patch. No new model call or paid continuation occurred. The final no-op candidate received fresh official functional/security evaluations. The unknown request retains its full reservation. This cell is an interrupted investigation, not a successful protocol completion.")
    lines+=['','## Release decision','',
        'Keep the full cohort stopped. This development pilot improves execution in several respects and prevents the observed Wagtail double-escaping regression, but does not establish better vulnerability repair or a history advantage. The dynamic-control gate failed qualification. Local post-pilot hardening rejects constant ordinary-control assertions; it was not applied to these frozen candidates and has not been paid-retested. A computed predicate still needs a faithful ordinary input and an actual sink, not a mock declaring success.', '',
        'Wagtail C0 retained the original code. C3 refuted the proposed XSS using downstream rendering but then retained an ancestor-label caching change under a separate performance/DoS claim. Both pass the official tests; this does not establish that speculative scanner-negative changes are eliminated.', '',
        'All 12 selected previously failed-edit cases retain FuncPass and fail SecPass in both v7 arms (0/12 verified security repairs per arm). Nmap C0 finds the relevant argument-validation mechanism but misses leading-dash targets; Streamlit C0 reaches the error-response sink but still fails the official response contract. Most others edit the wrong mechanism or retain no edit. The +1 C3 SecPass versus v6 is preservation of Wagtail, not a newly repaired insecure case.', '',
        'Before dispatch, 134 local tests passed. Post-pilot hardening and a missing-no-op-evaluation reporting regression test bring the local total to 137 passing tests. The original gate tests verified observation values but did not reject a generated program that simply asserted a constant control result; the new test covers that gap. The transport also needs an absolute request deadline: a socket inactivity timeout did not bound the stalled request.', '',
        'Final verification is recorded in `FINAL_VERIFICATION.json`: 40 selected cells, 80 recognized terminal evaluations, no protected overlap, no new unscoped requests, unchanged v6/v7 frozen manifests, stopped dispatcher and spending below the incremental cap. Neither a 302-case nor a 391-case run was launched.', '',
        'Full per-cell rejection strings, probe categories, target mechanisms, edited symbols, completion evidence and artifact paths: `V7_DEV_COMPARISON.json`.']
    (root/'report/V7_DEV_COMPARISON.md').write_text('\n'.join(lines)+'\n')
    print(json.dumps({'report':str(root/'report/V7_DEV_COMPARISON.md'),'summary':summary,'budget':budget}),flush=True)
    return data
