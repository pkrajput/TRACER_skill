"""Read-only scientific reporting; no results are returned to the investigator."""
from collections import Counter
import json
from pathlib import Path
import sqlite3
from security_ground_truth.runtime.common import utcnow, write_json
from .v11_dev_report import detail,failure_excerpt
from .prepare_v12 import LEDGER


def read(path,default=None):return json.loads(path.read_text()) if path.exists() else default


def spend(root):
    with sqlite3.connect('file:'+str(LEDGER)+'?mode=ro',uri=True) as db:
        costs=db.execute("SELECT micro_usd,details FROM requests WHERE json_extract(details,'$.budget_scope') IN (?,?)",
                         (root.name+':gate',root.name+':full')).fetchall()
        total=db.execute('SELECT SUM(micro_usd) FROM requests').fetchone()[0]
    provider=[];unknown=0;stages={}
    for micro,raw in costs:
        details=json.loads(raw);value=(details.get('usage') or {}).get('cost')
        stage=details.get('budget_scope','').rsplit(':',1)[-1]
        summary=stages.setdefault(stage,{'accounted_usd':0,'provider_reported_usd':0,'requests':0})
        summary['accounted_usd']+=micro/1e6;summary['requests']+=1
        if isinstance(value,(int,float)):summary['provider_reported_usd']+=value
        if isinstance(value,(int,float)):provider.append(value)
        else:unknown+=1
    return {'requests':len(costs),'provider_reported_usd':sum(provider),
            'accounted_incremental_usd':sum(m for m,_ in costs)/1e6,
            'unknown_billing_requests':unknown,'study_accounted_usd':total/1e6,'study_ceiling_usd':699,'stages':stages}


def summarize(rows,cases):
    lookup={c['case_key']:c for c in cases}
    summary={}
    for arm in ('C0','C1','C2','C3'):
        selected=[r for r in rows if r['arm']==arm]
        complete=[r for r in selected if r['terminal_phases']==2]
        summary[arm]={'completed_cells':len(selected),'terminal_complete_cells':len(complete),
            'func_pass':sum(r['func_pass'] for r in complete),'sec_pass':sum(r['sec_pass'] for r in complete),
            'original_func_pass_on_same_cases':sum(lookup[r['case_key']]['official_baseline_score']['func_pass'] for r in complete),
            'original_sec_pass_on_same_cases':sum(lookup[r['case_key']]['official_baseline_score']['sec_pass'] for r in complete),
            'repair_statuses':dict(Counter(r['repair_status'] for r in selected))}
    return summary


def publish(root,cases,rows,state,gate):
    root=Path(root);dest=root/'report';dest.mkdir(exist_ok=True)
    keys=set(read(root/'pilot_keys.json',[]));pilot=[r for r in rows if r['case_key'] in keys and r['arm'] in ('C0','C3')]
    budget=spend(root);summary=summarize(rows,cases)
    matched={c['case_key'] for c in cases if all(any(r['case_key']==c['case_key'] and r['arm']==a
            and r['terminal_phases']==2 for r in rows) for a in ('C0','C1','C2','C3'))}
    data={'utc':utcnow(),'status':state,'gate':gate,'expected_cases':len(cases),'expected_cells':4*len(cases),
        'original_cohort_cases':391,'source_only_exclusions':read(root/'input_qualification.json',{}).get('exclusions',[]),
        'completed_cells':len(rows),'terminal_phases':sum(r['terminal_phases'] for r in rows),
        'summary':summary,'fully_matched_case_count':len(matched),
        'fully_matched_summary':summarize([r for r in rows if r['case_key'] in matched],cases),
        'by_generator':{str(g):summarize([r for r in rows if r['generator']==g],cases)
                        for g in sorted({r['generator'] for r in rows},key=str)},
        'by_stratum':{s:summarize([r for r in rows if r['stratum']==s],cases)
                      for s in ('development_exposed','previously_protected')},
        'budget':budget,'rows':rows,
        'interpretation':'Official terminal-complete functional/security counts; partial arms have different denominators. Use fully_matched_summary for paired comparisons. Development-exposed and previously protected tasks remain separate.'}
    write_json(dest/'RESULTS.json',data)
    lines=['# v12 campaign status','',f'Status: **{state}**. Updated {data["utc"]}.',
        f'{len(rows)}/{4*len(cases)} cells evaluated; {data["terminal_phases"]}/{8*len(cases)} official phases terminal-complete.',
        f'Original cohort: 391 cases. Admitted: {len(cases)}. Source-only exclusions: {391-len(cases)} (listed in RESULTS.json).',
        f'Full auto-release gate: {gate["passed"] if gate else "pending"}. Fully matched four-arm cases: {len(matched)}.','',
        '| Arm | Terminal-complete cells | Original SecPass (same cases) | FuncPass | SecPass | Repair errors |',
        '|---|---:|---:|---:|---:|---:|']
    for a,s in summary.items():lines.append(f'| {a} | {s["terminal_complete_cells"]} | {s["original_sec_pass_on_same_cases"]} | {s["func_pass"]} | {s["sec_pass"]} | {s["repair_statuses"].get("repair_error",0)} |')
    lines+=['',f'Provider-reported ${budget["provider_reported_usd"]:.6f}; accounted campaign ${budget["accounted_incremental_usd"]:.6f}; total study ${budget["study_accounted_usd"]:.6f} / $699.',
        '', 'C0: common current snapshot/SAST. C1: temporal history and completeness cues. C2: recorded rationale and completeness cues. C3: combined evidence, divergence links and cues. All share the runtime gates and context policy.',
        '', 'All candidates, including no-ops, receive fresh official functional/security evaluations. The twenty qualification cells are reused in place by exact artifact hashes. No SAST judgment is used as a ground-truth label.',
        '', 'The release decision is development-selected. Report the previously protected stratum separately; do not treat development calibration or a result-conditioned release as an unbiased held-out estimate.']
    (dest/'DIAGNOSTIC_REPORT.md').write_text('\n'.join(lines)+'\n')
    previous=read(root/'report_inputs/V11_DEV_COMPARISON.json',{})
    comparison=['# v12 ten-case development qualification','',f'Status: **{state}**; gate: **{gate["passed"] if gate else "pending"}**.',
        '', '| Revision | Arm | FuncPass | SecPass | Terminal phases | Rejections / action events | Turn limits | Repair errors |',
        '|---|---|---:|---:|---:|---:|---:|---:|']
    for name,s in previous.get('summary',{}).items():
        v,a=name.split(':');comparison.append(f'| {v} | {a} | {s["func_pass"]}/10 | {s["sec_pass"]}/10 | {s["terminal_phases"]}/20 | {s["rejected"]}/{s["action_observations"]} | {s["turn_limits"]} | {s["repair_errors"]} |')
    details={}
    for r in pilot:details[(r['case_key'],r['arm'])]=detail(Path(r['cell']))
    for a in ('C0','C3'):
        selected=[r for r in pilot if r['arm']==a];ms=[details[(r['case_key'],a)] for r in selected]
        comparison.append(f'| v12-dev | {a} | {sum(r["func_pass"] for r in selected)}/10 | {sum(r["sec_pass"] for r in selected)}/10 | {sum(r["terminal_phases"] for r in selected)}/20 | {sum(m["rejected"] for m in ms)}/{sum(m["action_observations"] for m in ms)} | {sum(r["repair_status"]=="turn_limit" for r in selected)} | {sum(r["repair_status"]=="repair_error" for r in selected)} |')
    comparison+=['', '## Explicit release criteria', '',json.dumps(gate,indent=2) if gate else 'Pending all twenty cells and forty evaluations.',
        '',f'Qualification cost: {json.dumps(budget["stages"].get("gate",{}))}. Qualification is capped at $6 incremental; the full study is capped at $699.',
        '', '## Qualification cells', '', '| Case / arm | FuncPass | SecPass | Status | Patch bytes | Turns |', '|---|---:|---:|---|---:|---:|']
    for r in sorted(pilot,key=lambda r:(r['case_key'],r['arm'])):
        comparison.append(f'| {r["case_key"]} / {r["arm"]} | {r["func_pass"]} | {r["sec_pass"]} | {r["repair_status"]} | {r["patch_bytes"]} | {r["turns"]} |')
        if r['error']:comparison.append(f'\nError: {r["error"]}\n')
    comparison+=['','## Recorded mechanisms and execution','',
        'Hypotheses below are investigator claims. Verified security outcomes are the official SecPass values above.','']
    mechanisms=[]
    for r in sorted(pilot,key=lambda r:(r['case_key'],r['arm'])):
        cell=Path(r['cell']);hypotheses=read(cell/'hypotheses.json',{})
        assessments=read(cell/'assessments.json',[]);trace=read(cell/'trajectory.json',[])
        m=details[(r['case_key'],r['arm'])]
        observed=[{'id':i,'path':h.get('path'),'target':h.get('target_symbol'),
                   'property':h.get('security_property'),'mechanism':h.get('mechanism'),
                   'assessments':[a.get('decision') for a in assessments if a.get('hypothesis_id')==i]}
                  for i,h in hypotheses.items()]
        failures=failure_excerpt(cell);packed=[t['context_packing'] for t in trace if t.get('context_packing')]
        mechanisms.append({'case_key':r['case_key'],'arm':r['arm'],'hypotheses':observed,
            'security_failure_excerpt':failures,'context_packing':packed})
        comparison.extend([f'### {r["case_key"]} / {r["arm"]}','',
            f'Accepted edits: {m["accepted_edit_actions"]}; qualified protocol probes: {m["qualified_protocol_probes"]}; '
            f'rejected actions: {m["rejected"]}/{m["action_observations"]}; '
            f'final coverage warnings: {len(m["final_coverage_warnings"])}.',
            f'Repair routes: {json.dumps(m["repair_routes"])}.'])
        for h in observed:
            target=h['target'] or {};symbol=target.get('symbol','<unknown>') if isinstance(target,dict) else str(target)
            comparison.append(f'- {h["id"]}: `{h["path"]}:{symbol}` — {h["property"]}. Assessments: {", ".join(h["assessments"]) or "unassessed"}.')
        if packed:comparison.append(f'Largest packed exchange: {max(p["serialized_bytes"] for p in packed):,} bytes; ceiling {packed[0]["ceiling_bytes"]:,}.')
        if failures:comparison.extend(['','Official security failure excerpt:','```text',*failures[:12],'```'])
        comparison.append('')
    comparison+=['', 'Full trajectories, source-bound assessments, patches and fresh official logs are preserved under cells/<case>/<arm>. Evaluation feedback is never fed back to the investigator.']
    (dest/'V12_DEV_COMPARISON.md').write_text('\n'.join(comparison)+'\n')
    write_json(dest/'V12_DEV_COMPARISON.json',{'utc':utcnow(),'status':state,'gate':gate,
        'rows':pilot,'metrics':{k+':'+a:v for (k,a),v in details.items()},'mechanisms':mechanisms,'budget':budget})
    return data
