"""Summarize all frozen cells without selecting on outcome."""
import argparse
import csv
import difflib
import json
from pathlib import Path

BASE=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--results',type=Path,required=True,
                    help='rq5_independent_biology_final directory from the complete Zenodo artifact')
parser.add_argument('--out',type=Path,default=BASE/'local-output/rq5')
args=parser.parse_args()
ROOT=args.results
OUT=args.out
OUT.mkdir(parents=True,exist_ok=True)
manifest=json.loads((ROOT/'manifest.json').read_text())
results=json.loads((ROOT/'RESULTS.json').read_text())
cases={c['id']:c for c in manifest['cases']}
rows=results['records'];assert len(rows)==40 and not results['errors']
assert len({(r['case_id'],r['condition']) for r in rows})==40

audit={'all_cells_retained':True,'equal_first_inputs_within_memory_level':True,
       'no_security_feedback_in_B0_B1':True,'at_most_one_retry':True,'full_gate_never_accepts_failed_check':True}
for cid in cases:
    for left,right in [('B0','B2'),('B1','B3')]:
        a=json.loads((ROOT/'continuations'/cid/left/'1/input.json').read_text())
        b=json.loads((ROOT/'continuations'/cid/right/'1/input.json').read_text())
        assert a==b,(cid,left,right,'first inputs differ')
for r in rows:
    assert 1<=len(r['turns'])<=2
    for t in r['turns']:
        inp=json.loads((ROOT/'continuations'/r['case_id']/r['condition']/str(t['turn'])/'input.json').read_text())
        if r['condition'] in ('B0','B1'):
            assert set(inp.get('gate_failure_feedback',{}))<= {'application','functional','feature'}
    if r['condition'] in ('B2','B3') and r['accepted']:assert r['turns'][-1]['JointPass']
(OUT/'protocol_audit.json').write_text(json.dumps(audit,indent=2)+'\n')

def counts(selected,index):
    turns=[r['turns'][index] for r in selected]
    return {
        'N':len(turns),'FuncPass':sum(t['FuncPass']=='pass' for t in turns),
        'SecPass':sum(t['SecPass']=='pass' for t in turns),'JointPass':sum(t['JointPass'] for t in turns),
        'security_violations':sum(t['SecPass']=='fail' for t in turns),
        'security_unknown':sum(t['SecPass']=='unknown' for t in turns),
        'saved_boundary_pass':sum(t.get('saved_boundary',{}).get('status')=='pass' for t in turns),
        'saved_boundary_fail':sum(t.get('saved_boundary',{}).get('status')=='fail' for t in turns),
        'extended_boundary_pass':sum(t.get('extended_boundary',{}).get('status')=='pass' for t in turns),
    }

summary={'status':results['status'],'tasks':10,'repository_clusters':5,'model':manifest['model'],'arms':{},'by_repository':{},'ledger':results['ledger']}
for arm in ('B0','B1','B2','B3'):
    selected=[r for r in rows if r['condition']==arm]
    summary['arms'][arm]={'first':counts(selected,0),'final':counts(selected,-1),
        'retries':sum(len(r['turns'])==2 for r in selected),'fallbacks':sum(r['fallback'] for r in selected),
        'accepted_with_boundary_failure':sum(r['accepted'] and r['turns'][-1]['SecPass']=='fail' for r in selected),
        'any_observed_violation':sum(any(t['SecPass']=='fail' for t in r['turns']) for r in selected)}
for cid in sorted({c['base_id'] for c in cases.values()}):
    summary['by_repository'][cid]={arm:counts([r for r in rows if r['base_id']==cid and r['condition']==arm],-1) for arm in ('B0','B1','B2','B3')}
security_ids={'rfdiffusion_checkpoint','haddock_extract_symlink','proteinmpnn_record_name'}
summary['security_components_only']={arm:{'first':counts([r for r in rows if r['base_id'] in security_ids and r['condition']==arm],0),
    'final':counts([r for r in rows if r['base_id'] in security_ids and r['condition']==arm],-1)} for arm in ('B0','B1','B2','B3')}
(OUT/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
with (OUT/'all_outcomes.csv').open('w',newline='') as f:
    fields=['case_id','arm','stage','attempt','FuncPass','SecPass','JointPass','saved_boundary','extended_boundary','accepted','fallback']
    w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
    for r in sorted(rows,key=lambda x:(x['case_id'],x['condition'])):
        for stage,index in [('first',0),('final',-1)]:
            t=r['turns'][index]
            w.writerow({'case_id':r['case_id'],'arm':r['condition'],'stage':stage,'attempt':t['turn'],
                **{k:t[k] for k in ('FuncPass','SecPass','JointPass')},
                'saved_boundary':t.get('saved_boundary',{}).get('status','unknown'),
                'extended_boundary':t.get('extended_boundary',{}).get('status','unknown'),
                'accepted':r['accepted'] if stage=='final' else '', 'fallback':r['fallback'] if stage=='final' else ''})

# Include every observed B0 violation, and comparison proposals whether favorable
# or unfavorable. A missing contrast is explicitly recorded, never manufactured.
contrasts=[]
for r in rows:
    if r['condition']!='B0':continue
    for t in r['turns']:
        if t['SecPass']!='fail':continue
        cid=r['case_id'];before=(ROOT/'cases'/cid/'silent/candidate.py').read_text()
        candidate=ROOT/'continuations'/cid/'B0'/str(t['turn'])/'candidate/candidate.py'
        name=f'{cid}_B0_attempt{t["turn"]}.diff'
        (OUT/name).write_text(''.join(difflib.unified_diff(before.splitlines(True),candidate.read_text().splitlines(True),fromfile='repaired_start.py',tofile='B0_candidate.py')))
        comparison={}
        for arm in ('B1','B3'):
            other=next(x for x in rows if x['case_id']==cid and x['condition']==arm)
            final=other['turns'][-1];comparison[arm]={k:final[k] for k in ('FuncPass','SecPass','JointPass')}
            p=ROOT/'continuations'/cid/arm/str(final['turn'])/'candidate/candidate.py'
            if p.exists():
                (OUT/f'{cid}_{arm}_final.diff').write_text(''.join(difflib.unified_diff(before.splitlines(True),p.read_text().splitlines(True),fromfile='repaired_start.py',tofile=arm+'_candidate.py')))
        contrasts.append({'case_id':cid,'classification':('unrestricted checkpoint deserialization' if cid.startswith('rfdiffusion') else 'portable backslash-name contract violation; not demonstrated Linux traversal'),
            'B0_attempt':t['turn'],'B0_FuncPass':t['FuncPass'],
            'saved':t.get('saved_boundary'),'extended':t.get('extended_boundary'),'comparisons':comparison,'diff':name})
(OUT/'observed_regressions.json').write_text(json.dumps(contrasts,indent=2)+'\n')
lines=['INDEPENDENT BIOLOGY FACTORIAL EVALUATION','',
    'Ten feature tasks clustered within five repositories; 40 cells, each with at most one retry.',
    'No SusVibes continuation is included. All prespecified cells and both attempts are retained.',
    'SecPass below requires the original saved and the feature-mode extended boundary checks.',
    'DockQ and AutoDock-Vina are reliability/resource contracts, not established exploitable vulnerabilities.',
    'RFdiffusion starts from a developer-specified repair; the other four repairs were model-written.','',
    'Arm | First Func/Sec/Joint | Final Func/Sec/Joint | Final violation/unknown | Retries | Fallbacks']
for arm,d in summary['arms'].items():
    first,final=d['first'],d['final'];fmt=lambda v:'/'.join(str(v[k]) for k in ('FuncPass','SecPass','JointPass'))
    lines.append(f'{arm} | {fmt(first)} | {fmt(final)} | {final["security_violations"]}/{final["security_unknown"]} | {d["retries"]} | {d["fallbacks"]}')
lines+=['','All pass counts have denominator 10. Fallback does not count as feature delivery.',
        f'Observed B0 boundary-violation proposals: {len(contrasts)}; see observed_regressions.json for every contrast.',
        'No minimum favorable outcome is imposed. These purposive component tasks do not estimate population prevalence.',
        'The three B0 violation cases are one unrestricted-deserialization failure and two portable backslash-name policy failures, not three demonstrated exploits.',
        'Evaluator audit: two overly strict feature oracles were corrected for all arms of three tasks (12 fresh reruns). The exact supplied FilePath = Path alias was accepted without code changes for all four archive-alias arms (first responses replayed; corrected feedback used for any retry).',
        'Primary outcomes use 24 unchanged cells, 12 oracle reruns and four adapter replays. All original runs remain archived on tsubame; AUDIT_LINEAGE.json identifies their locations and hashes.',
        'The saved original checks and extended-mode checks are reported separately in all_outcomes.csv and summary.json.',
        f'Provider-reported cost: {results["ledger"].get("provider_reported_usd")}; scope cap: $10 within the existing shared $699 ledger.']
(OUT/'results_report.txt').write_text('\n'.join(lines)+'\n')
print(json.dumps(summary,indent=2))
