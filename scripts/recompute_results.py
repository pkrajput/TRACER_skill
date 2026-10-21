"""Recompute completed-cohort results from archived rows. No model or Docker use."""
import argparse
import gzip
import json
from pathlib import Path

ARMS=('C0','C1','C2','C3')

def complete(row):
    return all(row[k]['terminal_phases']==2 for k in ['baseline','evaluation'])

def summarize(rows):
    assert all(complete(r) for r in rows)
    return {'n':len(rows),
        'base_func':sum(r['baseline']['score']['func_pass'] for r in rows),
        'base_sec':sum(r['baseline']['score']['sec_pass'] for r in rows),
        'func':sum(r['evaluation']['score']['func_pass'] for r in rows),
        'sec':sum(r['evaluation']['score']['sec_pass'] for r in rows),
        'conversions':sum(not r['baseline']['score']['sec_pass'] and r['evaluation']['score']['sec_pass'] for r in rows),
        'regressions':sum(r['baseline']['score']['sec_pass'] and not r['evaluation']['score']['sec_pass'] for r in rows),
        'case_keys':sorted(r['case_key'] for r in rows)}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evidence',type=Path,default=Path(__file__).resolve().parents[1]/'evidence')
    args=p.parse_args();root=args.evidence
    frozen=json.loads((root/'FINAL_MANUSCRIPT_DATA.json').read_text())
    rows=json.loads(gzip.decompress((root/'study_outcomes.json.gz').read_bytes()))['rows']
    models=('deepseek','gemini')
    index={(r['investigator'],r['case_key'],r['arm']):r for r in rows}
    assert len(index)==len(rows)==3096
    all_keys={r['case_key'] for r in rows};assert len(all_keys)==387
    matched={m:{k for k in all_keys if all(complete(index[m,k,a]) for a in ARMS)} for m in models}
    common=set.intersection(*matched.values())
    assert sorted(common)==frozen['matched_cases']['shared']
    out={}
    for m in models:
        assert sorted(matched[m])==frozen['matched_cases'][m]
        selected=[r for r in rows if r['investigator']==m and r['case_key'] in common]
        groups={'Overall':selected,
                'SAST-seeded':[r for r in selected if r['input_has_scanner_alerts']],
                'Unseeded':[r for r in selected if not r['input_has_scanner_alerts']],
                'Development exposed':[r for r in selected if r['stratum']=='development_exposed'],
                'Previously protected':[r for r in selected if r['stratum']=='previously_protected']}
        groups.update({'Generator: '+g:[r for r in selected if r['generator']==g]
                       for g in sorted({r['generator'] for r in selected})})
        for name,group in groups.items():
            for arm in ARMS:
                got=summarize([r for r in group if r['arm']==arm])
                assert got==frozen['shared'][m][name][arm],(m,name,arm)
        for expected in frozen['funnel'][m]:
            r=[x for x in rows if x['investigator']==m and x['arm']==expected['arm']]
            s1=[x for x in r if x['stage1_reference_symbol']]
            s2=[x for x in s1 if x['stage2_supported_reference_symbol']]
            s3=[x for x in s2 if x['stage3_reference_file_edited']]
            s4=[x for x in s3 if x['candidate_patch_bytes']]
            sec=[x for x in s4 if x['evaluation']['terminal_phases']==2 and x['evaluation']['score']['sec_pass']]
            conv=[x for x in sec if x['baseline']['terminal_phases']==2 and
                  x['baseline']['score']['func_pass'] and not x['baseline']['score']['sec_pass']]
            got={'n':len(r),'s1':len(s1),'s2':len(s2),'s3_file':len(s3),'s4_retained':len(s4),
                 's4_sec':len(sec),'s4_conversions':len(conv),'discarded':sum(x['stage4_discarded_to_zero'] for x in r)}
            assert all(got[k]==expected[k] for k in got),(m,expected['arm'],got)
        out[m]={a:{k:v for k,v in summarize([r for r in selected if r['arm']==a]).items() if k!='case_keys'} for a in ARMS}
    print(json.dumps({'status':'verified','recorded_cells':len(rows),'shared_attempts':len(common),
        'matched_attempts':{k:len(v) for k,v in matched.items()},'shared':out,
        'checked':'all shared generator/stratum summaries and both full nested funnels',
        'model_calls':0,'new_evaluations':0},indent=2))

if __name__=='__main__':main()
