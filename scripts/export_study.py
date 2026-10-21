"""Export allowlisted terminal outcomes and funnel facts. Reads archives only."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['deepseek','gemini','cases','frozen','output']:
        p.add_argument('--'+name, type=Path, required=True)
    a=p.parse_args()
    frozen=json.loads(a.frozen.read_text())
    cases={c['case_key']:c for c in json.loads(a.cases.read_text())}
    rows=[]
    for investigator, source in [('deepseek',a.deepseek),('gemini',a.gemini)]:
        facts={(r['case_key'],r['arm']):r for r in frozen['cell_evidence'][investigator]}
        for r in json.loads(source.read_text())['rows']:
            c=cases[r['case_key']];f=facts[(r['case_key'],r['arm'])]
            row={k:r[k] for k in ['case_key','arm']}
            if 'input_has_scanner_alerts' in r:
                row['input_has_scanner_alerts']=r['input_has_scanner_alerts']
                row['repair_status']=r['repair_status']
            else:
                cell=Path(f['cell'])
                supplied=(cell/'input.json').read_bytes()
                result=(cell/'result.json').read_bytes()
                row['input_has_scanner_alerts']=bool(json.loads(supplied).get('scanner_alerts'))
                row['repair_status']=json.loads(result).get('status')
                row['additional_source_sha256']={
                    'input.json':hashlib.sha256(supplied).hexdigest(),
                    'result.json':hashlib.sha256(result).hexdigest()}
            row.update(investigator=investigator, generator=c['model_name'],
                       instance_id=c['instance_id'], stratum=c['v12_stratum'])
            row.update({k:f[k] for k in ['stage1_reference_symbol','stage2_supported_reference_symbol',
                'stage3_reference_file_edited','stage4_discarded_to_zero','candidate_patch_bytes','artifact_sha256']})
            for phase in ['baseline','evaluation']:
                record=r[phase]
                row[phase]={k:record.get(k) for k in ['terminal_phases','terminal_completed','score','parser']}
                # Terminal summaries and evidence identities are retained, but no
                # arbitrary log text, prompts, credentials, or host paths are copied.
                row[phase]['evidence']={k:{x:v.get(x) for x in ['raw_status','result_sha256','stdout_sha256','terminal']}
                                       for k,v in record.get('evidence',{}).items()}
            rows.append(row)
    assert len(rows)==3096
    assert len({(r['investigator'],r['case_key'],r['arm']) for r in rows})==3096
    payload={'schema':'tracer-study-outcomes-v1','model_calls':0,'new_evaluations':0,
        'sources':[{ 'name':k,'sha256':hashlib.sha256(getattr(a,k).read_bytes()).hexdigest()}
                   for k in ['deepseek','gemini','cases','frozen']], 'rows':rows}
    a.output.parent.mkdir(parents=True,exist_ok=True)
    encoded=(json.dumps(payload,sort_keys=True,separators=(',',':'))+'\n').encode()
    if a.output.suffix=='.gz':encoded=gzip.compress(encoded,mtime=0)
    with a.output.open('xb') as f:f.write(encoded)
    print(json.dumps({'rows':len(rows),'output':str(a.output)}))


if __name__=='__main__':main()
