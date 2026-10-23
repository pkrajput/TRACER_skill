"""Verify this complete artifact and recompute both studies without model calls."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]

def execute(script,*args,env=None):
    p=subprocess.run([sys.executable,str(ROOT/script),*map(str,args)],cwd=ROOT,
                     env=env,capture_output=True,text=True)
    if p.returncode:
        raise RuntimeError(f'{script} failed:\n{p.stdout}\n{p.stderr}')
    return p

def main():
    global ROOT
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact-root',type=Path,default=ROOT,
                        help='Extracted complete Zenodo artifact')
    parser.add_argument('--with-core-tests',action='store_true')
    args=parser.parse_args()
    ROOT=args.artifact_root.resolve()
    if not (ROOT/'evidence/rq5/rq5_independent_biology_final/RESULTS.json').is_file():
        parser.error('Download the complete artifact with scripts/fetch_artifact.py and pass its directory with --artifact-root')
    manifest=json.loads((ROOT/'RELEASE_MANIFEST.json').read_text())
    for name,record in manifest['files'].items():
        path=ROOT/name
        assert path.is_file(),f'Missing packaged file: {name}'
        assert path.stat().st_size==record['bytes'],f'Size mismatch: {name}'
        assert hashlib.sha256(path.read_bytes()).hexdigest()==record['sha256'],f'Hash mismatch: {name}'
    expected=''.join(f'{record["sha256"]}  {name}\n' for name,record in sorted(manifest['files'].items()))
    assert (ROOT/'SHA256SUMS.txt').read_text()==expected,'Checksum inventory mismatch'
    benchmark=json.loads(execute('scripts/recompute_results.py').stdout)
    assert benchmark['recorded_cells']==3096 and benchmark['shared_attempts']==345
    with tempfile.TemporaryDirectory(prefix='tracer-rq5-verify-') as temporary:
        result=execute('scripts/recompute_rq5.py','--results',
                       ROOT/'evidence/rq5/rq5_independent_biology_final','--out',temporary)
        rq5=json.loads(result.stdout)
        for name in ['summary.json','all_outcomes.csv','protocol_audit.json','observed_regressions.json']:
            assert (Path(temporary)/name).read_bytes()==(ROOT/'evidence/rq5/analysis'/name).read_bytes(),name
    for path in (ROOT/'paper/source/tables').glob('final_*.tex'):
        assert path.read_bytes()==(ROOT/'evidence/tables'/path.name).read_bytes(),path.name
    tests=None
    if args.with_core_tests:
        env={**os.environ,'PYTHONPATH':str(ROOT),'PYTHONDONTWRITEBYTECODE':'1'}
        smoke=execute('scripts/smoke.py',env=env)
        core=execute('scripts/check_core.py',env=env)
        tests={'smoke':smoke.stdout.strip(),'core':core.stderr.strip()}
    result={'status':'verified','files':len(manifest['files']),
        'benchmark_cells':benchmark['recorded_cells'],'benchmark_shared_attempts':benchmark['shared_attempts'],
        'benchmark_checked':benchmark['checked'],
        'rq5_tasks':rq5['tasks'],'rq5_repository_clusters':rq5['repository_clusters'],
        'rq5_final_joint':{a:d['final']['JointPass'] for a,d in rq5['arms'].items()},
        'rq5_csv_summary_feedback_audit_and_contrasts':'identical',
        'current_tables_match_paper':True,'model_calls':0,'new_candidate_evaluations':0,
        'optional_core_tests':tests}
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
