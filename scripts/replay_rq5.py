"""Replay one saved RQ5 candidate in the recorded offline Docker environment."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import uuid

ROOT=Path(__file__).resolve().parents[1]
PHASES={'functional':'functional','feature':'feature',
        'saved_security':'saved_boundary','extended_security':'extended_boundary'}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact-root',type=Path,default=ROOT,
                        help='Extracted complete Zenodo artifact (default: this checkout)')
    parser.add_argument('--case')
    parser.add_argument('--arm',choices=['B0','B1','B2','B3'],default='B0')
    parser.add_argument('--attempt',choices=['first','final'],default='final')
    parser.add_argument('--execute',action='store_true',help='Actually launch the saved checks in Docker')
    parser.add_argument('--out',type=Path,default=Path('replayed_checks'))
    parser.add_argument('--image',help='Explicit reconstructed image override; recorded identity is used by default')
    args=parser.parse_args()
    artifact=args.artifact_root.resolve()
    EVIDENCE=artifact/'evidence/rq5/rq5_independent_biology_final'
    if not (EVIDENCE/'RESULTS.json').is_file():
        parser.error('Download the complete artifact with scripts/fetch_artifact.py and pass its directory with --artifact-root')
    results=json.loads((EVIDENCE/'RESULTS.json').read_text())
    cases={c['id']:c for c in json.loads((EVIDENCE/'manifest.json').read_text())['cases']}
    if not args.case:
        print(json.dumps({'cases':sorted(cases),'execute':False,'model_calls':0},indent=2));return
    if args.case not in cases:parser.error('Unknown case; run without --case to list packaged cases')
    record=next(r for r in results['records'] if r['case_id']==args.case and r['condition']==args.arm)
    turn=record['turns'][0 if args.attempt=='first' else -1]
    cell=EVIDENCE/'continuations'/args.case/args.arm/str(turn['turn'])
    image=args.image or cases[args.case]['image']
    if not args.image:assert re.fullmatch(r'sha256:[0-9a-f]{64}',image)
    if not args.execute:
        print(json.dumps({'case':args.case,'arm':args.arm,'attempt':turn['turn'],
                          'image':image,'execute':False,'model_calls':0},indent=2));return
    if not (cell/'candidate/candidate.py').is_file():
        parser.error('This cell has no executable candidate; its application/unknown result is preserved in the evidence')
    out=args.out.resolve()
    if out==artifact or artifact/'evidence' in out.parents or out==artifact/'evidence':
        parser.error('Replay output must not overwrite packaged evidence')
    out.mkdir(parents=True,exist_ok=False)
    rows=[]
    for phase,key in PHASES.items():
        archived=cell/phase
        if not archived.is_dir():continue
        owned=out/phase;owned.mkdir(mode=0o755)
        for name in ('check.py','run.py','target.json'):
            shutil.copyfile(archived/name,owned/name);(owned/name).chmod(0o444)
        container='tracer-artifact-'+uuid.uuid4().hex[:12]
        command=['docker','run','--name',container,'--rm','--pull=never',
            '--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges',
            '--pids-limit=128','--memory=3g','--user=65534:65534',
            '--tmpfs=/tmp:rw,nosuid,nodev,size=128m','-e','PYTHONDONTWRITEBYTECODE=1',
            '-e','PYTHONPATH=/repo:/repo/libs/core','-e','OMP_NUM_THREADS=1',
            '--mount',f'type=bind,src={(cell/"candidate").resolve()},dst=/repo,readonly',
            '--mount',f'type=bind,src={owned},dst=/owned,readonly',
            '--workdir=/repo','--entrypoint=python',image,'/owned/run.py']
        try:
            process=subprocess.run(command,capture_output=True,text=True,timeout=150)
            (owned/'stdout.log').write_text(process.stdout);(owned/'stderr.log').write_text(process.stderr)
            lines=[line.split('=',1)[1] for line in process.stdout.splitlines() if line.startswith('TRACER_RESULT=')]
            receipt=json.loads(lines[0]) if process.returncode==0 and len(lines)==1 else {'status':'unknown','reason':'container_or_terminal_error'}
        except subprocess.TimeoutExpired:
            subprocess.run(['docker','rm','-f',container],capture_output=True)
            receipt={'status':'unknown','reason':'timeout'}
        expected=json.loads((archived/'receipt.json').read_text())['status']
        row={'phase':phase,'expected':expected,'observed':receipt.get('status','unknown'),
             'matches':receipt.get('status')==expected,'receipt':receipt}
        rows.append(row)
    result={'case':args.case,'arm':args.arm,'attempt':turn['turn'],'image':image,
            'recorded_image':cases[args.case]['image'],'image_override':bool(args.image),
            'model_calls':0,'checks':rows,'all_statuses_match':all(r['matches'] for r in rows)}
    (out/'REPLAY.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    if not result['all_statuses_match']:raise SystemExit(1)

if __name__=='__main__':main()
