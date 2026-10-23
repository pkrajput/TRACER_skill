"""Bounded generated checks and public functional tests on isolated candidates.

This module never copies the hidden security-test patch into a model tool.
The official evaluator is a separate post-repair stage.
"""
from __future__ import annotations
import hashlib, json, shutil, threading, uuid
from pathlib import Path
from security_ground_truth.runtime.common import run_logged, write_json, sha256

CHECK_SLOTS = threading.BoundedSemaphore(12)
DOCKER_HOST = 'unix:///run/user/1012/tracer-docker/docker.sock'


def validated_functional_score(raw, stdout, stderr, official):
    """The authors' failure threshold applies only after a completed test run."""
    from security_ground_truth.runtime.test_results import parse_test_log
    terminal = parse_test_log(stdout, stderr, raw.get('exit_code'), raw.get('status'))
    if not terminal['recognized']:
        return {'pass':False, 'test_status':'indeterminate',
                'reason':'No recognized terminal test result; a zero failure count is not a pass',
                'published_count_result':official, 'terminal_result':terminal}
    return {**official, 'terminal_result':terminal}

class Sandbox:
    def __init__(self, case, output, editor):
        self.case, self.output, self.editor = case, output, editor
        self.casepath = Path(case['case_path'])
        self.identity = json.loads((self.casepath/'image_identity.json').read_text())
        self.manifest = json.loads((Path(case['baseline'])/'source_manifest.json').read_text())
        self.sequence = 0

    def run(self, *, code=None, target_path=None, target_line=None, target_span=None, trace_target=None, functional=False):
        self.sequence += 1
        directory = self.output/('functional' if functional else 'checks')/('%03d'%self.sequence)
        control=directory/'input';control.mkdir(parents=True)
        shutil.copy2(self.casepath/'agent_effective.patch', control/'agent.patch')
        (control/'candidate.patch').write_text(self.editor.patch())
        manifest = json.loads(json.dumps(self.manifest))
        for row in manifest['files']:
            if row['path'] in self.editor.edits:
                row['sha256']=hashlib.sha256(self.editor.edits[row['path']].encode()).hexdigest()
        if trace_target:manifest['_tracer_trace_target']=trace_target
        write_json(control/'expected.json',manifest)
        if not functional:
            if not isinstance(code,str) or len(code)>18000:raise ValueError('Check must be at most 18000 characters')
            (control/'check.py').write_text(code)
            shutil.copy2(Path(__file__).parents[1]/'runtime/dynamic_probe.py',control/'probe.py')
        # Fixed launcher. Model code only executes after source identity checking.
        config={'workdir':self.identity['workdir'],'command':self.identity['command'],
                'functional':functional,'timeout':900 if functional else 60}
        write_json(control/'config.json',config)
        (control/'launch.py').write_text(LAUNCHER)
        for p in control.iterdir():p.chmod(0o444)
        control.chmod(0o755)
        name='tracer-temporal-'+uuid.uuid4().hex[:16]
        env={'DOCKER_HOST':DOCKER_HOST}
        def command(argv,label,timeout=90):
            return run_logged(['docker']+argv,directory/label,timeout=timeout,env=env)
        with CHECK_SLOTS:
            try:
                create=['create','--name',name,'--network','none','--cap-drop','ALL','--security-opt','no-new-privileges',
                        '--memory','6g','--pids-limit','512','--label','tracer.experiment=20261017-temporal',
                        '--env','OMP_NUM_THREADS=2','--env','OPENBLAS_NUM_THREADS=2','--env','MKL_NUM_THREADS=2',
                        '--env','PYTEST_XDIST_AUTO_NUM_WORKERS=2','--entrypoint','python',self.identity['image_id'],
                        '/tracer_check/launch.py']
                prior=self.casepath/'runs/agent/func/control/run.json'
                if prior.exists():
                    for cap in json.loads(prior.read_text()).get('added_capabilities',[]):create[1:1]=['--cap-add',cap]
                for argv,label in [(create,'create'),(['cp',str(control),name+':/tracer_check'],'input')]:
                    result=command(argv,label)
                    if result['exit_code']!=0:raise RuntimeError(label+' failed: '+(directory/label/'stderr.log').read_text()[-1000:])
                result=command(['start','-a',name],'execute',1080 if functional else 100)
                command(['stop','-t','2',name],'stop',20)
                transfer=command(['cp',name+':/tracer_output',str(directory/'artifacts')],'collect')
                artifacts=directory/'artifacts'
                if transfer['exit_code'] or not (artifacts/'result.json').exists():
                    raise RuntimeError('Missing check result: '+(directory/'execute/stderr.log').read_text()[-2000:])
                raw=json.loads((artifacts/'result.json').read_text())
                stdout=(artifacts/'stdout').read_text(errors='replace') if (artifacts/'stdout').exists() else ''
                stderr=(artifacts/'stderr').read_text(errors='replace') if (artifacts/'stderr').exists() else ''
                raw.update(stdout=stdout[-10000:],stderr=stderr[-5000:],hidden_security_tests_used=False,
                           candidate_patch_sha256=sha256(control/'candidate.patch'),artifact_directory=str(directory))
                if not functional:
                    coverage=raw.pop('coverage',{})
                    reached=(target_line in coverage.get(target_path,[]) or bool(target_span and
                             any(target_span[0]<=line<=target_span[1] for line in coverage.get(target_path,[]))))
                    if trace_target:reached=bool(raw.get('target_frame_executed'))
                    raw.update(target_reached=(raw.get('source_identity')=='expected_files_match' and reached),
                               target_file_executed_lines=coverage.get(target_path,[])[:300],
                               edited_file_executed_lines={p:coverage.get(p,[]) for p in self.editor.edits},
                               coverage_file_count=len(coverage),independent_ground_truth=False)
                else:
                    from security_ground_truth.repair_check.official_score import load_authors_classes,score_raw
                    parser=Path(self.case['authors_logs_path'])
                    task=json.loads((self.casepath/'task.json').read_text())
                    spec=json.loads((self.casepath/'logs_handler.json').read_text())
                    full_stdout=(artifacts/'stdout').read_text(errors='replace')
                    full_stderr=(artifacts/'stderr').read_text(errors='replace')
                    run={'logs':full_stdout+'\n'+full_stderr,'timed_out':raw.get('status')=='timeout'}
                    if raw.get('status')=='preparation_error':run={'execution_error':raw['error']}
                    score=score_raw(task,spec,{'func':run,'sec':{'execution_error':'not exposed during repair'}},load_authors_classes(parser))
                    raw['functional_result']=validated_functional_score(raw,full_stdout,full_stderr,score['runs']['func'])
                write_json(directory/'feedback.json',raw)
                return raw
            except Exception as error:
                result={'status':'tool_execution_error','error_type':type(error).__name__,'error':str(error)[:2500],
                        'hidden_security_tests_used':False,'independent_ground_truth':False}
                write_json(directory/'feedback.json',result);return result
            finally:
                command(['rm','-f',name],'remove',30)

LAUNCHER = r'''import json, os, subprocess, shutil, resource, traceback, hashlib
from pathlib import Path
c=Path('/tracer_check');out=Path('/tracer_output');out.mkdir(exist_ok=True)
cfg=json.loads((c/'config.json').read_text())
resource.setrlimit(resource.RLIMIT_AS,(6*1024**3,6*1024**3))
resource.setrlimit(resource.RLIMIT_CPU,(cfg['timeout'],cfg['timeout']+5))
try:
 os.chdir(cfg['workdir'])
 for name in ['agent.patch','candidate.patch']:
  if (c/name).stat().st_size:subprocess.run(['git','apply','--ignore-space-change',str(c/name)],check=True)
 shutil.rmtree('.git',ignore_errors=True)
 for row in json.loads((c/'expected.json').read_text())['files']:
  source=Path(row['path'])
  if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest()!=row['sha256']:
   raise ValueError('Candidate source identity mismatch: '+row['path'])
 if cfg['functional']:
  # Public functional tests only. The hidden security patch is never supplied.
  with (out/'stdout').open('w') as stdout,(out/'stderr').open('w') as stderr:
   try:
    proc=subprocess.run(cfg['command'],stdout=stdout,stderr=stderr,timeout=cfg['timeout'])
    result={'status':'executed','exit_code':proc.returncode}
   except subprocess.TimeoutExpired:result={'status':'timeout'}
  (out/'result.json').write_text(json.dumps(result))
 else:
  with (out/'stdout').open('w') as stdout,(out/'stderr').open('w') as stderr:
   subprocess.run(['python',str(c/'probe.py'),os.getcwd(),str(c/'check.py'),str(c/'expected.json'),str(out/'result.json')],stdout=stdout,stderr=stderr,check=True,timeout=cfg['timeout'])
except BaseException as e:
 (out/'result.json').write_text(json.dumps({'status':'preparation_error','error':str(e),'traceback':traceback.format_exc()[-3000:]}))
'''
