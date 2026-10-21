"""Isolated evaluation of a single committed repair candidate; no model feedback."""
from __future__ import annotations
import json, os, shutil, threading, uuid
from pathlib import Path
from security_ground_truth.runtime.common import run_logged,write_json,sha256,utcnow
from .official_score import score_raw, completion_checked_run

DOCKER='unix:///run/user/1012/tracer-docker/docker.sock'
RUN_ENV={'DOCKER_HOST':DOCKER}


def evaluate(case,patch,output,namespace,worker_files,*,execution_overrides=None,phases=None):
    selected=tuple(phases) if phases is not None else ('func','sec')
    if not selected or len(set(selected))!=len(selected) or any(p not in ('func','sec') for p in selected):
        raise ValueError('Select distinct official func/sec phases')
    # Partial evaluation supports evaluator-only rescue: run public functionality
    # first, then security only if it passes. Never reuse a partial summary as a
    # completed two-phase evaluation.
    result_path=output/('evaluation.json' if selected==('func','sec') else 'evaluation.'+'.'.join(selected)+'.json')
    if result_path.exists():return json.loads(result_path.read_text())
    output.mkdir(parents=True,exist_ok=True);casepath=Path(case['case_path'])
    overrides=execution_overrides or {}
    task=json.loads((casepath/'task.json').read_text());spec=json.loads((casepath/'logs_handler.json').read_text())
    identity=json.loads((casepath/'image_identity.json').read_text())
    runs={p:{'execution_error':'Phase not requested in this invocation'} for p in ('func','sec')};phase_results={}
    for phase in selected:
        dest=output/phase;control=dest/'control';control.mkdir(parents=True,exist_ok=True)
        for name in ['agent_effective.patch','security_tests.patch','expected_masked_files.json']:
            shutil.copy2(casepath/name,control/name)
        shutil.copy2(patch,control/'repair.patch')
        shutil.copy2(worker_files/'container_worker.py',control/'worker.py')
        shutil.copy2(worker_files/'test_results.py',control/'test_results.py')
        previous=json.loads((casepath/'runs/agent'/phase/'control/run.json').read_text())
        patches=([{'file':'security_tests.patch'}] if phase=='sec' else [])+[{'file':'agent_effective.patch'}]
        if patch.stat().st_size:patches.append({'file':'repair.patch'})
        cfg={**previous,'patches':patches,'worker_sha256':sha256(control/'worker.py'),
             'repair_patch_sha256':sha256(patch),'command':identity['command'],'timeout_seconds':900}
        cfg.update({k:overrides[k] for k in ('command','timeout_seconds','memory_limit_bytes','added_capabilities') if k in overrides})
        write_json(control/'run.json',cfg)
        # Atomic JSON writes are owner-only; rootless containers with all
        # capabilities dropped cannot bypass that host ownership after docker cp.
        for file in control.iterdir():
            file.chmod(0o444)
        control.chmod(0o755)
        name='tracer-repair-'+uuid.uuid4().hex[:16]
        def command(argv,label,timeout=120):
            return run_logged(['docker']+argv,dest/'logs'/label,timeout=timeout,env=RUN_ENV)
        create=['create','--name',name,'--network','none','--cap-drop','ALL','--security-opt','no-new-privileges',
                '--pids-limit','512','--memory',overrides.get('memory','6g'),'--label','tracer.experiment=20261015-repair-pass1',
                '--env','OMP_NUM_THREADS=2','--env','OPENBLAS_NUM_THREADS=2','--env','MKL_NUM_THREADS=2',
                '--env','PYTEST_XDIST_AUTO_NUM_WORKERS=2','--entrypoint','python']
        for key,value in overrides.get('env',{}).items():create.extend(['--env',key+'='+str(value)])
        if overrides.get('wheelhouse'):create.extend(['--mount','type=bind,source='+overrides['wheelhouse']+',target=/tracer_wheels,readonly'])
        for cap in cfg.get('added_capabilities',[]):create.extend(['--cap-add',cap])
        create.extend([identity['image_id'],'/tracer_control/worker.py'])
        try:
            for argv,label in [(create,'create'),(['cp',str(control),name+':/tracer_control'],'copy_input')]:
                # Layer materialization can exceed two minutes under concurrent
                # evaluations. This is infrastructure startup, not the benchmark
                # test deadline (which remains 900 seconds for both phases).
                outcome = command(argv,label,300 if label=='create' else 120)
                if outcome['exit_code']!=0:
                    raise RuntimeError('Container '+label+' failed: '+outcome.get('status','unknown')+
                                       '; exit='+str(outcome['exit_code']))
            command(['start','-a',name],'start',cfg['timeout_seconds']+180)
            command(['stop','-t','5',name],'stop',30)
            transfer=command(['cp',name+':/tracer_artifacts',str(dest/'artifacts')],'copy_output')
            art=dest/'artifacts'
            if transfer['exit_code']!=0 or not (art/'result.json').exists():raise RuntimeError('Missing test artifacts')
            report=json.loads((art/'result.json').read_text());phase_results[phase]=report
            if report['status']=='source_or_patch_error' or not (art/'test.stdout').exists():
                raise RuntimeError('Source/test preparation failed: '+str(report.get('error',report['status']))[:1000])
            runs[phase]=completion_checked_run(report,(art/'test.stdout').read_text(errors='replace'),
                         (art/'test.stderr').read_text(errors='replace') if (art/'test.stderr').exists() else '')
            if phase=='func':
                write_json(output/'source_provenance.json',{'image_id':identity['image_id'],
                     'original_patch_sha256':sha256(casepath/'agent_effective.patch'),'repair_patch_sha256':sha256(patch),
                     'evaluated_source_identity':json.loads((art/'source_identity.json').read_text()),
                     'hidden_tests_in_functional_source':json.loads((art/'state_ready.json').read_text())['oracle_tests_in_source']})
        except Exception as exc:
            runs[phase]={'execution_error':str(exc)[:2000]}
        finally:
            command(['rm','-f',name],'remove',30)
    score=score_raw(task,spec,runs,namespace)
    result={'case_key':case['case_key'],'score':score,'phase_results':phase_results,
            'requested_phases':list(selected),
            'repair_patch_sha256':sha256(patch),'finished_utc':utcnow(),
            'scoring_semantics':'Terminal-execution validation followed by SusVibes v1.0 pinned count parser and cumulative capped expected failures',
            'execution_settings':'same image ID, test command, caps and 900-second timeout as archived baseline',
            'hidden_test_feedback_to_model':False}
    if overrides:result['execution_overrides']=overrides
    write_json(result_path,result);return result
