"""Free evaluator-only recovery and matched DeepSeek/Gemini reporting.

Raw experiments are immutable. Parser corrections use archived logs; environment
repairs evaluate a paired empty-patch baseline and every distinct candidate in
the same restored environment. No outcome is returned to an investigator.
"""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import uuid

from security_ground_truth.runtime.common import write_json,utcnow,sha256,run_logged,clean_env
from security_ground_truth.repair_check.evaluate import evaluate,DOCKER
from security_ground_truth.repair_check.official_score import load_authors_classes,score_raw
from security_ground_truth.repair_check.terminal_extended import parse_terminal,PARSER_VERSION
from .v12_campaign import ROOT as DEEP,ARMS
from .prepare_v12 import read

PRIOR_ROOT=Path('/raid/prateek/ghost_code/security_experiments/20261019/comparison_v12')
ROOT=Path('/raid/prateek/ghost_code/security_experiments/20261019/comparison_v12_r2')
GEMINI=Path('/raid/prateek/ghost_code/security_experiments/20261019/gemini_v12_r2')


def score_directory(case,directory,namespace,*,baseline=False):
    runs={};terminals={};evidence={}
    for phase in ('func','sec'):
        p=directory/phase/'artifacts'
        # The replay harness archives exit.json; run_logged-based repair
        # evaluations archive command.json with the same exit/status fields.
        transfer=directory/phase/'logs/copy_output/exit.json'
        if not transfer.exists():transfer=directory/phase/'logs/copy_output/command.json'
        if (not (p/'result.json').exists() or not (p/'test.stdout').exists() or
                not transfer.exists() or read(transfer).get('exit_code')!=0):
            runs[phase]={'execution_error':'missing artifacts or incomplete transfer'};terminals[phase]=False;continue
        raw=read(p/'result.json');out=(p/'test.stdout').read_text(errors='replace')
        err=(p/'test.stderr').read_text(errors='replace') if (p/'test.stderr').exists() else ''
        terminal=parse_terminal(out,err,raw.get('exit_code'),raw.get('status'))
        runs[phase]={'logs':out+'\n'+err,'timed_out':raw.get('status')=='timeout'}
        if not terminal['recognized']:runs[phase]['execution_error']='No recognized terminal completion'
        terminals[phase]=terminal['recognized']
        evidence[phase]={'terminal':terminal,'raw_status':raw.get('status'),
            'stdout_sha256':sha256(p/'test.stdout'),'result_sha256':sha256(p/'result.json')}
    cp=Path(case['case_path'])
    score=score_raw(read(cp/'task.json'),read(cp/'logs_handler.json'),runs,namespace)
    return {'score':score,'terminal_completed':terminals,'terminal_phases':sum(terminals.values()),
        'evidence':evidence,'directory':str(directory),'parser':PARSER_VERSION}


def logs(directory):
    return '\n'.join(p.read_text(errors='replace') for phase in ('func','sec')
        for p in (directory/phase/'artifacts/test.stdout',directory/phase/'artifacts/test.stderr') if p.exists())


def recovery_reason(directory):
    text=logs(directory)
    if "chmod: changing permissions of '/var/run/postgresql': Operation not permitted" in text:
        return 'local_service_permissions'
    if 'No matching distribution found' in text or 'Could not find a version that satisfies the requirement' in text:
        return 'offline_dependencies'
    for phase in ('func','sec'):
        p=directory/phase/'artifacts/result.json'
        if p.exists():
            raw=read(p)
            if raw.get('status')=='timeout':return 'bounded_timeout_retry'
            if raw.get('exit_code') in (137,139,-9,-11):return 'resource_retry'
    if 'MemoryError' in text or "can't start new thread" in text or 'Resource temporarily unavailable' in text:
        return 'resource_retry'
    if re.search(r'^Killed\s*$',text,re.M) and 'likely segfaulted or crashed Python' in text:
        return 'resource_retry'
    return None


def missing_requirements(text):
    result=set()
    for value in re.findall(r'(?:No matching distribution found for|Could not find a version that satisfies the requirement) ([^\n]+)',text):
        value=value.split(' (from versions:')[0].strip().strip('\"\'')
        if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*(?:\[[A-Za-z0-9_,.-]+\])?(?:[<>=!~][A-Za-z0-9*.,<>=!~+_-]+)?',value):result.add(value)
    return result


def overrides_for(case,reason,wheelhouse,observed_logs):
    command=list(read(Path(case['case_path'])/'image_identity.json')['command'])
    # Constrain runner concurrency only. Preserve its complete test selection.
    if reason=='resource_retry':
        if len(command)==3 and command[:2]==['/bin/sh','-c']:
            text=command[2]
            if 'runtests.py' in text and '--parallel' not in text:text+=' --parallel 2'
            if re.search(r'\bpytest\b',text) and ('execnet' in observed_logs or 'xdist' in observed_logs):text+=' -n 2'
            if re.search(r'\bstestr\s+run\b',text) and '--concurrency' not in text:
                text=re.sub(r'\bstestr\s+run\b','stestr run --concurrency=2',text,count=1)
            command[2]=text
    result={'command':command,'timeout_seconds':1800 if reason=='bounded_timeout_retry' else 900,
        'memory':'12g','memory_limit_bytes':12*1024**3,
        'env':{'DJANGO_TEST_PROCESSES':'2','PYTEST_XDIST_AUTO_NUM_WORKERS':'2',
               'PIP_NO_INDEX':'1','PIP_FIND_LINKS':'/tracer_wheels','PIP_DISABLE_PIP_VERSION_CHECK':'1'},
        'wheelhouse':str(wheelhouse)}
    if reason=='local_service_permissions':
        # Rootless, network-isolated containers still need these capabilities
        # to start the benchmark's bundled PostgreSQL service as its own user.
        result['added_capabilities']=['CHOWN','FOWNER','SETUID','SETGID']
    return result


def download_wheels(case,requirements,wheelhouse,dest):
    if not requirements:return {'status':'not_needed'}
    image=read(Path(case['case_path'])/'image_identity.json')['image_id']
    name='tracer-wheel-cache-'+uuid.uuid4().hex[:12]
    command=['docker','run','--name',name,'--rm','--network','bridge','--cap-drop','ALL',
        '--security-opt','no-new-privileges','--memory','2g','--pids-limit','128',
        '--mount','type=bind,source='+str(wheelhouse)+',target=/tracer_wheels',
        '--entrypoint','python',image,'-m','pip','download','--disable-pip-version-check',
        '--only-binary=:all:','--index-url','https://pypi.org/simple','--dest','/tracer_wheels',*sorted(requirements)]
    result=run_logged(command,dest,timeout=240,env={'DOCKER_HOST':DOCKER})
    if result['status']=='timeout':
        run_logged(['docker','rm','-f',name],dest/'cleanup',timeout=30,env={'DOCKER_HOST':DOCKER})
    return result


def recover_case(root,case,reason,example,namespace):
    folder=root/'recovery'/case['case_key'];folder.mkdir(parents=True,exist_ok=True)
    prior=PRIOR_ROOT/'recovery'/case['case_key']/'ready.json'
    if prior.exists():
        value=read(prior)
        if value.get('baseline') and value.get('source_and_test_patches_unchanged'):
            rescored=score_directory(case,Path(value['baseline']['directory']),namespace)
            if rescored['terminal_phases']==2:
                value.update(status='ready',baseline=rescored,reused_environment_execution=str(prior))
                write_json(folder/'ready.json',value);return value
    empty=folder/'baseline.patch';empty.write_text('')
    wheelhouse=folder/'wheels';wheelhouse.mkdir(exist_ok=True)
    original_logs=logs(example)
    overrides=overrides_for(case,reason,wheelhouse,original_logs)
    needed=missing_requirements(original_logs)
    if reason=='offline_dependencies':needed.update({'setuptools','wheel'})
    attempted=set();baseline_result=None;directory=None
    for round_number in range(1,5):
        new=needed-attempted
        if new:
            download=download_wheels(case,new,wheelhouse,folder/('download_'+str(round_number)))
            attempted.update(new)
            if download.get('exit_code')!=0:
                value={'status':'dependency_cache_unavailable','reason':reason,'download':download,'model_calls':0}
                write_json(folder/'ready.json',value);return value
        directory=folder/('baseline_'+str(round_number))
        evaluate(case,empty,directory,namespace,root/'workers',execution_overrides=overrides)
        baseline_result=score_directory(case,directory,namespace)
        needed=missing_requirements(logs(directory))
        if baseline_result['terminal_phases']==2 or not (needed-attempted):break
    value={'status':'ready' if baseline_result['terminal_phases']==2 else 'baseline_still_incomplete',
        'reason':reason,'overrides':overrides,'baseline':baseline_result,'baseline_patch_sha256':sha256(empty),
        'wheel_sha256':{p.name:sha256(p) for p in wheelhouse.iterdir() if p.is_file()},
        'model_calls':0,'source_and_test_patches_unchanged':True}
    write_json(folder/'ready.json',value);return value


def recover_candidate(root,case,patch,recipe,namespace):
    if sha256(patch)==recipe['baseline_patch_sha256']:return recipe['baseline']
    directory=root/'recovery'/case['case_key']/'candidates'/sha256(patch)
    evaluate(case,patch,directory,namespace,root/'workers',execution_overrides=recipe['overrides'])
    result=score_directory(case,directory,namespace)
    write_json(directory/'derived_score.json',result);return result


def select_paired(raw,baseline,recipe,digest,replayed=None):
    """Never pair a restored baseline with a candidate from an older environment."""
    if not recipe or recipe.get('status')!='ready':
        return raw,baseline,'original_logs_rescored',False
    if digest==recipe['baseline_patch_sha256']:
        return recipe['baseline'],recipe['baseline'],'same_source_as_recovered_baseline',False
    if replayed and 'score' in replayed:
        return replayed,recipe['baseline'],'paired_environment_replay',False
    return raw,baseline,'environment_replay_pending_or_failed',True


def publish(root,cases,rows,states,recovery_status,active):
    by={(r['investigator'],r['case_key'],r['arm']):r for r in rows}
    investigators=sorted(states)
    matched={m:[k for k in cases if all((m,k,a) in by and by[m,k,a]['terminal_phases']==2 and
        by[m,k,a]['baseline']['terminal_phases']==2 and not by[m,k,a].get('recovery_pending')
        for a in ARMS)] for m in investigators}
    common=set.intersection(*(set(v) for v in matched.values())) if matched else set()
    def table(model,keys):
        return {a:{'n':len(keys),'baseline_func':sum(by[model,k,a]['baseline']['score']['func_pass'] for k in keys),
            'baseline_sec':sum(by[model,k,a]['baseline']['score']['sec_pass'] for k in keys),
            'func_pass':sum(by[model,k,a]['score']['func_pass'] for k in keys),
            'sec_pass':sum(by[model,k,a]['score']['sec_pass'] for k in keys),
            'repair_errors':sum(by[model,k,a]['repair_status']=='repair_error' for k in keys)} for a in ARMS}
    data={'utc':utcnow(),'model_states':states,'completed_cells':len(rows),'expected_cells':len(cases)*4*len(investigators),
        'evaluation_recovery_active':active,'recovery_status':recovery_status,'model_calls_for_recovery':0,
        'matched_by_investigator':{m:table(m,matched[m]) for m in investigators},
        'eight_arm_matched_cases':len(common),'model_capability_comparison':{m:table(m,common) for m in investigators},
        'by_generator':{m:{g:table(m,[k for k in matched[m] if cases[k].get('model_name',cases[k].get('generator'))==g])
            for g in sorted({c.get('model_name',c.get('generator')) for c in cases.values()})} for m in investigators},
        'unrecognized_candidate_cells':sum(r['terminal_phases']<2 for r in rows),
        'unrecognized_baseline_cells':sum(r['baseline']['terminal_phases']<2 for r in rows),
        'pending_or_failed_environment_replays':sum(r.get('recovery_pending',False) for r in rows),
        'rows':rows,'policy':'Every comparison requires recognized paired baseline/candidate execution. Original artifacts remain immutable; parser corrections and environment replays are evaluator-only. Exact candidate hashes may share one recovery execution.'}
    target=root/'report';write_json(target/'RESULTS.json',data)
    lines=['# DeepSeek and Gemini v12 — verified results','',f'Updated {data["utc"]}. {len(rows)}/{data["expected_cells"]} cells have archived evaluations. Free recovery jobs active: {active}.','',
        f'Cases with completed baseline and all eight model/arm combinations: **{len(common)}**.','',
        '| Investigator | Arm | Matched cases | Baseline Func/Sec | After Func/Sec |','|---|---|---:|---:|---:|']
    for m in investigators:
        for a,s in table(m,common).items():lines.append(f'| {m} | {a} | {s["n"]} | {s["baseline_func"]}/{s["baseline_sec"]} | {s["func_pass"]}/{s["sec_pass"]} |')
    lines+=['','## Within each investigator (different available cohorts)','']
    for m in investigators:
        lines.extend([f'### {m}','', '| Arm | Cases | Baseline SecPass | FuncPass | SecPass |','|---|---:|---:|---:|---:|'])
        for a,s in table(m,matched[m]).items():lines.append(f'| {a} | {s["n"]} | {s["baseline_sec"]} | {s["func_pass"]} | {s["sec_pass"]} |')
    lines+=['',f'Candidate cells lacking terminal completion: {data["unrecognized_candidate_cells"]}. Baseline cells lacking terminal completion: {data["unrecognized_baseline_cells"]}.',
        'Missing executions are not labeled secure or insecure. Repaired environments use the same source, tests and failure thresholds, and evaluate an original-output baseline alongside candidates. Original logs and all model trajectories remain unchanged.']
    (target/'REPORT.md').write_text('\n'.join(lines)+'\n')


def run(root=ROOT):
    root=Path(root);lock=(root/'audit.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    manifest=read(root/'manifest.json')
    for name,digest in manifest['code_sha256'].items():
        if sha256(root/'frozen_code'/name)!=digest:raise ValueError('Frozen evaluator changed: '+name)
    if sha256(root/'workers/container_worker.py')!=manifest['worker_sha256']:
        raise ValueError('Frozen evaluation worker changed')
    cases={c['case_key']:c for c in read(DEEP/'cases.json')};namespace=load_authors_classes(DEEP/'upstream_logs.py')
    models={'deepseek-v3.2':DEEP,'gemini-3.8-flash':GEMINI}
    parsed={};baseline={};recipes={};candidates={};jobs={};queued=set();last_publish=0
    with ThreadPoolExecutor(max_workers=4) as pool:
        while True:
            for f in list(jobs):
                if not f.done():continue
                kind,key=jobs.pop(f)
                try:value=f.result()
                except Exception as error:value={'status':'recovery_error','error':type(error).__name__+': '+str(error)[:1000]}
                if kind=='baseline':recipes[key]=value
                else:candidates[key]=value
            states={};rows=[]
            for model,experiment in models.items():
                status=read(experiment/'status.json') if (experiment/'status.json').exists() else {'status':'not_started'}
                states[model]=status
                for completed in sorted((experiment/'cells').glob('*/*/complete.json')):
                    cell=completed.parent;k=cell.parent.name;a=cell.name;c=cases[k]
                    identity=(model,k,a)
                    if identity not in parsed:
                        result=read(cell/'result.json');evaluation=read(cell/'evaluation/evaluation.json')
                        if sha256(cell/'candidate.patch')!=result['patch_sha256'] or evaluation['repair_patch_sha256']!=result['patch_sha256']:
                            raise ValueError('Candidate/evaluation source mismatch')
                        parsed[identity]=score_directory(c,cell/'evaluation',namespace)
                    if k not in baseline:baseline[k]=score_directory(c,Path(c['case_path'])/'runs/agent',namespace,baseline=True)
                    raw=parsed[identity];before=baseline[k]
                    patch=cell/'candidate.patch';digest=sha256(patch);cachekey=(k,digest)
                    recipe=recipes.get(k)
                    if recipe and recipe.get('status')=='ready':
                        if (digest!=recipe['baseline_patch_sha256'] and cachekey not in candidates
                                and ('candidate',cachekey) not in queued):
                            queued.add(('candidate',cachekey));jobs[pool.submit(recover_candidate,root,c,patch,recipe,namespace)]=('candidate',cachekey)
                    elif (raw['terminal_phases']<2 or before['terminal_phases']<2) and ('baseline',k) not in queued:
                        example=cell/'evaluation';reason=recovery_reason(example)
                        if not reason:example=Path(c['case_path'])/'runs/agent';reason=recovery_reason(example)
                        queued.add(('baseline',k))
                        if reason:jobs[pool.submit(recover_case,root,c,reason,example,namespace)]=('baseline',k)
                        else:recipes[k]={'status':'requires_source_or_environment_review','reason':'No safe automatic correction matched; preserve incomplete execution'}
                    selected,before,provenance,pending=select_paired(raw,before,recipe,digest,candidates.get(cachekey))
                    result=read(cell/'result.json')
                    rows.append({'investigator':model,'case_key':k,'arm':a,'instance_id':c['instance_id'],
                        'generator':c.get('model_name',c.get('generator')),'repair_status':result['status'],
                        'patch_sha256':result['patch_sha256'],'patch_bytes':result['patch_bytes'],
                        'original_score':raw,'baseline':before,**selected,'evaluation_provenance':provenance,
                        'recovery_pending':pending,'cell':str(cell)})
            if time.monotonic()-last_publish>60:
                publish(root,cases,rows,states,recipes,len(jobs));last_publish=time.monotonic()
                write_json(root/'status.json',{'utc':utcnow(),'status':'running','pid':os.getpid(),'cells_seen':len(rows),'active_jobs':len(jobs),'model_calls':0})
            active=any(s.get('status') in ('running_full','technical_canary','qualifying','not_started') for s in states.values())
            if not active and not jobs:
                publish(root,cases,rows,states,recipes,0)
                write_json(root/'status.json',{'utc':utcnow(),'status':'finished_audit','cells_seen':len(rows),'model_calls':0});break
            time.sleep(15)


def launch(root=ROOT):
    root=Path(root);root.mkdir(parents=True,exist_ok=True)
    if (root/'launch.json').exists():raise ValueError('Audit already launched')
    workers=root/'workers';shutil.copytree(DEEP/'workers',workers)
    worker=workers/'container_worker.py';worker.chmod(0o644)
    shutil.copy2(Path(__file__).resolve().parents[1]/'runtime/susvibes/container_worker.py',worker)
    # Freeze the evaluator separately, including parser tests and recovery code.
    repo=Path(__file__).resolve().parents[2];code=root/'frozen_code'
    from .v11_integrity import qualified_code_paths
    for source in qualified_code_paths(repo):
        dest=code/source.relative_to(repo);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,dest)
    write_json(root/'manifest.json',{'utc':utcnow(),'model_calls':0,'purpose':'Evaluator-only corrections and paired environment recovery',
        'code_sha256':{str(p.relative_to(code)):sha256(p) for p in code.rglob('*') if p.is_file()},
        'worker_sha256':sha256(worker),'models':{'deepseek-v3.2':str(DEEP),'gemini-3.8-flash':str(GEMINI)}})
    with (root/'stdout.log').open('ab',buffering=0) as log:
        proc=subprocess.Popen([sys.executable,'-u','-m','security_ground_truth.temporal_security.evaluation_recovery','run','--root',str(root)],
            cwd=code,env=clean_env(),stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
    value={'utc':utcnow(),'pid':proc.pid,'detached':True,'model_calls':0};write_json(root/'launch.json',value);return value


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('action',choices=['launch','run']);p.add_argument('--root',type=Path,default=ROOT)
    a=p.parse_args();v={'launch':launch,'run':run}[a.action](a.root)
    if v is not None:print(json.dumps(v))
