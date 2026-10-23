"""Stream free preparation into a frozen, budgeted four-arm experiment."""
from __future__ import annotations
import argparse, collections, concurrent.futures as futures, fcntl, json, os
from pathlib import Path
import shutil, signal, threading, time, traceback
from . import engine,inputs
from .score import write_report
from security_ground_truth.repair_check.google_native import GoogleRepair
from .openrouter_repair import OpenRouterRepair
from security_ground_truth.repair_check.evaluate import evaluate
from security_ground_truth.repair_check.official_score import load_authors_classes
from security_ground_truth.runtime.common import write_json,utcnow,sha256

def qualification_failures(results):
    failures=[]
    for row in results:
        repair=row['repair'];score=row['evaluation']['score']
        if (repair['status'] not in {'finished','turn_limit'} or not repair['hypothesis_count']
                or not repair['static_assessments']
                or any(v['test_status']!='completed' for v in score['runs'].values())):
            failures.append({'case_key':row['case_key'],'arm':row['arm'],'status':repair['status']})
    if not any(row['repair']['status']=='finished' for row in results):
        failures.append({'stage':'protocol','reason':'No cell demonstrated the finish action'})
    return failures

def existing_cell(cell, key, arm):
    """Resume only recorded results; never reroll an interrupted paid attempt."""
    complete=cell/'complete.json';result=cell/'result.json'
    if complete.exists():
        joined=json.loads(complete.read_text());repair=joined['repair']
        if joined['case_key']!=key or joined['arm']!=arm:
            raise ValueError('Recorded cell identity mismatch')
    elif result.exists():
        joined=None;repair=json.loads(result.read_text())
        if repair['case_key']!=key or repair['arm']!=arm:
            raise ValueError('Recorded repair identity mismatch')
    elif (cell/'trajectory.json').exists():
        raise ValueError('Interrupted recorded attempt requires explicit recovery; no paid reroll')
    else:return None,None
    if sha256(cell/'candidate.patch')!=repair['patch_sha256']:
        raise ValueError('Recorded candidate patch changed')
    return joined,repair

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--workers',type=int,default=24);parser.add_argument('--eval-workers',type=int,default=12)
    parser.add_argument('--deadline-hours',type=float,default=24)
    parser.add_argument('--release-after-qualification',action='store_true')
    parser.add_argument('--execution-revision',type=Path)
    args=parser.parse_args();root=args.root;runroot=root/'experiment'
    lock=(runroot/'campaign.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    manifest=json.loads((runroot/'manifest.json').read_text())
    for path,digest in manifest['frozen_sha256'].items():
        if sha256(runroot/path)!=digest:raise ValueError('Frozen implementation changed: '+path)
    if args.execution_revision:
        revision=json.loads(args.execution_revision.read_text())
        if revision['base_manifest_sha256']!=sha256(runroot/'manifest.json'):
            raise ValueError('Execution revision refers to another frozen protocol')
        for path,digest in revision['files_sha256'].items():
            if sha256(args.execution_revision.parent/'code'/path)!=digest:
                raise ValueError('Execution revision changed: '+path)
    config=json.loads((runroot/'config.json').read_text());config['response_schema']=engine.ACTION_SCHEMA
    gateway=(GoogleRepair(Path(manifest['shared_ledger_root']),config) if config.get('provider')=='gemini-direct'
             else OpenRouterRepair(Path(manifest['shared_ledger_root']),config,engine.ACTION_SCHEMA))
    namespace=load_authors_classes(runroot/'upstream_logs.py')
    stop=threading.Event();signal.signal(signal.SIGTERM,lambda *_:stop.set());signal.signal(signal.SIGINT,lambda *_:stop.set())
    generate=gateway.generate
    def guarded_generate(*a,**kw):
        if stop.is_set() or (runroot/'STOP').exists():raise RuntimeError('Campaign stop before next model request')
        return generate(*a,**kw)
    gateway.generate=guarded_generate
    cases={};prepared={};known=set();preparing={};repairs={};evaluating={};completed={};repair_results={}
    pending=collections.deque();pending_eval=collections.deque();errors=[];last_report=0
    previous=json.loads((runroot/'status.json').read_text()) if (runroot/'status.json').exists() else {}
    pilot=set(manifest['qualification_case_keys']);qualified=False
    initial=previous.get('initial_budget') or gateway.ledger.summary()
    segment_started=utcnow();started=previous.get('started_utc') or segment_started
    started_clock=time.monotonic();deadline_recorded=False
    def repair_one(case,arm):
        common,history=prepared[case['case_key']]
        return engine.run(case,common,history,arm,gateway,runroot/'cells'/case['case_key']/arm,max_calls=22)
    def evaluate_one(case,arm,repair):
        cell=runroot/'cells'/case['case_key']/arm
        if repair['patch_bytes']:
            result=evaluate(case,cell/'candidate.patch',cell/'evaluation',namespace,runroot/'workers')
            result['evaluation_mode']='fresh_official_tests'
        else:
            result={'score':case['official_baseline_score'],'evaluation_mode':'unchanged_original_exact_source',
                    'patch_sha256':repair['patch_sha256'],'hidden_security_feedback':False}
            write_json(cell/'evaluation/evaluation.json',result)
        joined={'case_key':case['case_key'],'arm':arm,'repair':repair,'evaluation':result}
        write_json(cell/'complete.json',joined);return joined
    def publish(state,force=False):
        nonlocal last_report
        released=(runroot/'RELEASE').exists()
        status={'status':state,'pid':os.getpid(),'started_utc':started,'updated_utc':utcnow(),
                'segment_started_utc':segment_started,'segment_deadline_hours':args.deadline_hours,
                'execution_revision':str(args.execution_revision) if args.execution_revision else None,
                'qualification_passed':qualified,'full_campaign_released':released,
                'ready_cases_seen':len(cases),'input_bundles_ready':len(prepared),
                'total_arms':4,'target_cells':4*len(cases),'repairs_finished':len(repair_results),'evaluations_finished':len(completed),
                'active_inputs':len(preparing),'active_repairs':len(repairs),'active_evaluations':len(evaluating),
                'queued_repairs':len(pending),'queued_evaluations':len(pending_eval),'errors':errors,
                'repair_statuses':dict(collections.Counter(r['status'] for r in repair_results.values())),
                'changed_candidates':sum(r['patch_bytes']>0 for r in repair_results.values()),
                'budget':gateway.ledger.summary(),'initial_budget':initial}
        write_json(runroot/'status.json',status)
        if force or time.monotonic()-last_report>45:
            write_report(root,list(cases.values()),list(completed.values()));last_report=time.monotonic()
    def load_ready():
        path=runroot/'ready.json'
        if not path.exists():return []
        rows=json.loads(path.read_text())
        rows.sort(key=lambda c:(c['case_key'] not in pilot,c['instance_id'],c['generator']))
        return rows
    try:
        with futures.ThreadPoolExecutor(max_workers=4) as ip, futures.ThreadPoolExecutor(max_workers=args.workers) as rp, futures.ThreadPoolExecutor(max_workers=args.eval_workers) as ep:
            while True:
                if (runroot/'STOP').exists():stop.set()
                if time.monotonic()-started_clock>=args.deadline_hours*3600:
                    stop.set()
                    if not deadline_recorded:
                        errors.append({'stage':'campaign','status':'wall_clock_deadline_reached',
                                       'deadline_hours':args.deadline_hours})
                        deadline_recorded=True
                low=shutil.disk_usage(root).free<10**12 or shutil.disk_usage(Path.home()).free<10*10**9
                released=(runroot/'RELEASE').exists()
                if not stop.is_set() and not low:
                    for case in load_ready():
                        key=case['case_key']
                        if key in known:continue
                        if len(preparing)>=4:break
                        case['authors_logs_path']=str(runroot/'upstream_logs.py');cases[key]=case;known.add(key)
                        if not qualified and key not in pilot:continue
                        preparing[ip.submit(inputs.prepare,case,runroot/'inputs'/key)]=key
                    # Cases first seen during pilot are admitted after its gate.
                    if qualified and released:
                        for key in sorted(cases):
                            if len(preparing)>=4:break
                            if key not in prepared and key not in preparing.values():
                                preparing[ip.submit(inputs.prepare,cases[key],runroot/'inputs'/key)]=key
                for future in list(preparing):
                    if not future.done():continue
                    key=preparing.pop(future)
                    try:prepared[key]=future.result()
                    except Exception as exc:
                        errors.append({'stage':'input','case_key':key,'error':str(exc)});stop.set();continue
                    offset=int(key[:2],16)%4
                    for arm in engine.ARMS[offset:]+engine.ARMS[:offset]:
                        joined,repair=existing_cell(runroot/'cells'/key/arm,key,arm)
                        if joined:
                            completed[(key,arm)]=joined;repair_results[(key,arm)]=repair
                        elif repair:
                            repair_results[(key,arm)]=repair;pending_eval.append((key,arm,repair))
                        else:pending.append((key,arm))
                if not stop.is_set() and not low:
                    while pending and len(repairs)<args.workers:
                        key,arm=pending.popleft();repairs[rp.submit(repair_one,cases[key],arm)]=(key,arm)
                # A spending stop must not strand already paid candidates without
                # their free official evaluation. Drain them even while stopped.
                if not low:
                    while pending_eval and len(evaluating)<args.eval_workers:
                        key,arm,repair=pending_eval.popleft();evaluating[ep.submit(evaluate_one,cases[key],arm,repair)]=(key,arm)
                for future in list(repairs):
                    if not future.done():continue
                    key,arm=repairs.pop(future);repair=future.result();repair_results[(key,arm)]=repair
                    pending_eval.append((key,arm,repair))
                for future in list(evaluating):
                    if not future.done():continue
                    key,arm=evaluating.pop(future);completed[(key,arm)]=future.result()
                if not qualified and all((k,a) in completed for k in pilot for a in engine.ARMS):
                    results=[completed[(k,a)] for k in pilot for a in engine.ARMS]
                    bad=qualification_failures(results)
                    qualified=not bad
                    write_json(runroot/'qualification.json',{'passed':qualified,'cells':len(results),'failed_cells':len(bad),
                               'static_first_cells':sum(r['repair']['static_assessments']>0 for r in results),
                               'turn_limit_cells':sum(r['repair']['status']=='turn_limit' for r in results),
                               'failures':bad,
                               'poc_fallback_cells':sum(r['repair']['poc_fallbacks_attempted']>0 for r in results),
                               'criterion':'transport, hypothesis/static-assessment protocol and evaluator availability; security gains are not a gate',
                               'separate_poc_harness_qualification':manifest['poc_harness_qualification'],
                               'updated_utc':utcnow()})
                    if bad:errors.append('Qualification failed; no full paid dispatch');stop.set()
                    elif args.release_after_qualification:
                        write_json(runroot/'RELEASE',{'released_utc':utcnow(),'reason':'Authorized full run; engineering qualification passed',
                                   'qualification_sha256':sha256(runroot/'qualification.json')})
                recent=list(repair_results.values())[-16:]
                if not stop.is_set() and len(recent)==16 and all(r['status']=='repair_error' for r in recent):
                    errors.append('16 consecutive repair errors; spending stopped');stop.set()
                prepstatus=json.loads((root/'prep/status.json').read_text()) if (root/'prep/status.json').exists() else {}
                state=('stopping' if stop.is_set() else 'paused_low_disk' if low else
                       'running' if qualified and released else 'qualified_waiting_release' if qualified else 'qualifying')
                publish(state)
                if stop.is_set() and not preparing and not repairs and not evaluating and not pending_eval:break
                if qualified and prepstatus.get('status') in {'completed','failed','stopped'} and not any([preparing,repairs,evaluating,pending,pending_eval]):
                    if len(known)==len(load_ready()) and len(completed)==4*len(cases):break
                time.sleep(2)
        publish('stopped' if stop.is_set() else 'completed',True)
    except BaseException as exc:
        stop.set();errors.append({'type':type(exc).__name__,'error':str(exc),'traceback':traceback.format_exc()})
        publish('failed',True);raise

if __name__=='__main__':main()
