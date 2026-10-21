"""Finite, frozen v12 pilot followed by conditional four-arm auto-release.

No case can enter the full queue before all four explicit release criteria pass.
The pilot and full stage use one cell directory; exact completed pilot artifacts
are reused in place, not rerun. Budget reservations use the shared atomic ledger.
"""
from __future__ import annotations
import argparse
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
import fcntl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import subprocess
import sys
import threading
import time

from security_ground_truth.runtime.common import clean_env, sha256, utcnow, write_json
from security_ground_truth.repair_check.evaluate import evaluate
from security_ground_truth.repair_check.official_score import load_authors_classes
from . import engine
from .campaign import existing_cell
from .dev_pilot_report import score_cell
from .openrouter_repair import OpenRouterRepair
from .v11_integrity import qualified_code_paths, qualified_code_hashes, validate_case_external_snapshot
from .v12_cards import verify_arms
from .v12_protocol import POLICY
from .prepare_v12 import DEFAULT as INPUTS, PARENT, V11, LEDGER, read

ROOT=V11.parent/'temporal_security_v12'
ARMS=('C0','C1','C2','C3')
PILOT_ARMS=('C0','C3')
GATE_CAP=6000000
TOTAL_CAP=699000000
WAGTAIL='d7d694dafa51f88ef9c1b5f3'


def ledger_total():
    with sqlite3.connect('file:'+str(LEDGER)+'?mode=ro',uri=True) as db:
        cap=db.execute("SELECT value FROM settings WHERE key='cap_micro_usd'").fetchone()[0]
        if cap!=TOTAL_CAP:raise ValueError('Shared study ceiling is not $699')
        return db.execute('SELECT COALESCE(SUM(micro_usd),0) FROM requests').fetchone()[0]


def gate_criteria(rows):
    """Pure release predicate. Missing cells/phases never count as failures/pass."""
    counts={a:sum(r.get('sec_pass') is True for r in rows if r['arm']==a) for a in PILOT_ARMS}
    identities={(r['case_key'],r['arm']) for r in rows}
    complete=(len(rows)==20 and len(identities)==20 and
              {a for _,a in identities}==set(PILOT_ARMS) and
              all((k,a) in identities for k,_ in identities for a in PILOT_ARMS))
    criteria={
        'repair_error_zero':complete and all(r.get('repair_status') in {'finished','turn_limit'} for r in rows),
        'all_40_official_phases_terminal':complete and sum(r.get('terminal_phases',0) for r in rows)==40,
        'wagtail_preserved_both_arms':complete and all(any(r['case_key']==WAGTAIL and r['arm']==a
            and r.get('func_pass') is True and r.get('sec_pass') is True for r in rows) for a in PILOT_ARMS),
        'C3_SecPass_greater_than_C0':complete and counts['C3']>counts['C0']}
    return {'passed':all(criteria.values()),'criteria':criteria,'sec_pass':counts,'cells':len(rows)}


def full_queue(cases, gate, completed):
    if not gate.get('passed') or not all(gate.get('criteria',{}).get(k) is True for k in (
        'repair_error_zero','all_40_official_phases_terminal','wagtail_preserved_both_arms','C3_SecPass_greater_than_C0')):
        return []
    pending=[]
    for case in cases:
        offset=int(case['case_key'][:2],16)%4
        for arm in ARMS[offset:]+ARMS[:offset]:
            if (case['case_key'],arm) not in completed:pending.append((case,arm))
    return pending


def freeze(root=ROOT):
    root=Path(root)
    if root.exists():raise ValueError('Refusing to overwrite a frozen v12 campaign')
    prep=read(INPUTS/'qualification.json')
    local=read(INPUTS/'local_verification.json')
    if (prep['status']!='passed' or prep['expected_cases']!=391
            or prep['cases']+len(prep.get('exclusions',[]))!=391
            or prep['input_bundles']!=4*prep['cases']):
        raise ValueError('The full admitted cohort must pass, with explicit source-only exclusions')
    if local['status']!='passed' or local['model_calls']!=0:
        raise ValueError('Local v12 unit tests and exact-state replay must pass')
    repo=Path(__file__).resolve().parents[2]
    if local['code_sha256']!=qualified_code_hashes(repo):raise ValueError('Code changed after local qualification')
    for name,digest in read(INPUTS/'input_manifest.json').items():
        if sha256(INPUTS/name)!=digest:raise ValueError('Prepared input changed: '+name)
    cases=read(INPUTS/'cases.json');keys=[c['case_key'] for c in read(V11/'cases.json')]
    assert len(cases)==prep['cases'] and len(set(keys))==10 and WAGTAIL in keys
    assert set(keys)<={c['case_key'] for c in cases}
    development=set(read(PARENT.parent/'diagnostic_audit/report/DIAGNOSTIC_REPORT.json')
                    ['known_development_exposure']['development_task_ids'])
    protected=[c for c in read(PARENT/'ready.json') if c['instance_id'] not in development]
    assert len(protected)==142 and len({c['instance_id'] for c in protected})==48
    assert not set(keys)&{c['case_key'] for c in protected}
    root.mkdir(parents=True)
    for path in qualified_code_paths(repo):
        dest=root/'frozen_code'/path.relative_to(repo);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,dest)
    (root/'inputs').mkdir();(root/'external').mkdir()
    for case in cases:
        shutil.copytree(INPUTS/'inputs'/case['case_key'],root/'inputs'/case['case_key'])
        shutil.copy2(INPUTS/'external'/(case['case_key']+'.json'),root/'external'/(case['case_key']+'.json'))
    shutil.copytree(V11/'workers',root/'workers')
    shutil.copy2(V11/'upstream_logs.py',root/'upstream_logs.py')
    for case in cases:
        case['v11_external_input_snapshot']=read(root/'external'/(case['case_key']+'.json'))
        case['authors_logs_path']=str(root/'upstream_logs.py')
        case['v12_stratum']='development_exposed' if case['instance_id'] in development else 'previously_protected'
    config=read(V11/'config.json');config.pop('budget_scope',None)
    config.update(protocol=POLICY,campaign_id=root.name,gross_cap_usd=699,
                  max_context_message_bytes=100000,request_timeout_seconds=240,
                  retry_zero_token_timeout=True,retry_policy='zero_token_deadline_once_only')
    initial=ledger_total()
    write_json(root/'config.json',config);write_json(root/'cases.json',cases)
    write_json(root/'pilot_keys.json',keys)
    write_json(root/'prelaunch_verification.json',local)
    write_json(root/'input_qualification.json',prep)
    write_json(root/'authorization.json',{'source':'User: Fix -> Qualify -> Auto-Release Full Campaign',
        'created_utc':utcnow(),'initial_ledger_micro_usd':initial,'pilot_incremental_cap_micro_usd':GATE_CAP,
        'study_total_cap_micro_usd':TOTAL_CAP,'pilot_cells':20,'pilot_fresh_phases':40,
        'full_cases':len(cases),'full_cells':4*len(cases),'full_arms':list(ARMS),'max_turns':22,
        'original_cohort_cases':391,'source_only_exclusions':prep.get('exclusions',[]),
        'repair_workers':24,'evaluation_workers':12,'pilot_protected_overlap':0,
        'previously_protected_attempts':142,'previously_protected_tasks':48,
        'protected_full_dispatch_authorized_only_after_gate':True,
        'release_criteria':['repair_error_zero','all_40_official_phases_terminal',
                            'wagtail_preserved_both_arms','C3_SecPass_greater_than_C0']})
    # Baseline comparisons are evaluator-only frozen artifacts.
    (root/'report_inputs').mkdir()
    shutil.copy2(V11/'report/V11_DEV_COMPARISON.json',root/'report_inputs/V11_DEV_COMPARISON.json')
    files=[p for p in root.rglob('*') if p.is_file()]
    write_json(root/'manifest.json',{'protocol':POLICY,'created_utc':utcnow(),
        'ledger_root':str(LEDGER.parent),'packing_ceiling_bytes':prep['packing_ceiling_bytes'],
        'frozen_sha256':{str(p.relative_to(root)):sha256(p) for p in files}})
    for path in [*files,root/'manifest.json']:path.chmod(0o444)
    return {'root':str(root),'pilot_cells':20,'conditional_full_cells':4*len(cases),
            'initial_ledger_usd':initial/1e6,'pilot_cap_usd':6,'study_ceiling_usd':699}


def launch(root=ROOT):
    root=Path(root)
    if (root/'launch.json').exists():raise ValueError('Already launched; no implicit paid reroll')
    if ledger_total()!=read(root/'authorization.json')['initial_ledger_micro_usd']:
        raise ValueError('Ledger changed since freeze')
    command=[sys.executable,'-u','-m','security_ground_truth.temporal_security.v12_campaign','run','--root',str(root)]
    with (root/'stdout.log').open('ab',buffering=0) as log:
        proc=subprocess.Popen(command,cwd=root/'frozen_code',env=clean_env(),stdin=subprocess.DEVNULL,
                              stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
    record={'pid':proc.pid,'utc':utcnow(),'detached':True,'command':command,'conditional_release':True}
    write_json(root/'launch.json',record);return record


def cell_row(root,case,arm,namespace):
    cell=root/'cells'/case['case_key']/arm
    if not (cell/'complete.json').exists():return None
    result=read(cell/'result.json')
    if sha256(cell/'candidate.patch')!=result['patch_sha256']:raise ValueError('Candidate changed')
    if read(cell/'input.json')!=read(root/'inputs'/case['case_key']/(arm+'.json')):
        raise ValueError('Runtime arm input differs from freeze')
    score=score_cell(cell,case,namespace)
    if not score:raise ValueError('Missing official score')
    return {'case_key':case['case_key'],'arm':arm,'generator':case.get('model_name',case.get('generator')),
            'stratum':case['v12_stratum'],'repair_status':result['status'],
            'terminal_phases':sum(score['terminal_completed'].values()),
            'func_pass':bool(score['terminal_completed']['func'] and score['score']['func_pass']),
            'sec_pass':bool(all(score['terminal_completed'].values()) and score['score']['sec_pass']),
            'patch_bytes':result['patch_bytes'],'turns':result['model_calls'],
            'error':result.get('error'),'cell':str(cell)}


def reuse_hashes(root,keys):
    return {str(p.relative_to(root)):sha256(p) for k in keys for a in PILOT_ARMS
            for p in sorted((root/'cells'/k/a).rglob('*')) if p.is_file()}


def check_reuse(root,hashes):
    if any(not (root/name).is_file() or sha256(root/name)!=digest for name,digest in hashes.items()):
        raise ValueError('Qualification artifact changed; automatic reuse denied')


def budget_failure(result):
    """Only a ledger rejection stops spending; billing text is not a signal."""
    return (result.get('error') or {}).get('type') == 'BudgetExceeded'


def run(root=ROOT, execution_revision=None):
    root=Path(root);lock=(root/'campaign.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    manifest=read(root/'manifest.json');auth=read(root/'authorization.json')
    for name,digest in manifest['frozen_sha256'].items():
        if sha256(root/name)!=digest:raise ValueError('Frozen v12 artifact changed: '+name)
    revision=None
    if execution_revision:
        execution_revision=Path(execution_revision);revision=read(execution_revision)
        if revision['base_manifest_sha256']!=sha256(root/'manifest.json'):
            raise ValueError('Execution revision belongs to another frozen campaign')
        code=Path(__file__).resolve().parents[2]
        if code!=execution_revision.parent/'code':raise ValueError('Wrong execution directory')
        for name,digest in revision['files_sha256'].items():
            if sha256(code/name)!=digest:raise ValueError('Execution revision changed: '+name)
        check_reuse(root,revision['existing_cell_artifacts_sha256'])
    if auth['study_total_cap_micro_usd']!=TOTAL_CAP:raise ValueError('Wrong budget authorization')
    cases=read(root/'cases.json');keys=read(root/'pilot_keys.json');by_key={c['case_key']:c for c in cases}
    if len(cases)!=auth['full_cases'] or len(keys)!=10:raise ValueError('Wrong cohort')
    config=read(root/'config.json');namespace=load_authors_classes(root/'upstream_logs.py')
    if revision:
        config.update(revision.get('config_overrides',{}))
    stop=threading.Event();signal.signal(signal.SIGTERM,lambda *_:stop.set());signal.signal(signal.SIGINT,lambda *_:stop.set())
    rows={};errors=[];released=False;state='qualifying';gate=None;reused={};started=utcnow()
    if revision:
        gate=read(root/'qualification_gate.json')
        if not gate['passed'] or not (root/'RELEASE.json').exists():raise ValueError('Full stage was never released')
        for c in cases:
            for a in ARMS:
                cell=root/'cells'/c['case_key']/a
                if (cell/'complete.json').exists():rows[(c['case_key'],a)]=cell_row(root,c,a,namespace)
                elif cell.exists():raise ValueError('Unfinished cell needs explicit recovery: '+str(cell))
        if len(rows)!=revision['reused_cells']:raise ValueError('Resume cell count changed')
        if not gate_criteria([rows[(k,a)] for k in keys for a in PILOT_ARMS])['passed']:
            raise ValueError('Recorded qualification no longer passes')
        reused=read(root/'qualification_reuse_manifest.json');check_reuse(root,reused)
        released=True;state='running_full'
    validated=set();validation_locks={c['case_key']:threading.Lock() for c in cases}
    report_dir=root/'report';report_dir.mkdir(exist_ok=True)
    def report():
        from .v12_report import publish
        publish(root,cases,list(rows.values()),state,gate)
    report()
    class ReadOnly(BaseHTTPRequestHandler):
        def do_GET(self):
            name=self.path.split('?')[0].lstrip('/') or 'DIAGNOSTIC_REPORT.md'
            if name not in {'RESULTS.json','DIAGNOSTIC_REPORT.md','V12_DEV_COMPARISON.md'}:
                self.send_error(404);return
            path=report_dir/name
            if not path.is_file():self.send_error(404);return
            data=path.read_bytes();self.send_response(200)
            self.send_header('Content-Type','application/json' if name.endswith('.json') else 'text/plain; charset=utf-8')
            self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),ReadOnly)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    write_json(root/'report_service.json',{'url':'http://127.0.0.1:'+str(server.server_port),
        'read_only':True,'update_seconds':120,'pid':os.getpid()})
    last_report=0
    def gateway_for(stage):
        cfg=dict(config)
        scope_id=(revision.get('scope_id') if revision and stage=='full' else None) or root.name+':'+stage
        with sqlite3.connect('file:'+str(LEDGER)+'?mode=ro',uri=True) as db:
            scope=db.execute('SELECT cap_micro_usd,initial_total_micro_usd FROM budget_scopes WHERE id=?',
                             (scope_id,)).fetchone()
        total=ledger_total()
        cfg['budget_scope']={'id':scope_id,
            'cap_micro_usd':scope[0] if scope else GATE_CAP if stage=='gate' else TOTAL_CAP-total,
            'initial_total_micro_usd':scope[1] if scope else auth['initial_ledger_micro_usd'] if stage=='gate' else total}
        if revision and stage=='full' and revision.get('budget_scope'):
            cfg['budget_scope']=revision['budget_scope']
        gateway=OpenRouterRepair(LEDGER.parent,cfg,engine.ACTION_SCHEMA)
        from security_ground_truth.runtime.rate_limit_retry import RateLimitRetry
        generate=RateLimitRetry(gateway.generate,stopped=lambda:stop.is_set() or (root/'STOP').exists(),
                               retry_transient=bool(config.get('retry_transient_transport')))
        def guarded(*a,**kw):
            if stop.is_set() or (root/'STOP').exists():raise RuntimeError('Campaign stopped before provider request')
            identity=kw.get('cell_id','').split(':')
            if len(identity)!=3 or identity[0]!=root.name or identity[1] not in by_key or identity[2] not in ARMS:
                raise ValueError('Out-of-scope provider request')
            if stage=='gate' and (identity[1] not in keys or identity[2] not in PILOT_ARMS):
                raise ValueError('Full-cohort request before release')
            return generate(*a,**kw)
        gateway.generate=guarded;return gateway
    def execute(queue,stage):
        nonlocal last_report,state
        gateway=gateway_for(stage);pending=deque(queue);repairs={};evals={};pending_eval=deque()
        def repair(case,arm):
            with validation_locks[case['case_key']]:
                if case['case_key'] not in validated:
                    validate_case_external_snapshot(case)
                    validated.add(case['case_key'])
            cell=root/'cells'/case['case_key']/arm
            joined,prior=existing_cell(cell,case['case_key'],arm)
            if prior:return prior
            inp=root/'inputs'/case['case_key']
            return engine.run(case,read(inp/'common.json'),read(inp/'history.json'),arm,gateway,cell,max_calls=22)
        def evaluate_one(case,arm,repair):
            cell=root/'cells'/case['case_key']/arm
            value=evaluate(case,cell/'candidate.patch',cell/'evaluation',namespace,root/'workers')
            value['evaluation_mode']='fresh_official_tests_including_noops'
            write_json(cell/'complete.json',{'case_key':case['case_key'],'arm':arm,'repair':repair,'evaluation':value})
            return cell_row(root,case,arm,namespace)
        with ThreadPoolExecutor(max_workers=8 if stage=='gate' else 24) as rp, ThreadPoolExecutor(max_workers=6 if stage=='gate' else 12) as ep:
            while pending or repairs or evals or pending_eval:
                if (root/'STOP').exists():stop.set()
                if stop.is_set():pending.clear()
                repair_limit=8 if stage=='gate' else 24;eval_limit=6 if stage=='gate' else 12
                while pending and len(repairs)<repair_limit:
                    c,a=pending.popleft();repairs[rp.submit(repair,c,a)]=(c,a)
                while pending_eval and len(evals)<eval_limit:
                    c,a,r=pending_eval.popleft();evals[ep.submit(evaluate_one,c,a,r)]=(c,a)
                for future in list(repairs):
                    if not future.done():continue
                    c,a=repairs.pop(future)
                    try:
                        # An exhausted request fails this attempt, not the
                        # remaining cohort. Preserve/evaluate its last candidate.
                        result=future.result();pending_eval.append((c,a,result))
                        if budget_failure(result):
                            errors.append({'stage':stage,'error':'Shared ledger rejected a budget reservation'})
                            stop.set()
                    except Exception as exc:
                        errors.append({'stage':'repair','case_key':c['case_key'],'arm':a,'error':str(exc)});stop.set()
                for future in list(evals):
                    if not future.done():continue
                    c,a=evals.pop(future)
                    try:rows[(c['case_key'],a)]=future.result()
                    except Exception as exc:errors.append({'stage':'evaluation','case_key':c['case_key'],'arm':a,'error':str(exc)})
                write_json(root/'status.json',{'status':state,'stage':stage,'pid':os.getpid(),'started_utc':started,
                    'updated_utc':utcnow(),'full_campaign_released':released,'target_cells':4*len(cases) if released else 20,
                    'evaluations_finished':len(rows),'official_phases_terminal_completed':sum(r['terminal_phases'] for r in rows.values()),
                    'active_repairs':len(repairs),'active_evaluations':len(evals),'queued_repairs':len(pending),
                    'errors':errors,'execution_revision':str(execution_revision) if revision else None,
                    'reused_completed_cells':revision['reused_cells'] if revision else 0,
                    'stage_budget':gateway.ledger.scope_summary(),
                    'study_budget':gateway.ledger.summary(),'pilot_cells_reused':20 if released else 0})
                if time.monotonic()-last_report>=120:
                    report();last_report=time.monotonic()
                if pending or repairs or evals or pending_eval:time.sleep(2)
        report()
    try:
        if revision:
            execute(full_queue(cases,gate,set(rows)),'full')
            check_reuse(root,revision['existing_cell_artifacts_sha256'])
            state='completed' if len(rows)==4*len(cases) and all(r['terminal_phases']==2 for r in rows.values()) and not errors else 'incomplete'
            return
        execute([(by_key[k],a) for i,k in enumerate(keys) for a in (PILOT_ARMS if i%2==0 else PILOT_ARMS[::-1])],'gate')
        gate=gate_criteria(list(rows.values()))
        gate.update(utc=utcnow(),pilot_keys=keys,protected_overlap=0,errors=list(errors))
        if errors or stop.is_set():gate['passed']=False
        write_json(root/'qualification_gate.json',gate)
        report()
        if not gate['passed']:
            state='qualification_failed';return
        reused=reuse_hashes(root,keys);check_reuse(root,reused)
        write_json(root/'qualification_reuse_manifest.json',reused)
        # Recompute the gate from fresh recognized official outcomes immediately
        # before release; a stale manually edited RELEASE file is not authority.
        fresh=[cell_row(root,by_key[k],a,namespace) for k in keys for a in PILOT_ARMS]
        if not gate_criteria(fresh)['passed']:raise ValueError('Release gate changed')
        released=True;state='running_full'
        write_json(root/'RELEASE.json',{'utc':utcnow(),'gate_sha256':sha256(root/'qualification_gate.json'),
            'reuse_manifest_sha256':sha256(root/'qualification_reuse_manifest.json'),
            'new_cells':4*len(cases)-20,'reused_cells':20,'total_cells':4*len(cases),'study_cap_usd':699})
        execute(full_queue(cases,gate,set(rows)),'full')
        check_reuse(root,reused)
        state='completed' if len(rows)==4*len(cases) and all(r['terminal_phases']==2 for r in rows.values()) and not errors else 'incomplete'
    except BaseException as exc:
        stop.set();state='failed';errors.append({'stage':'controller','error':type(exc).__name__+': '+str(exc)})
        raise
    finally:
        report()
        previous=read(root/'status.json') if (root/'status.json').exists() else {}
        write_json(root/'status.json',{**previous,'status':state,'updated_utc':utcnow(),
            'active_repairs':0,'active_evaluations':0,'errors':errors,'full_campaign_released':released})
        server.shutdown();server.server_close();lock.close()


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('action',choices=['freeze','launch','run']);p.add_argument('--root',type=Path,default=ROOT)
    p.add_argument('--execution-revision',type=Path)
    args=p.parse_args()
    if args.execution_revision and args.action!='run':p.error('Execution revisions apply only to run')
    value=run(args.root,args.execution_revision) if args.action=='run' else {'freeze':freeze,'launch':launch}[args.action](args.root)
    if value is not None:print(json.dumps(value))
