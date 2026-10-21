"""Zero-model-cost full-cohort preparation and qualification."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path
import sqlite3
import types
import time
from unittest.mock import patch

from security_ground_truth.runtime.common import write_json, sha256, utcnow
from . import engine, inputs
from .openrouter_repair import OpenRouterRepair
from .v12_protocol import POLICY, SYSTEM
from .v12_inputs import upgrade,AdmissionError
from .v12_cards import arm_input
from .v11_integrity import case_external_snapshot

PARENT=Path('/raid/prateek/ghost_code/security_experiments/20261017/temporal_security_v2_rationale/experiment')
V11=Path('/raid/prateek/ghost_code/security_experiments/20261018/temporal_security_v11_dev')
DEFAULT=V11.parent/'v12_local_architecture'
LEDGER=Path('/raid/prateek/ghost_code/security_experiments/20261014/investigator/budget.sqlite')


def read(path):return json.loads(Path(path).read_text())


def ledger():
    with sqlite3.connect('file:'+str(LEDGER)+'?mode=ro',uri=True) as db:
        return db.execute('SELECT COUNT(*),SUM(micro_usd) FROM requests').fetchone()


def build(root=DEFAULT, workers=4, retry_failed=False, refresh_only=False):
    root=Path(root);root.mkdir(parents=True,exist_ok=True)
    before=ledger()
    cases=read(PARENT/'ready.json')
    assert len(cases)==391 and len({c['case_key'] for c in cases})==391
    pilot={c['case_key']:c for c in read(V11/'cases.json')}
    # Same baseline/case identities, newest label-blind ten-case preparation.
    cases=[{**c,**pilot.get(c['case_key'],{})} for c in cases]
    config=read(V11/'config.json');config['protocol']=POLICY
    ceiling=OpenRouterRepair.message_limit(types.SimpleNamespace(config=config,response_schema=engine.ACTION_SCHEMA),SYSTEM)-500
    prior=read(root/'qualification.json') if retry_failed and not refresh_only else {}
    rows=[r for r in prior.get('rows',[]) if r['status']=='passed']
    already={r['case_key'] for r in rows}
    base_folder=root/('base_retries/'+str(time.time_ns()) if retry_failed else 'base_inputs')
    def original_cached_inputs(case):
        key=case['case_key']
        candidates=[root/'base_inputs'/key]+[p.parent for p in sorted((root/'base_retries').glob('*/'+key+'/ready.json'),reverse=True)]
        for folder in candidates:
            if not (folder/'ready.json').exists():continue
            metadata=read(folder/'ready.json')
            if (metadata.get('common_sha256')!=sha256(folder/'common.json') or
                    metadata.get('history_sha256')!=sha256(folder/'history.json') or
                    metadata.get('original_patch_sha256')!=sha256(Path(case['case_path'])/'agent_effective.patch') or
                    metadata.get('source_manifest_sha256')!=sha256(Path(case['baseline'])/'source_manifest.json')):
                raise ValueError('Original unabridged preparation cache changed: '+str(folder))
            return read(folder/'common.json'),read(folder/'history.json'),str(folder)
        raise ValueError('Missing original unabridged input cache: '+key)
    def one(case):
        key=case['case_key'];dest=root/'inputs'/key
        try:
            if key in pilot:
                common=read(V11/'inputs'/key/'common.json');history=read(V11/'inputs'/key/'history.json')
                original_input_root=str(V11/'inputs'/key)
            elif refresh_only:
                common,history,original_input_root=original_cached_inputs(case)
            else:
                common,history=inputs.prepare(case,base_folder/key,v12_base=True)
                original_input_root=str(base_folder/key)
            common,history,verified=upgrade(common,history,case,ceiling)
            dest.mkdir(parents=True,exist_ok=True)
            write_json(dest/'common.json',common);write_json(dest/'history.json',history)
            for arm in engine.ARMS:write_json(dest/(arm+'.json'),arm_input(common,history,arm))
            write_json(dest/'ready.json',verified)
            # Separate evaluator-only identity, never added to an arm bundle.
            snapshot_path=root/'external'/f'{key}.json'
            if not refresh_only or not snapshot_path.exists():
                snapshot=case_external_snapshot(case)
                write_json(snapshot_path,snapshot)
            return {'case_key':key,'status':'passed','original_input_root':original_input_root,**verified}
        except AdmissionError as exc:
            return {'case_key':key,'status':'excluded','reason':str(exc),'label_blind':True}
        except Exception as exc:
            return {'case_key':key,'status':'failed','error':type(exc).__name__+': '+str(exc)[:2000]}
    with patch('security_ground_truth.runtime.model_gateway.request_json',side_effect=AssertionError('Paid transport disabled during v12 input preparation')):
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures=[pool.submit(one,c) for c in sorted(cases,key=lambda c:c['case_key'] not in pilot) if c['case_key'] not in already]
            for future in as_completed(futures):
                row=future.result();rows.append(row)
                write_json(root/'progress.json',{'utc':utcnow(),'finished':len(rows),'target':391,'rows':rows})
                print(json.dumps({'finished':len(rows),**row}),flush=True)
    # Refresh cached successful renders with the final context serializer and
    # accurate omission markers. This never recomputes labels or drops cases.
    from .v12_cards import verify_arms
    refreshed=[]
    for row in rows:
        if row['status']!='passed':refreshed.append(row);continue
        dest=root/'inputs'/row['case_key'];common=read(dest/'common.json');history=read(dest/'history.json')
        for group in common.get('current_code_groups',[]):
            if not group.get('source') and not any(p['path']==group['path'] and
                    p['start_line']<=group['start_line'] and p['end_line']>=group['end_line']
                    for p in common['preloaded_source_ranges']):group['source_abbreviated']=True
        verified=verify_arms(common,history,ceiling)
        write_json(dest/'common.json',common)
        for arm in engine.ARMS:write_json(dest/(arm+'.json'),arm_input(common,history,arm))
        write_json(dest/'ready.json',{**read(dest/'ready.json'),**verified})
        refreshed.append({**row,**verified})
    rows=refreshed
    after=ledger();assert before==after,'Ledger changed during zero-cost preparation'
    failed=[r for r in rows if r['status']=='failed']
    excluded=[r for r in rows if r['status']=='excluded']
    if any(r['case_key'] in pilot for r in excluded):failed.extend(excluded)
    admitted={r['case_key'] for r in rows if r['status']=='passed'}
    write_json(root/'cases.json',[c for c in cases if c['case_key'] in admitted])
    write_json(root/'qualification.json',{'utc':utcnow(),'status':'passed' if not failed else 'failed',
        'cases':len(admitted),'input_bundles':4*len(admitted),'expected_cases':391,
        'model_calls':0,'ledger_unchanged':True,'before_ledger':before,'after_ledger':after,
        'packing_ceiling_bytes':ceiling,'initial_target_bytes':min(72000,ceiling-25000),
        'required_headroom_bytes':25000,'rows':rows,'failures':failed,'exclusions':excluded,
        'exclusion_policy':'Primary baseline file Python syntax errors, or no current production-code target after deletions; no security outcomes used'})
    write_json(root/'input_manifest.json',{str(p.relative_to(root)):sha256(p)
        for folder in ('inputs','external') for p in sorted((root/folder).rglob('*.json'))})
    return len(failed)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,default=DEFAULT)
    parser.add_argument('--workers',type=int,default=4)
    parser.add_argument('--retry-failed',action='store_true')
    parser.add_argument('--refresh-only',action='store_true',help='Rebuild all arm views from hashed original source/history caches, without recomputing GumTree')
    args=parser.parse_args();raise SystemExit(bool(build(args.root,args.workers,args.retry_failed,args.refresh_only)))
