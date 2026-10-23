"""All-condition rerun after two evaluator-oracle corrections.

The changes relax undocumented representation/iterator-consumption requirements.
No security assertion, prompt, starting repair, budget, or arm is changed.
Every affected condition is rerun; all original responses remain archived.
"""
from concurrent.futures import ThreadPoolExecutor,as_completed
import json
from pathlib import Path
import random
import shutil

from paper.rq5_factorial import run as base
from security_ground_truth.runtime.common import write_json,sha256,utcnow

ORIGINAL=base.ROOT
ROOT=ORIGINAL.with_name('rq5_independent_biology_oracle_audit_v2')
AFFECTED={'rfdiffusion_checkpoint__A','rfdiffusion_checkpoint__B','dockq_handle_lifecycle__A'}

LAZY_CHECK=r'''
def feature_dockq_handle_lifecycle(m, td):
    import dockq_parsers
    p=Path(td)/'models.pdb';p.write_text(multi_pdb());parsed=[]
    real_pdb=dockq_parsers.PDBParser;real_cif=dockq_parsers.MMCIFParser
    class TrackedPDB(real_pdb):
        def get_structure(self,*args,**kwargs):
            parsed.append(kwargs.get('model_number',0));return super().get_structure(*args,**kwargs)
    class TrackedCIF(real_cif):
        def get_structure(self,*args,**kwargs):
            parsed.append(kwargs.get('model_number',0));return super().get_structure(*args,**kwargs)
    dockq_parsers.PDBParser=TrackedPDB;dockq_parsers.MMCIFParser=TrackedCIF
    m.PDBParser=TrackedPDB;m.MMCIFParser=TrackedCIF
    try:
        result=m.load_PDB(str(p),model_numbers=iter([0,1]))
        assert iter(result) is result and not parsed, 'model_numbers must return an iterator without eager parsing'
        first=next(result)
        assert parsed and all(n==0 for n in parsed), 'a later model was parsed before being requested'
        assert first.id==str(p) and len(list(first.get_atoms()))==1
        second=next(result)
        assert 1 in parsed and second.id==str(p) and len(list(second.get_atoms()))==1
        try:next(result)
        except StopIteration:pass
        else:raise AssertionError('unexpected extra model')
    finally:
        dockq_parsers.PDBParser=real_pdb;dockq_parsers.MMCIFParser=real_cif
'''

def corrected_feature(case,text):
    if case['id']=='rfdiffusion_checkpoint__A':
        old="assert isinstance(obj.ckpt['config'],argparse.Namespace) and obj.ckpt['config'].span==slice(1,4), 'legacy Namespace config not preserved'"
        new="config=obj.ckpt['config']\n    assert isinstance(config,(argparse.Namespace,dict)) and (config.span if isinstance(config,argparse.Namespace) else config.get('span'))==slice(1,4), 'legacy config values not preserved'"
        assert old in text;return text.replace(old,new)
    if case['id']=='rfdiffusion_checkpoint__B':
        old="assert torch.equal(obj.ckpt['model_state_dict']['w'],torch.tensor([1.,2.])) and obj.ckpt['config'].span==slice(1,4)"
        new="config=obj.ckpt['config']\n    assert torch.equal(obj.ckpt['model_state_dict']['w'],torch.tensor([1.,2.])) and isinstance(config,(argparse.Namespace,dict)) and (config.span if isinstance(config,argparse.Namespace) else config.get('span'))==slice(1,4)"
        assert old in text;return text.replace(old,new)
    marker="\nm=module('/repo/candidate.py')"
    assert marker in text;return text.replace(marker,LAZY_CHECK+marker)

def prepare():
    if (ROOT/'manifest.json').exists():return base.read(ROOT/'manifest.json')
    manifest=base.read(ORIGINAL/'manifest.json')
    cases=[c for c in manifest['cases'] if c['id'] in AFFECTED]
    for case in cases:
        source=ORIGINAL/'cases'/case['id'];dest=ROOT/'cases'/case['id'];dest.mkdir(parents=True,exist_ok=True)
        for p in source.iterdir():
            if p.is_file():shutil.copy2(p,dest/p.name)
        for name in ('silent','reference','mutant'):base.prior.copy_tree(source/name,dest/name)
        (dest/'feature.py').write_text(corrected_feature(case,(dest/'feature.py').read_text()))
        # Source, ordinary and security oracles are byte-identical.
        for name in ('starting_code.py','memory.json','functional.py','saved_security.py','extended_security.py'):
            assert sha256(source/name)==sha256(dest/name)
    manifest.update(cases=cases,tasks=3,repositories=2,utc=utcnow(),protocol_version='oracle-audit-v2',
        original_study=str(ORIGINAL),affected_cells=12,shared_budget_scope=ORIGINAL.name,
        correction='Accept either Namespace or dict retaining config values; measure actual parser calls rather than consuming model-number input. No source, prompt, memory, security oracle or retry budget change.',
        all_affected_conditions_rerun=True,old_results_retained=True,audit_script_sha256=sha256(Path(__file__)))
    write_json(ROOT/'manifest.json',manifest);return manifest

def qualify(case):
    folder=base.case_dir(case);result=folder/'qualification/result.json'
    if result.exists():return base.read(result)
    previous=base.read(ORIGINAL/'cases'/case['id']/'qualification/result.json')
    assert previous['qualified']
    current={kind:base.local(case,folder/('silent' if kind=='start' else kind),'feature',folder/'qualification'/kind) for kind in ('start','reference','mutant')}
    ok=current['start']['status']!='pass' and all(current[k]['status']=='pass' for k in ('reference','mutant'))
    row={'case_id':case['id'],'qualified':ok,'new_feature_controls':current,
         'unchanged_ordinary_and_security_controls':previous,'utc':utcnow()}
    write_json(result,row);return row

def main():
    obj=base.gateway() # Reuse the original $10 scope, not a fresh budget.
    base.ROOT=ROOT
    manifest=prepare()
    with ThreadPoolExecutor(max_workers=4) as pool:quals=list(pool.map(qualify,manifest['cases']))
    write_json(ROOT/'QUALIFICATION.json',{'cases':quals,'utc':utcnow()})
    print(json.dumps({'qualified':sum(q['qualified'] for q in quals),'total':3}),flush=True)
    assert all(q['qualified'] for q in quals),'No generation before corrected controls qualify'
    base.freeze(manifest)
    queue=[(c,a) for c in manifest['cases'] for a in base.ARMS];random.Random(20261024).shuffle(queue)
    if not (ROOT/'LAUNCH.json').exists():write_json(ROOT/'LAUNCH.json',{'utc':utcnow(),'queue':[(c['id'],a) for c,a in queue],
        'audit_script_sha256':sha256(Path(__file__)),'freeze_sha256':sha256(ROOT/'FREEZE.json')})
    rows=[];errors=[]
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures={pool.submit(base.run_cell,c,a,obj.complete):(c['id'],a) for c,a in queue}
        for f in as_completed(futures):
            try:rows.append(f.result())
            except Exception as exc:
                cid,arm=futures[f];row={'case_id':cid,'arm':arm,'error_type':type(exc).__name__,'error':str(exc),'utc':utcnow()}
                write_json(ROOT/'continuations'/cid/arm/'infrastructure_error.json',row);errors.append(row);print(json.dumps(row),flush=True)
    write_json(ROOT/'RESULTS.json',{'records':rows,'errors':errors,'status':'completed' if len(rows)==12 else 'incomplete',
        'utc':utcnow(),'ledger':obj.ledger.scope_summary(),'manifest_sha256':sha256(ROOT/'manifest.json')})
    print(json.dumps({'completed_cells':len(rows),'errors':errors}),flush=True)

if __name__=='__main__':main()
