"""Lossless acceptance of the supplied FilePath = Path module alias.

Reuse every affected first response because its model input is unchanged.
Discard no original artifact. Retest all four arms; any newly needed semantic
retry uses corrected execution feedback, never the old adapter error.
"""
import ast
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import shutil

from paper.rq5_factorial import run as base
from security_ground_truth.runtime.common import write_json,sha256,utcnow

ORIGINAL=base.ROOT
ROOT=ORIGINAL.with_name('rq5_independent_biology_alias_audit_v3')
CID='haddock_extract_symlink__A'
original_validator=base.prior.bio.validate_replacement

def validate(code,target):
    tree=ast.parse(code)
    permitted=ast.dump(ast.parse('FilePath = Path').body[0],include_attributes=False)
    tree.body=[node for node in tree.body if not (target=='extract_files_flat' and ast.dump(node,include_attributes=False)==permitted)]
    # This filtered copy is used for validation only. The original response is
    # passed unchanged to component_source and executed with its alias intact.
    return original_validator(ast.unparse(tree),target)

def main():
    obj=base.gateway();base.ROOT=ROOT;base.prior.bio.validate_replacement=validate
    manifest=base.read(ORIGINAL/'manifest.json');case=next(c for c in manifest['cases'] if c['id']==CID)
    source=ORIGINAL/'cases'/CID;folder=ROOT/'cases'/CID
    if not (ROOT/'manifest.json').exists():
        folder.mkdir(parents=True,exist_ok=True)
        for p in source.iterdir():
            if p.is_file():shutil.copy2(p,folder/p.name)
        for name in ('silent','reference','mutant','qualification'):base.prior.copy_tree(source/name,folder/name)
        manifest.update(cases=[case],tasks=1,repositories=1,utc=utcnow(),protocol_version='alias-adapter-audit-v3',
            correction='Allow exactly the supplied FilePath = Path alias during validation. No generated code changes. All four unchanged first responses are replayed; corrected feedback may trigger one fresh retry.',
            original_study=str(ORIGINAL),all_affected_conditions_replayed=True,audit_script_sha256=sha256(Path(__file__)))
        write_json(ROOT/'manifest.json',manifest)
        for arm in base.ARMS:
            old=ORIGINAL/'continuations'/CID/arm/'1';new=ROOT/'continuations'/CID/arm/'1';new.mkdir(parents=True,exist_ok=True)
            for name in ('input.json','started.json','raw_response.json'):
                shutil.copy2(old/name,new/name)
            write_json(new/'REUSED_RESPONSE.json',{'original':str(old),'response_sha256':sha256(old/'raw_response.json'),
                'input_sha256':sha256(old/'input.json'),'reason':'unchanged generation input; only lossless adapter acceptance changed','utc':utcnow()})
    else:manifest=base.read(ROOT/'manifest.json')
    assert base.read(folder/'qualification/result.json')['qualified']
    # Meaningful adapter checks: accept that alias but still reject unrelated
    # assignments, while retaining the original target-function validation.
    validate('FilePath = Path\ndef extract_files_flat(a,b):\n    pass\n','extract_files_flat')
    try:validate('unrelated = 42\ndef extract_files_flat(a,b):\n    pass\n','extract_files_flat')
    except ValueError:pass
    else:raise AssertionError('adapter broadened beyond the supplied alias')
    base.freeze(manifest)
    write_json(ROOT/'LAUNCH.json',{'utc':utcnow(),'audit_script_sha256':sha256(Path(__file__)),
        'freeze_sha256':sha256(ROOT/'FREEZE.json'),'original_first_responses':4})
    with ThreadPoolExecutor(max_workers=4) as pool:rows=list(pool.map(lambda arm:base.run_cell(case,arm,obj.complete),base.ARMS))
    write_json(ROOT/'RESULTS.json',{'utc':utcnow(),'records':rows,'errors':[],'status':'completed',
        'ledger':obj.ledger.scope_summary(),'manifest_sha256':sha256(ROOT/'manifest.json')})

if __name__=='__main__':main()
