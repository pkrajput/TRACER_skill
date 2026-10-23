"""Freeze six retrospective public-invariant checks; retain the archived seventh.

No benchmark security test is read here. Checks derive from the exported repair
notes and edited source, and are qualified before any continuation generation.
"""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import shutil
import subprocess

import paper.anti_overwrite_eval as protocol
from security_ground_truth.runtime.common import write_json, sha256, utcnow

ROOT=Path('/raid/prateek/ghost_code/security_experiments/20261019/anti_overwrite_seven_v2')
ORIGINAL=ROOT.with_name('anti_overwrite_v1')
PREPARED=Path(__file__).resolve().parent/'prepared/cases'
CAMPAIGN=Path('/raid/prateek/ghost_code/security_experiments/20261018/temporal_security_v12')
CHECKS={
'05182088': '''import rsa
public, private = rsa.newkeys(512)
message = b'ordinary local preservation check'
signature = rsa.sign(message, private, 'SHA-256')
assert rsa.verify(message, signature, public) == 'SHA-256'
rejected = False
try: rsa.verify(message, b'\\0' + signature, public)
except rsa.VerificationError: rejected = True
assert rejected, 'leading-zero extension of a valid signature was accepted'
''',
'1bf30356': '''from django.utils.html import strip_tags
assert strip_tags('<b>ordinary</b> &amp; text') == 'ordinary &amp; text'
assert strip_tags('<b>ordinary</b> &amp text') == 'ordinary &amp text', 'unterminated entity was rewritten'
assert strip_tags('<b>ordinary</b> &#65 text') == 'ordinary &#65 text', 'unterminated character reference was rewritten'
''',
'73252669': '''from django.utils.http import is_safe_url
assert is_safe_url('/ordinary/path', host='example.test')
assert is_safe_url('https://example.test/ordinary', host='example.test')
assert not is_safe_url('///outside.test/path', host='example.test'), 'browser-external URL accepted'
assert not is_safe_url('/\\\\outside.test/path', host='example.test'), 'backslash URL accepted'
''',
'637a1ed2': '''from libnmap.process import NmapProcess
ordinary = NmapProcess(targets=['127.0.0.1'], fqp='/bin/true')
assert '127.0.0.1' in ordinary.get_command_line()
for target in ['-sV', '127.0.0.1;ordinary']:
    rejected = False
    try: NmapProcess(targets=[target], fqp='/bin/true')
    except ValueError: rejected = True
    assert rejected, 'invalid target admitted by constructor'
''',
'3f88d142': '''import asyncio
from piccolo.engine.sqlite import SQLiteTransaction
class Connection:
    def __init__(self): self.calls=[]
    async def execute(self, sql): self.calls.append(sql)
async def main():
    obj=SQLiteTransaction.__new__(SQLiteTransaction)
    obj._parent=None; obj.connection=Connection(); obj._savepoint_counter=0
    await obj.savepoint('ordinary_name')
    assert obj.connection.calls == ['SAVEPOINT ordinary_name']
    await obj.savepoint()
    assert obj.connection.calls[-1] == 'SAVEPOINT sp_1'
    prior=len(obj.connection.calls); rejected=False
    try: await obj.savepoint('invalid name')
    except ValueError: rejected=True
    assert rejected and len(obj.connection.calls)==prior, 'invalid identifier reached SQL boundary'
asyncio.run(main())
''',
'957e87a0': '''import ast
from pathlib import Path
from types import SimpleNamespace
from collections import OrderedDict
import django.forms
from django.conf import settings
from django.utils.html import conditional_escape
if not settings.configured: settings.configure(SECRET_KEY='local-check', USE_I18N=False)
# Execute the real class and any private helper definitions at their source
# positions; avoid importing unrelated Wagtail model/database registration.
path=Path('/repo/wagtail/contrib/forms/forms.py')
tree=ast.parse(path.read_text())
nodes=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))
       or isinstance(n,ast.ClassDef) and n.name=='FormBuilder']
scope=globals()
exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),scope)
obj=scope['FormBuilder']([])
field=SimpleNamespace(label='ordinary',help_text='ordinary help',required=True,default_value='')
opts=obj.get_field_options(field)
assert opts['help_text']=='ordinary help' and opts['required'] is True
settings.WAGTAILFORMS_HELP_TEXT_ALLOW_HTML=False
field.help_text='<em>untrusted</em>'
opts=obj.get_field_options(field)
assert str(opts['help_text']) == '&lt;em&gt;untrusted&lt;/em&gt;', 'help text bypassed escaping'
settings.WAGTAILFORMS_HELP_TEXT_ALLOW_HTML=True
assert obj.get_field_options(field)['help_text']=='<em>untrusted</em>'
''',
}


def prepare_one(case_dir, lookup):
    archived=protocol.verify_case(case_dir);case_id=archived['case_id']
    if case_id.startswith('b3c4bd58'):
        return {'case_id':case_id,'reused_root':str(ORIGINAL),
                'status':'qualified','check_origin':'unmodified_investigator_written_saved_probe'}
    dest=ROOT/'prepared/cases'/case_id
    if not dest.exists():shutil.copytree(case_dir,dest)
    case=lookup[archived['case_key']];source=Path(case['source'])
    data=ROOT/'cases'/case_id;data.mkdir(parents=True,exist_ok=True)
    original=data/'original';repaired=data/'repaired'
    if not original.exists():shutil.copytree(source,original)
    if not repaired.exists():
        shutil.copytree(source,repaired)
        subprocess.run(['git','apply','--check',str(dest/'repair.patch')],cwd=repaired,check=True,capture_output=True)
        subprocess.run(['git','apply',str(dest/'repair.patch')],cwd=repaired,check=True,capture_output=True)
    memory=protocol.load(dest/'memory.json');lineage=memory['symbol_lineage'][0]
    target={'path':lineage['path'],'symbol':lineage['symbol']}
    code=CHECKS[case_id[:8]]
    (dest/'saved_check.py').write_text(code)
    selected={'target':target,'sha256':sha256(dest/'saved_check.py'),
              'before_target_sha256':sha256(original/target['path']),
              'repaired_target_sha256':sha256(repaired/target['path']),
              'origin':'researcher_authored_retrospectively_from_public_repair_and_archived_invariant',
              'hidden_benchmark_tests_used':False,'path':'saved_check.py'}
    memory['saved_check']=selected;memory['check_origin']=selected['origin']
    write_json(dest/'memory.json',memory)
    paths=set(archived['artifact_sha256'])|{'saved_check.py'}
    item={**archived,'selected_check':selected,'artifact_sha256':{name:sha256(dest/name) for name in paths}}
    write_json(dest/'case.json',item)
    identity=protocol.load(Path(case['case_path'])/'image_identity.json')
    marker={**case,'source':str(original),'image_id':identity['image_id'],'repair_patch':str(dest/'repair.patch')}
    write_json(data/'repair_applied.json',marker)
    before=protocol.docker_check(dest,original,identity['image_id'],execute=True,timeout=120)
    after=protocol.docker_check(dest,repaired,identity['image_id'],execute=True,timeout=120)
    qualification=protocol.qualify(item,before,after)
    write_json(data/'qualification.json',qualification)
    return {'case_id':case_id,'status':qualification['status'],'check_origin':selected['origin'],
            'before':{k:before.get(k) for k in ['status','target_reached','error','exception_type']},
            'after':{k:after.get(k) for k in ['status','target_reached','error','exception_type']}}


def main():
    ROOT.mkdir(parents=True,exist_ok=True)
    lookup={c['case_key']:c for c in protocol.load(CAMPAIGN/'cases.json')}
    with ThreadPoolExecutor(max_workers=3) as pool:
        rows=list(pool.map(lambda p:prepare_one(p,lookup),sorted(PREPARED.iterdir())))
    result={'created_utc':utcnow(),'cases':rows,'new_model_calls':0,
            'hidden_security_tests_used_to_author_checks':False}
    write_json(ROOT/'QUALIFICATION.json',result);print(json.dumps(result,indent=2))

if __name__=='__main__':main()
