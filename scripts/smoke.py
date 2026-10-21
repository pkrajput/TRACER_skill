"""Exercise the installed index, scanner planning, and rationale entry points."""
import difflib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

def main():
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp);repo=root/'repo';repo.mkdir()
        before='def parse_count(value):\n    return int(value)\n'
        after='def parse_count(value):\n    count = int(value)\n    if count < 0:\n        raise ValueError("negative count")\n    return count\n'
        (repo/'app.py').write_text(after)
        patch=''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='a/app.py',tofile='b/app.py'))
        (root/'change.patch').write_text(patch)
        def run(*args):
            subprocess.run([sys.executable,'-m','tracer_skill.cli',*map(str,args)],check=True,capture_output=True,text=True)
        run('index','--source',repo/'app.py','--path','app.py','--output',root/'index.json')
        index=json.loads((root/'index.json').read_text())
        assert index['parse_status']=='parsed'
        assert index['symbols'][0]['qualified_name']=='parse_count'
        assert index['guards'][0]['test_syntax']=='count < 0'
        findings={'results':[{'check_id':'example.count','path':'app.py','start':{'line':2},'end':{'line':2},'extra':{'message':'Review input conversion','severity':'WARNING'}}]}
        (root/'semgrep.json').write_text(json.dumps(findings))
        run('plan','--source',repo,'--patch',root/'change.patch','--semgrep',root/'semgrep.json','--output',root/'plan.json')
        result=json.loads((root/'plan.json').read_text())
        assert result['labels_used'] is False
        assert 'parse_count' in json.dumps(result) and 'example.count' in json.dumps(result)
        (root/'targets.json').write_text(json.dumps([{'path':'app.py','symbol':'parse_count'}]))
        rationale='parse_count should reject negative values because the API requires a nonnegative count.'
        messages=[{'role':'assistant','content':rationale,'tool_calls':[{'id':'edit1','type':'function','function':{'name':'str_replace_editor','arguments':json.dumps({'command':'view','path':'/project/app.py'})}}]}]
        (root/'messages.json').write_text(json.dumps(messages))
        run('prepare-agent','--messages',root/'messages.json','--targets',root/'targets.json','--source',repo,'--rationale-only','--output',root/'agent.json')
        agent=json.loads((root/'agent.json').read_text())
        assert agent['temporal_history']['status']=='not_requested'
        assert rationale in json.dumps(agent['rationale'])
        collision=subprocess.run([sys.executable,'-m','tracer_skill.cli','index','--source',str(repo/'app.py'),'--path','app.py','--output',str(root/'index.json')],capture_output=True)
        assert collision.returncode==2
    print('PASS index, guard extraction, scanner-linked plan, separate rationale, immutable outputs. Model calls 0.')

if __name__=='__main__':main()
