"""Behavioral controls for false attribution and bounded source-write discovery."""
import unittest
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

from ghost_analysis.helper_ast import analyze
from ghost_analysis.discover_helpers import invocations, literal_creation_before_invocation, snapshot_ref
from ghost_analysis.structure import sha


class WriteAnalysisTests(unittest.TestCase):
    def test_read_replace_write_tracks_origins(self):
        r = analyze("p='pkg/a.py'\nwith open(p) as f:\n s=f.read()\ns=s.replace('a','b')\nwith open(p,'w') as f:\n f.write(s)\n")
        self.assertEqual(r['effects'][0]['paths'], ['pkg/a.py'])
        self.assertEqual(r['effects'][0]['reads'], ['pkg/a.py'])
        self.assertIn('replace', r['effects'][0]['operations'])

    def test_shadowed_open_is_not_a_file_handle(self):
        r = analyze("open = fake\nf=open('pkg/a.py','w')\nf.write('hello')")
        self.assertFalse(any(e['paths'] for e in r['effects']))

    def test_read_only_and_string_containing_code_are_not_writers(self):
        r = analyze('s = "open(\'pkg/a.py\', \'w\').write(\'x\')"\nprint(s)\nx=open("pkg/a.py").read()')
        self.assertEqual(r['effects'], [])

    def test_deferred_function_and_lambda_are_not_executed(self):
        r = analyze("def f():\n open('a.py','w').write('x')\ng=lambda:open('b.py','w').write('y')")
        self.assertEqual(r['effects'], [])

    def test_direct_function_call_binds_path(self):
        r = analyze("def emit(p):\n open(p,'w').write('x')\nemit('a.py')")
        self.assertEqual(r['effects'][0]['paths'], ['a.py'])
        self.assertTrue(r['effects'][0]['context'])

    def test_path_alias_and_dynamic_path(self):
        r = analyze("from pathlib import Path as P\np=P('pkg')/'a.py'\np.write_text('x')\nopen(get_path(),'w').write('y')")
        self.assertEqual(r['effects'][0]['paths'], ['pkg/a.py'])
        self.assertEqual(r['effects'][1]['paths'], [])

    def test_branch_merge_and_rebinding(self):
        r = analyze("p='a.py'\nif flag:\n p='b.py'\nopen(p,'w').write('x')\np='c.py'\nopen(p,'w').write('y')")
        self.assertEqual(r['effects'][0]['paths'], ['a.py', 'b.py'])
        self.assertEqual(r['effects'][1]['paths'], ['c.py'])

    def test_list_mutation_preserves_read_origin(self):
        r = analyze("lines=open('a.py').readlines()\nlines[1:2]=['x']\nlines.insert(0,'y')\nopen('a.py','w').writelines(lines)")
        e = r['effects'][0]
        self.assertEqual(e['reads'], ['a.py'])
        self.assertIn('subscript_assignment', e['operations'])
        self.assertIn('insert', e['operations'])

    def test_invalid_python_is_unknown(self):
        self.assertIsNotNone(analyze('def broken(')['parse_error'])


class HistoryTests(unittest.TestCase):
    def test_heredoc_mentions_are_not_invocations(self):
        cmd = "cat > a.py <<'EOF'\npython fake.py\nEOF\npython a.py"
        self.assertEqual([c['path'] for c in invocations(cmd)], ['/testbed/a.py'])
        self.assertEqual(invocations('echo "python a.py"\npython -c "python a.py"'), [])

    def test_cd_relative_and_python_options(self):
        calls = invocations('cd /testbed/pkg && python3 -u ../fix.py')
        self.assertEqual(calls[0]['path'], '/testbed/fix.py')
        self.assertEqual(calls[0]['cwd'], '/testbed/pkg')

    def test_exact_literal_before_invocation(self):
        cmd = "cat > a.py << 'EOF'\nprint('x')\nEOF\npython a.py"
        digest = sha("print('x')\n")
        self.assertTrue(literal_creation_before_invocation(cmd, '/testbed/a.py', digest))
        self.assertTrue(literal_creation_before_invocation('cd /testbed && ' + cmd, '/testbed/a.py', digest))
        self.assertFalse(literal_creation_before_invocation(cmd, '/testbed/a.py', sha('other')))
        self.assertFalse(literal_creation_before_invocation(cmd.replace("'EOF'", 'EOF'), '/testbed/a.py', digest))
        self.assertFalse(literal_creation_before_invocation(cmd.replace('python a.py', 'sed -i s/x/y/ a.py\npython a.py'), '/testbed/a.py', digest))
        self.assertFalse(literal_creation_before_invocation('python a.py\n' + cmd, '/testbed/a.py', digest))

    def test_absent_overlay_is_not_absent_base_file(self):
        snap = dict(files={'a.py': None}, tmp_files={})
        self.assertEqual(snapshot_ref(snap, '/testbed/b.py'), 'BASE')
        self.assertIsNone(snapshot_ref(snap, '/testbed/a.py'))
        self.assertIsNone(snapshot_ref(snap, '/tmp/b.py'))


class DiscoveryIntegrationTests(unittest.TestCase):
    def test_archive_discovery_without_nomination_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            batch = root / 'batch'
            inputs = batch / 'inputs/swebench/run'
            inputs.mkdir(parents=True)
            sources = {'writer.py': "s=open('product.py').read()\nopen('product.py','w').write(s.replace('1','2'))\n",
                       'noop.py': "s=open('product.py').read()\nopen('product.py','w').write(s)\n",
                       'data.py': 'payload="open(\'product.py\',\'w\').write(\'bad\')"\n'}
            old, new = 'x=1\n', 'x=2\n'
            blobs = {sha(s): s for s in [*sources.values(), old, new]}
            files = {p: sha(s) for p, s in sources.items()}
            snaps = [dict(snapshot_id='initial', files={'product.py': sha(old)}, tmp_files={}),
                     dict(snapshot_id='created', files={**files, 'product.py': sha(old)}, tmp_files={}),
                     dict(snapshot_id='changed', files={**files, 'product.py': sha(new)}, tmp_files={})]
            events = [dict(event_id='create', sequence=1, command='echo recorded_creation', before_snapshot='initial', after_snapshot='created'),
                      dict(event_id='edit', sequence=2, command='python writer.py', exit_code=0, before_snapshot='created', after_snapshot='changed'),
                      dict(event_id='noop', sequence=3, command='python noop.py', exit_code=0, before_snapshot='changed', after_snapshot='changed')]
            def lines(rows):
                return ''.join(json.dumps(r) + '\n' for r in rows)
            (batch/'endpoint_census_final.jsonl').write_text(lines([dict(run_id='run', benchmark='swebench', eligible=True)]))
            (batch/'file_inventory.jsonl').write_text(lines([dict(run_id='run', task='task', path=p,
                final_content_sha256=sha(s), stratum='repository_untracked', nominated=False, origin='deliberately_wrong') for p, s in sources.items()]))
            # There is intentionally no nominations file or oracle data.
            for name, value in [('initial', snaps[0]), ('final', snaps[-1]), ('instance', dict(repo='test/repo', base_commit='base'))]:
                (inputs/(name+'.json')).write_text(json.dumps(value))
            archive = root/'archive.zip'
            with zipfile.ZipFile(archive, 'w') as z:
                for digest, source in blobs.items():
                    z.writestr('ghost_model_families/blobs/'+digest, source)
                z.writestr('ghost_model_families/runs/run/events.jsonl', lines(events))
                z.writestr('ghost_model_families/runs/run/snapshots.jsonl', lines(snaps))
            out = root/'output'
            subprocess.run([sys.executable, str(Path(__file__).parents[1] / 'discover_helpers.py'),
                            '--archive', str(archive), '--batch', str(batch), '--out', str(out)],
                           check=True, capture_output=True, text=True)
            rows = {r['path']:r for r in map(json.loads, (out/'discovery.jsonl').read_text().splitlines())}
            self.assertTrue(rows['writer.py']['detected'])
            self.assertEqual(rows['writer.py']['history_links'][0]['ast_change'], 'changed')
            self.assertTrue(rows['noop.py']['endpoint_static_source_writer'])
            self.assertFalse(rows['noop.py']['detected'])
            self.assertFalse(rows['data.py']['endpoint_static_source_writer'])


if __name__ == '__main__':
    unittest.main()
