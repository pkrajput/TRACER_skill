"""Synthetic Git-object boundary tests only; no target software is executed."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

from .query import GitHistoryView, safe_git_environment


class GitHistoryBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.work = self.root / 'work'
        self.work.mkdir()
        self.git('init', '--quiet', '-b', 'main')
        self.git('config', 'user.name', 'History Boundary Tests')
        self.git('config', 'user.email', 'history-tests@example.invalid')

    def tearDown(self):
        self.temp.cleanup()

    def git(self, *args, env=None):
        return subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', '-C', str(self.work), *args],
                                       env=env or safe_git_environment(), stderr=subprocess.PIPE).decode().strip()

    def commit(self, message, files=None, *, date=None):
        for name, content in (files or {}).items():
            path = self.work / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        self.git('add', '-A')
        env = safe_git_environment()
        if date:
            env.update(GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=date)
        self.git('commit', '--quiet', '-m', message, env=env)
        return self.git('rev-parse', 'HEAD')

    def view(self, cutoff, arm='B3'):
        bare = self.root / ('cache-'+arm+'.git')
        subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', 'clone', '--bare', '--quiet', str(self.work), str(bare)],
                       check=True, env=safe_git_environment(), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        return GitHistoryView(bare, cutoff, arm)

    def test_ancestry_not_dates_excludes_future_and_unmerged_sibling(self):
        root = self.commit('original', {'a.py': 'def f():\n    return 1\n'})
        self.git('checkout', '--quiet', '-b', 'sibling')
        sibling = self.commit('UNMERGED_SECRET', {'a.py': 'def f():\n    return 22\n'})
        self.git('checkout', '--quiet', 'main')
        cutoff = self.commit('allowed prior change', {'a.py': 'def f():\n    return 2\n'})
        future = self.commit('FUTURE_FIX_SECRET', {'a.py': 'def f():\n    return 999\n'}, date='2000-01-01T00:00:00+0000')
        view = self.view(cutoff)
        for forbidden in (future, sibling, 'HEAD', cutoff[:12]):
            with self.assertRaises(ValueError):
                view.symbol_at('a.py', 'f', commit=forbidden)
            with self.assertRaises(ValueError):
                view.relevant_symbol_history('a.py', before_commit=forbidden)
        result = view.relevant_symbol_history('a.py', 'f', max_states=20)
        self.assertNotIn('SECRET', str(result))
        self.assertNotIn('999', str(result))
        earlier = view.relevant_symbol_history('a.py', 'f', before_commit=root, max_states=20)
        self.assertEqual({row['commit'] for row in earlier['history']['states']}, {root})

    def test_paths_and_symlinks_never_escape_literal_repository_path(self):
        (self.work / 'link.py').symlink_to('/tmp/external_target.py')
        cutoff = self.commit('files', {'a.py': 'raise RuntimeError("SOURCE MUST NOT EXECUTE")\ndef f():\n    return 1\n'})
        view = self.view(cutoff)
        for path in ('../a.py', '/etc/passwd', '/project/../a.py', '.git/config', 'a\x00.py', 'a\\b.py', ':(glob)*', './a.py'):
            with self.assertRaises(ValueError):
                view.relevant_symbol_history(path)
        self.assertEqual(view.symbol_at('/project/a.py', 'f')['status'], 'found')
        symlink = view.relevant_symbol_history('link.py')['history']['states'][0]
        self.assertEqual(symlink['source_status'], 'non_regular_file_not_followed')
        self.assertEqual(symlink['source_fragment'], '')
        literal_glob = view.relevant_symbol_history('*.py')
        self.assertTrue(all(row['source_status'] == 'path_absent' for row in literal_glob['history']['states']))

    def test_ambiguous_rename_is_not_followed_or_joined(self):
        self.commit('two identical originals', {'a.py': 'def f():\n    pass\n', 'b.py': 'def f():\n    pass\n'})
        (self.work / 'a.py').unlink()
        (self.work / 'b.py').unlink()
        cutoff = self.commit('ambiguous move', {'c.py': 'def f():\n    pass\n'})
        view = self.view(cutoff)
        rename = view.rename_candidates(cutoff, 'c.py')
        self.assertEqual(rename['status'], 'ambiguous_exact_blob_rename')
        self.assertEqual(rename['candidates'], ['a.py', 'b.py'])
        self.assertFalse(rename['automatic_follow'])
        history = view.relevant_symbol_history('c.py', max_states=20)['history']
        self.assertEqual([row['commit'] for row in history['states']], [cutoff])
        self.assertEqual(history['lineage']['path_identity_boundary'], cutoff)

    def test_unique_rename_and_recreated_path_start_new_identity(self):
        self.commit('old identity', {'a.py': 'def old():\n    pass\n'})
        self.git('mv', 'a.py', 'renamed.py')
        renamed = self.commit('move')
        cutoff = self.commit('new identity at old path', {'a.py': 'def new():\n    pass\n'})
        view = self.view(cutoff)
        rename = view.rename_candidates(renamed, 'renamed.py')
        self.assertEqual(rename['status'], 'exact_blob_rename_candidate')
        self.assertFalse(rename['automatic_follow'])
        history = view.relevant_symbol_history('a.py', max_states=20)['history']
        self.assertEqual([row['commit'] for row in history['states']], [cutoff])
        self.assertNotIn('def old', str(history))

    def test_arms_share_states_without_inventing_reasoning(self):
        self.commit('raw commit explanation', {'a.py': 'def f(x):\n    return x\n'})
        cutoff = self.commit('add a guard', {'a.py': 'def f(x):\n    if x:\n        return validate(x)\n'})
        raw, structured = self.view(cutoff, 'B2'), self.view(cutoff, 'B3')
        a, b = raw.relevant_symbol_history('a.py', 'f'), structured.relevant_symbol_history('a.py', 'f')
        self.assertEqual(a['selected_state_ids_sha256'], b['selected_state_ids_sha256'])
        self.assertNotIn('symbols', a['history']['states'][0])
        self.assertIn('symbols', b['history']['states'][0])
        self.assertEqual(b['rationale']['status'], 'not_recorded_in_git')
        self.assertEqual(b['rationale']['events'], [])
        with self.assertRaises(ValueError):
            raw.symbol_at('a.py', 'f')
        with self.assertRaises(ValueError):
            structured.relevant_symbol_history('a.py', before_message=4)

    def test_unqualified_symbol_ambiguity_is_explicit(self):
        cutoff = self.commit('two scopes', {'a.py': 'class A:\n    def f(self):\n        pass\nclass B:\n    def f(self):\n        pass\n'})
        view = self.view(cutoff)
        self.assertEqual(view.symbol_at('a.py', 'f')['status'], 'ambiguous_symbol_name')
        self.assertEqual(view.symbol_at('a.py', 'A.f')['status'], 'found')


if __name__ == '__main__':
    unittest.main()
