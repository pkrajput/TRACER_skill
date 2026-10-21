import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from .gumtree import digest, summarize_pair
from .history import agent_history, git_history, build_case_history
from ..runtime.git_history.query import GitHistoryView
from ..runtime.history.adapter import normalize, build_view


class GumTreeTests(unittest.TestCase):
    def test_guard_and_fallback_deltas_come_from_observed_sources(self):
        before='def parse(x):\n    if not x:\n        raise ValueError()\n    return decode(x)\n'
        after='def parse(x):\n    try:\n        return decode(x)\n    except ValueError:\n        return x\n'
        r=summarize_pair(before,after,'app.py','fallback-edit',symbol='parse')
        self.assertEqual(r['guard_deltas']['removed'][0]['condition'],'not x')
        self.assertEqual(r['guard_deltas']['added'],[])
        self.assertIn('return x',r['fallback_deltas']['added'][0]['syntax'])
        unrelated=summarize_pair(before,after,'app.py','fallback-edit',symbol='elsewhere')
        self.assertEqual(unrelated['fallback_deltas']['added'],[])

    def test_parent_tree_action_preserves_its_nested_target_without_fabricating_actions(self):
        before='unchanged = 1\n'
        after=before+'class Builder:\n    def options(self, field):\n        return render(field.help_text)\n'
        for a,b,kind in [(before,after,'insert'),(after,before,'delete')]:
            result=summarize_pair(a,b,'app.py','class-edit',symbol='Builder.options')
            self.assertEqual(result['status'],'ok')
            self.assertTrue(result['operations'])
            parent=next(r for r in result['operations'] if r.get('covered_target_symbol')=='Builder.options')
            self.assertEqual(parent['operation'],kind)
            self.assertEqual(parent['node_type'],'ClassDef')
            self.assertEqual(parent['symbol'],'Builder')
            self.assertIn('render',parent['hint'])
        unrelated=summarize_pair(before,after,'app.py','class-edit',symbol='Builder.missing')
        self.assertEqual(unrelated['operations'],[])

    def test_real_update_of_security_relevant_call(self):
        a = "def load(x):\n    return yaml.load(x)\n"
        b = "def load(x):\n    return yaml.safe_load(x)\n"
        result = summarize_pair(a, b, "app.py", "edit1")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["matcher"]["name"], "GumTree ClassicGumtree")
        self.assertEqual(result["operations"][0]["operation"], "update")
        self.assertIn("safe_load", result["symbol_hints"][0]["hint"])
        self.assertEqual(result["symbol_hints"][0]["symbol"], "load")

    def test_real_move_is_not_delete_plus_insert(self):
        a = "def f():\n    first()\n    second()\n"
        b = "def f():\n    second()\n    first()\n"
        result = summarize_pair(a, b, "app.py", "edit2")
        self.assertEqual([x["operation"] for x in result["operations"]], ["move"])
        self.assertEqual(result["operations"][0]["gumtree_action"], "move-tree")

    def test_insert_delete_and_symbol_filter(self):
        a = "def f(x):\n    return x\n\ndef g(x):\n    return x\n"
        b = "def f(x):\n    if x is None:\n        raise ValueError()\n    return x\n\ndef g(x):\n    return x\n"
        inserted = summarize_pair(a, b, "app.py", "edit3", symbol="f")
        self.assertIn("Insert If", inserted["symbol_hints"][0]["hint"])
        self.assertIn("x is None", inserted["symbol_hints"][0]["hint"])
        deleted = summarize_pair(b, a, "app.py", "edit4", symbol="f")
        self.assertEqual(deleted["operations"][0]["operation"], "delete")
        other = summarize_pair(a, b, "app.py", "edit5", symbol="g")
        self.assertEqual(other["operations"], [])
        self.assertGreater(other["raw_operation_count"], 0)

    def test_syntax_failure_and_whitespace_are_not_fabricated_edits(self):
        self.assertEqual(summarize_pair("def (", "", "x.py", "bad")["status"], "unparseable_or_oversized")
        result = summarize_pair("x = 1\n", "x=1\n", "x.py", "format")
        self.assertEqual(result["raw_operation_count"], 0)

    def test_separate_rationale_and_observed_transition(self):
        def action(args, ident, text):
            return {"role": "assistant", "content": text, "tool_calls": [{"id": ident, "type": "function",
                      "function": {"name": "str_replace_editor", "arguments": json.dumps(args)}}]}
        def observation(text, ident):
            return {"role": "tool", "tool_call_id": ident, "content": text}
        messages = [
            action({"command": "view", "path": "/project/a.py"}, "t1", "Read the parser."),
            observation("Here's the result of running `cat -n` on /project/a.py:\n     1\tdef f(x):\n     2\t    return yaml.load(x)\n", "t1"),
            action({"command": "str_replace", "path": "/project/a.py", "old_str": "yaml.load(x)",
                    "new_str": "yaml.safe_load(x)"}, "t2", "UNIQUE_RATIONALE_MARKER: use the safe parser."),
            observation("The file /project/a.py has been edited.\n     2\t    return yaml.safe_load(x)\n", "t2")]
        view = build_view(normalize(messages, "trace-hash"), rationale=True)
        temporal, rationale = agent_history(view, [{"path": "a.py", "symbol": "f"}])
        self.assertTrue(temporal["records"])
        self.assertNotIn("UNIQUE_RATIONALE_MARKER", json.dumps(temporal))
        self.assertIn("UNIQUE_RATIONALE_MARKER", json.dumps(rationale))
        self.assertTrue(temporal["records"][0]["continuous_transition"])
        self.assertFalse(temporal["archived_commands_executed"])

    def test_git_future_commit_denied_and_masked_history_default_withheld(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work, bare = root / "work", root / "bare.git"
            work.mkdir()
            def git(*args):
                return subprocess.check_output(["git", "-C", str(work), *args], stderr=subprocess.DEVNULL).decode().strip()
            git("init", "--quiet")
            git("config", "user.email", "test@example.invalid")
            git("config", "user.name", "Test")
            (work / "app.py").write_text("def f(x):\n    return old(x)\n")
            git("add", "app.py"); git("commit", "-qm", "first")
            (work / "app.py").write_text("def f(x):\n    return current(x)\n")
            git("commit", "-qam", "reference")
            cutoff = git("rev-parse", "HEAD")
            (work / "app.py").write_text("def f(x):\n    return SECRET_FUTURE_FIX(x)\n")
            git("commit", "-qam", "future")
            future = git("rev-parse", "HEAD")
            subprocess.run(["git", "clone", "--bare", "--quiet", str(work), str(bare)], check=True)
            guarded = GitHistoryView(bare, cutoff)
            with self.assertRaises(ValueError):
                guarded._file(future, "app.py")
            withheld = git_history(bare, cutoff, [{"path": "app.py"}])
            self.assertEqual(withheld["status"], "withheld_pending_masked_reference_leakage_audit")
            allowed = git_history(bare, cutoff, [{"path": "app.py"}], pre_reference_allowed=True)
            self.assertTrue(allowed["records"])
            self.assertNotIn("SECRET_FUTURE_FIX", json.dumps(allowed))
            self.assertTrue(all(r["ancestor_of_cutoff_verified"] for r in allowed["records"]))

    def test_case_manifest_verifies_original_and_view_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            messages = [{"role": "assistant", "content": "Inspect the input validation."}]
            raw = json.dumps(messages).encode()
            (root / "trace.json").write_bytes(raw)
            view = build_view(normalize(messages, digest(raw)), rationale=True)
            (root / "view.json").write_text(json.dumps(view))
            case = {"case_key": "0" * 24, "record_id": "test", "trajectory_path": str(root / "trace.json"),
                    "trajectory_sha256": digest(raw), "history_paths": {"B4": str(root / "view.json")}}
            result = build_case_history(case, [])
            self.assertEqual(result["provenance"]["source_trace_sha256"], digest(raw))
            view["events"][0]["text"] = "INJECTED FUTURE INFORMATION"
            (root / "view.json").write_text(json.dumps(view))
            with self.assertRaisesRegex(ValueError, "differs from"):
                build_case_history(case, [])
            (root / "trace.json").write_text("[]")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                build_case_history(case, [])


if __name__ == "__main__":
    unittest.main()
