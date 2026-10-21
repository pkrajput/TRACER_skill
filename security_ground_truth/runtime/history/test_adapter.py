"""Boundary tests for recorded-history evidence; no target code is executed."""
import json
import unittest

from adapter import (apply_editor, build_view, full_view, normalize, project_path,
                     shared_payload, structural_index)


def action(name, args, ident="t1", content=""):
    return {"role": "assistant", "content": content, "tool_calls": [
        {"id": ident, "function": {"name": name, "arguments": json.dumps(args)}}]}


def observation(text, ident="t1"):
    return {"role": "tool", "tool_call_id": ident, "content": text}


VIEW = "Here's the result of running `cat -n` on /project/a.py:\n     1\tdef f(x):\n     2\t    return x\n"


class RecordedHistoryTests(unittest.TestCase):
    def test_rationale_mask_keeps_identical_actions_and_sources(self):
        messages = [action("str_replace_editor", {"command": "view", "path": "/project/a.py"},
                           content="I expect this guard to reject traversal."), observation(VIEW)]
        normalized = normalize(messages, "raw_hash")
        b3, b4 = build_view(normalized, rationale=False), build_view(normalized, rationale=True)
        self.assertEqual(shared_payload(b3), shared_payload(b4))
        self.assertNotIn("I expect this guard", json.dumps(b3))
        self.assertIn("I expect this guard", json.dumps(b4))
        self.assertNotIn("rationale_links", b3)
        self.assertEqual(normalized["states"][0]["structure"]["symbols"][0]["name"], "f")

    def test_evaluator_feedback_truncates_all_later_rationale_and_actions(self):
        messages = [{"role": "assistant", "content": "Earlier reasoning"},
                    {"role": "tool", "content": "SecPass: false"},
                    action("bash", {"command": "echo secret future fix"}, content="Now I know the label")]
        normalized = normalize(messages, "h")
        self.assertEqual(normalized["cutoff_message"], 1)
        view = build_view(normalized, rationale=True)
        self.assertNotIn("SecPass", json.dumps(view))
        self.assertNotIn("secret future fix", json.dumps(view))
        self.assertNotIn("Now I know", json.dumps(view))

    def test_upstream_history_read_is_excluded_before_its_result(self):
        normalized = normalize([action("bash", {"command": "git show abc123:fix.py"}),
                                observation("hidden future implementation")], "h")
        self.assertEqual(normalized["cutoff_message"], 0)
        self.assertEqual(normalized["events"], [])

    def test_initial_prompt_quoted_history_prohibition_is_not_action(self):
        normalized = normalize([{"role": "user", "content": "Do not run git log or git show."}], "h")
        self.assertEqual(len(normalized["events"]), 1)

    def test_arbitrary_shell_effect_invalidates_source_continuity(self):
        messages = [action("str_replace_editor", {"command": "view", "path": "/project/a.py"}), observation(VIEW),
                    action("bash", {"command": "python arbitrary.py"}, "t2"), observation("done", "t2"),
                    action("str_replace_editor", {"command": "str_replace", "path": "/project/a.py",
                                                  "old_str": "return x", "new_str": "return x + 1"}, "t3"),
                    observation("The file /project/a.py has been edited.\n     2\t    return x + 1\n", "t3")]
        normalized = normalize(messages, "h")
        self.assertEqual(len(normalized["states"]), 1)
        self.assertIn("no_continuous_prior_file_state", [e["reason"] for e in normalized["reconstruction_audit"]])
        self.assertEqual(len(normalized["edit_records"]), 1)
        self.assertFalse(normalized["edit_records"][0]["complete_file_state"])
        self.assertTrue(normalized["edit_records"][0]["success_acknowledged"])

    def test_deterministic_edit_requires_unique_old_and_matching_result(self):
        source = "def f(x):\n    return x\n"
        args = {"command": "str_replace", "old_str": "return x", "new_str": "return x + 1"}
        output = "The file has been edited.\n     2\t    return x + 1\n"
        after, status = apply_editor(source, args, output)
        self.assertEqual(after, "def f(x):\n    return x + 1\n")
        self.assertIn("matching_observed", status)
        self.assertIsNone(apply_editor(source + source, args, output)[0])
        self.assertIsNone(apply_editor(source, args, output.replace("x + 1", "x + 2"))[0])
        self.assertIsNone(apply_editor(source, args, "Error: old_str not found")[0])

    def test_partial_truncated_and_noncontiguous_views_not_full_states(self):
        args = {"command": "view", "path": "/project/a.py"}
        self.assertIsNotNone(full_view(args, VIEW)[0])
        self.assertIsNone(full_view({**args, "view_range": [1, 2]}, VIEW)[0])
        self.assertIsNone(full_view(args, VIEW + "<response clipped>")[0])
        self.assertIsNone(full_view(args, VIEW.replace("2\t", "3\t"))[0])
        self.assertIsNone(full_view({**args, "path": "/project/wrong.py"}, VIEW)[0])

    def test_repeated_tool_ids_pair_latest_preceding_action(self):
        messages = [action("str_replace_editor", {"command": "view", "path": "/project/a.py"}), observation(VIEW),
                    action("str_replace_editor", {"command": "view", "path": "/project/b.py"}), observation(VIEW.replace("a.py", "b.py"))]
        normalized = normalize(messages, "h")
        self.assertEqual([s["path"] for s in normalized["states"]], ["a.py", "b.py"])
        self.assertEqual([s["action_event_id"] for s in normalized["states"]], ["m000000:action:0", "m000002:action:0"])

    def test_cutoff_never_recovers_future_edits(self):
        messages = [action("str_replace_editor", {"command": "view", "path": "/project/a.py"}), observation(VIEW)]
        normalized = normalize(messages, "h", cutoff_message=1)
        self.assertEqual(normalized["states"], [])
        self.assertEqual(len(normalized["exclusions"]), 1)

    def test_path_and_parse_failures_are_explicit(self):
        for path in ("/project/../outside.py", "/tmp/file.py", "relative.py", "/project/a\x00.py"):
            self.assertIsNone(project_path(path))
        self.assertEqual(structural_index("def broken(", "f.py")["parse_status"], "syntax_error")
        structure = structural_index("def f(x):\n    if x:\n        target(x)\n", "f.py")
        self.assertFalse(structure["calls"][0]["resolved"])
        self.assertFalse(structure["semantic_flow_available"])

    def test_unsupported_edit_fragment_stays_a_fragment(self):
        messages = [action("str_replace_editor", {"command": "str_replace", "path": "/project/a.py",
                                                   "old_str": "def f():\n    pass", "new_str": "def f():\n    validate()"},
                           content="We need a validation call"),
                    observation("The file /project/a.py has been edited.\n     8\tdef f():\n     9\t    validate()\n")]
        normalized = normalize(messages, "h")
        self.assertEqual(normalized["states"], [])
        self.assertEqual(len(normalized["edit_records"]), 1)
        b3, b4 = build_view(normalized, rationale=False), build_view(normalized, rationale=True)
        self.assertEqual(shared_payload(b3), shared_payload(b4))
        self.assertNotIn("rationale_event_ids", b3["edit_records"][0])
        self.assertIn("m000000:action:0", b4["rationale_links"])


if __name__ == "__main__":
    unittest.main()
