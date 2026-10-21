import json
import copy
import unittest

from adapter import build_view, normalize, structural_index
from query import HistoryView
from test_adapter import action, observation, VIEW


class HistoryQueryTests(unittest.TestCase):
    def setUp(self):
        self.normalized = normalize([
            action("str_replace_editor", {"command": "view", "path": "/project/a.py"}, content="First rationale"),
            observation(VIEW),
            action("str_replace_editor", {"command": "str_replace", "path": "/project/a.py",
                                           "old_str": "return x", "new_str": "return validate(x)"}, "t2", "Guard needs validation"),
            observation("The file /project/a.py has been edited.\n     2\t    return validate(x)\n", "t2")], "h")

    def test_rationale_capability_is_enforced(self):
        masked = HistoryView(build_view(self.normalized, rationale=False))
        exposed = HistoryView(build_view(self.normalized, rationale=True))
        a, b = masked.history_for_path("a.py"), exposed.history_for_path("a.py")
        self.assertEqual(a["states"], b["states"])
        self.assertEqual(a["events"], b["events"])
        self.assertEqual(a["rationale"]["events"], [])
        self.assertEqual(len(b["rationale"]["events"]), 2)
        self.assertEqual(masked.rationale_for(["m000000:rationale"])["status"], "masked_by_arm")

    def test_temporal_cutoff_and_call_deltas(self):
        view = HistoryView(build_view(self.normalized, rationale=False))
        old = view.symbol_at("a.py", "f", before_message=1)
        new = view.symbol_at("a.py", "f")
        self.assertNotIn("validate", old["matches"][0]["source"])
        self.assertIn("validate", new["matches"][0]["source"])
        delta = view.changed_edges(old["state_id"], new["state_id"])
        self.assertTrue(delta["continuous_transition"])
        self.assertEqual(delta["added"], [("f", "validate")])
        self.assertFalse(delta["semantic_flow_available"])

    def test_cross_file_and_reverse_deltas_rejected(self):
        view = HistoryView(build_view(self.normalized, rationale=False))
        ids = list(view.states)
        self.assertEqual(view.changed_edges(ids[1], ids[0])["status"], "invalid_temporal_order")
        self.assertEqual(view.changed_edges(ids[0], "missing")["status"], "states_missing_or_different_files")

    def test_poisoned_masked_view_is_rejected(self):
        view = build_view(self.normalized, rationale=True)
        view["arm"] = "B3"
        with self.assertRaises(ValueError):
            HistoryView(view)

    def test_bounded_retrieval_has_identical_b3_b4_history(self):
        masked = HistoryView(build_view(self.normalized, rationale=False))
        exposed = HistoryView(build_view(self.normalized, rationale=True))
        a = masked.relevant_symbol_history("a.py", "f", max_history_chars=1500, max_rationale_chars=20)
        b = exposed.relevant_symbol_history("a.py", "f", max_history_chars=1500, max_rationale_chars=20)
        self.assertEqual(a["history"], b["history"])
        self.assertEqual(a["shared_history_sha256"], b["shared_history_sha256"])
        self.assertEqual(a["rationale"]["events"], [])
        self.assertLessEqual(sum(len(e["text"]) for e in b["rationale"]["events"]), 20)

    def test_b2_has_same_raw_states_without_structural_retrieval(self):
        raw = HistoryView(build_view(self.normalized, rationale=False, arm="B2"))
        structured = HistoryView(build_view(self.normalized, rationale=False))
        self.assertEqual(list(raw.states), list(structured.states))
        self.assertNotIn("structure", next(iter(raw.states.values())))
        self.assertNotIn("structural_delta", next(iter(raw.states.values())))
        result = raw.relevant_symbol_history("a.py", "f")
        self.assertNotIn("symbols", result["history"]["states"][0])
        self.assertEqual(result["rationale"]["events"], [])
        with self.assertRaises(ValueError):
            raw.symbol_at("a.py", "f")

    def test_search_respects_temporal_cutoff(self):
        view = HistoryView(build_view(self.normalized, rationale=False))
        self.assertEqual(view.search("validate", before_message=1)["matches"], [])
        self.assertEqual(len(view.search("validate")["matches"]), 1)

    def test_target_changes_survive_recent_unrelated_edits(self):
        normalized = copy.deepcopy(self.normalized)
        for n in range(3):
            state = copy.deepcopy(normalized['states'][-1])
            state.update(state_id='unrelated-%d' % n, message_index=10 + n,
                         source=state['source'] + '\ndef unrelated%d():\n    return 1\n' % n)
            state['structure'] = structural_index(state['source'], 'a.py')
            normalized['states'].append(state)
        outputs = []
        for arm in ('B2', 'B3', 'B4'):
            view = HistoryView(build_view(normalized, rationale=arm == 'B4', arm=arm))
            result = view.relevant_symbol_history('a.py', 'f', max_states=2, selection='symbol_changes')
            self.assertEqual([s['state_id'] for s in result['history']['states']],
                             [s['state_id'] for s in normalized['states'][:2]])
            self.assertTrue(result['history']['selection']['paired_transition_available'])
            outputs.append(result)
        self.assertEqual(outputs[1]['history'], outputs[2]['history'])
        self.assertNotIn('symbols', outputs[0]['history']['states'][0])

    def test_symbol_change_selection_honors_cutoff_and_missing_symbol(self):
        view = HistoryView(build_view(self.normalized, rationale=False))
        result = view.relevant_symbol_history('a.py', 'f', before_message=1, selection='symbol_changes')
        self.assertEqual(result['history']['selection']['observed_symbol_change_count'], 0)
        self.assertEqual(result['history']['selected_state_count'], 1)
        missing = view.relevant_symbol_history('a.py', 'missing', selection='symbol_changes')
        self.assertFalse(missing['history']['selection']['symbol_observed'])
        self.assertEqual(missing['history']['states'], [])

    def test_partial_edit_requires_exact_qualified_symbol(self):
        normalized = normalize([
            action('str_replace_editor', {'command': 'str_replace', 'path': '/project/a.py',
                                         'old_str': 'class Safe:\n    def run(self):\n        return 1\n',
                                         'new_str': 'class Safe:\n    def run(self):\n        return 2\n'},
                   content='Update the return value'),
            observation('The file /project/a.py has been edited.')], 'fragment')
        outputs = []
        for arm in ('B2', 'B3', 'B4'):
            view = HistoryView(build_view(normalized, rationale=arm == 'B4', arm=arm))
            result = view.relevant_symbol_history('a.py', 'Safe.run', selection='symbol_changes')
            self.assertEqual(result['history']['selection']['explicit_symbol_fragment_edit_count'], 1)
            self.assertEqual(result['history']['states'], [])
            wrong = view.relevant_symbol_history('a.py', 'Other.run', selection='symbol_changes')
            self.assertEqual(wrong['history']['selection']['explicit_symbol_fragment_edit_count'], 0)
            future = view.relevant_symbol_history('a.py', 'Safe.run', before_message=-1, selection='symbol_changes')
            self.assertEqual(future['history']['selection']['explicit_symbol_fragment_edit_count'], 0)
            outputs.append(result)
        self.assertEqual(outputs[1]['history'], outputs[2]['history'])

    def test_multisymbol_edit_does_not_attribute_context_lines_as_changes(self):
        before = 'def f(x):\n    return x\ndef other():\n    return 1\n'
        after = before.replace('return 1', 'return 2')
        normalized = normalize([
            action('str_replace_editor', {'command':'str_replace', 'path':'/project/a.py',
                   'old_str': before, 'new_str': after}, content='Change other'),
            observation('The file /project/a.py has been edited.')], 'multisymbol')
        for arm in ('B2', 'B3', 'B4'):
            view = HistoryView(build_view(normalized, rationale=arm == 'B4', arm=arm))
            unchanged = view.relevant_symbol_history('a.py', 'f', selection='symbol_changes', current_source=after)
            changed = view.relevant_symbol_history('a.py', 'other', selection='symbol_changes', current_source=after)
            self.assertEqual(unchanged['history']['edit_records'], [])
            self.assertEqual(len(changed['history']['edit_records']), 1)

    def test_top_level_symbol_does_not_match_same_named_method(self):
        normalized = copy.deepcopy(self.normalized)
        normalized['edit_records'] = []
        for i, state in enumerate(normalized['states']):
            state['source'] = 'def f(x):\n    return x\nclass Other:\n    def f(self):\n        return %d\n' % i
            state['structure'] = structural_index(state['source'], 'a.py')
        view = HistoryView(build_view(normalized, rationale=False))
        result = view.relevant_symbol_history('a.py', 'f', selection='symbol_changes')
        self.assertEqual(result['history']['selection']['observed_symbol_change_count'], 0)
        self.assertEqual([s['qualified_name'] for s in result['history']['states'][0]['symbols']], ['f'])

    def test_observed_target_does_not_inherit_unrelated_edit_from_same_action(self):
        normalized = copy.deepcopy(self.normalized)
        state = normalized['states'][-1]
        normalized['states'] = [state]
        normalized['edit_records'] = [{'edit_id': 'unrelated-edit', 'path': 'a.py',
            'message_index': state['message_index'], 'action_event_id': state['action_event_id'],
            'observation_event_id': 'o', 'command': 'str_replace', 'success_acknowledged': True,
            'complete_file_state': False, 'rationale_event_ids': [], 'fragments': {'old_str': 'def other():\n    return 1\n',
                                                      'new_str': 'def other():\n    return 2\n'}}]
        for arm in ('B2', 'B3', 'B4'):
            view = HistoryView(build_view(normalized, rationale=arm == 'B4', arm=arm))
            result = view.relevant_symbol_history('a.py', 'f', selection='symbol_changes', current_source=state['source'])
            self.assertTrue(result['history']['selection']['symbol_observed'])
            self.assertEqual(result['history']['edit_records'], [])
            self.assertFalse(result['history']['selection']['paired_transition_available'])

    def test_body_edit_can_be_linked_to_current_class_method_without_inventing_states(self):
        normalized = normalize([
            action('str_replace_editor', {'command': 'str_replace', 'path': '/project/a.py',
                   'old_str': '        return unsafe(value)', 'new_str': '        return safe(value)'},
                   content='Validate the value'),
            observation('The file /project/a.py has been edited.')], 'fragment')
        source = 'class Safe:\n    def run(self, value):\n        return safe(value)\n'
        outputs = []
        for arm in ('B2', 'B3', 'B4'):
            view = HistoryView(build_view(normalized, rationale=arm == 'B4', arm=arm))
            result = view.relevant_symbol_history('a.py', 'Safe.run', selection='symbol_changes', current_source=source)
            self.assertEqual(result['history']['states'], [])
            self.assertEqual(len(result['history']['edit_records']), 1)
            self.assertEqual(result['history']['selection']['current_anchored_edit_count'], 1)
            self.assertFalse(result['history']['selection']['paired_transition_available'])
            outputs.append(result)
        self.assertEqual(outputs[1]['history'], outputs[2]['history'])
        self.assertNotIn('current_source_anchors', outputs[0]['history']['edit_records'][0])
        self.assertEqual(outputs[1]['rationale']['events'], [])
        self.assertEqual(len(outputs[2]['rationale']['events']), 1)
        view = HistoryView(build_view(normalized, rationale=False))
        repeated = source + 'class Other:\n    def run(self, value):\n        return safe(value)\n'
        result = view.relevant_symbol_history('a.py', 'Safe.run', selection='symbol_changes', current_source=repeated)
        self.assertEqual(result['history']['edit_records'], [])
        future = view.relevant_symbol_history('a.py', 'Safe.run', before_message=-1,
                                             selection='symbol_changes', current_source=source)
        self.assertEqual(future['history']['edit_records'], [])


if __name__ == "__main__":
    unittest.main()
