"""Offline protocol tests: no model calls and no target-code execution."""
from __future__ import annotations

import copy
import hashlib
import json
import jsonschema
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from . import engine


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


class FakeGateway:
    config = {'model': 'offline-protocol-test'}

    def __init__(self, script):
        self.script = iter(script)
        self.messages = []

    def generate(self, system, messages, *, cell_id):
        self.messages.append(copy.deepcopy(messages))
        answer = next(self.script)
        if isinstance(answer, Exception):
            raise answer
        return {'actions': answer}, 'offline-request-' + str(len(self.messages))


class FakeSandbox:
    def __init__(self, case, output, editor, *, check_feedback=None, functional_feedback=None):
        self.editor = editor
        self.calls = []
        self.check_feedback = check_feedback
        self.functional_feedback = functional_feedback

    def run(self, *, code=None, target_path=None, target_line=None, target_span=None, trace_target=None, functional=False):
        current_hash = digest(self.editor.patch())
        self.calls.append({'functional': functional, 'path': target_path, 'patch_sha256': current_hash})
        if functional:
            feedback = {'status': 'executed', 'functional_result': {'pass': True, 'test_status': 'completed',
                                                                  'terminal_result': {'recognized': True}},
                        'candidate_patch_sha256': current_hash}
            feedback.update(self.functional_feedback or {})
        else:
            feedback = {'status': 'completed', 'source_identity': 'expected_files_match', 'target_reached': True,
                        'observations': [{'property': 'user_input_is_escaped', 'value': True}],
                        'candidate_patch_sha256': current_hash, 'hidden_security_tests_used': False}
            feedback.update(self.check_feedback or {})
        return feedback


def read(path='app.py'):
    return {'action': 'read', 'path': path}


def hypothesis(path='app.py'):
    return {'action': 'hypothesis', 'path': path, 'line': 2,
            'mechanism': 'User input reaches a rendering operation',
            'preconditions': 'An untrusted caller supplies the value',
            'security_property': 'Input is rendered as text rather than markup',
            'history_use': 'None', 'alert_ids': ['scanner-1'] if path == 'app.py' else []}


def check(ident='H001'):
    return {'action': 'check', 'hypothesis_id': ident,
            'python_code': 'tracer_observe("user_input_is_escaped", True)'}


def assess(decision='inconclusive', ident='H001', quote=''):
    return {'action': 'assess', 'hypothesis_id': ident, 'decision': decision,
            'reason': 'The current implementation provides this evidence.', 'evidence_quote': quote}


def edit(path='app.py', old='return value', new='return str(value)'):
    return {'action': 'edit', 'path': path, 'old': old, 'new': new}


FINISH = {'action': 'finish', 'summary': 'Reviewed and repaired the implementation.'}


class EngineProtocolTests(unittest.TestCase):
    def test_optional_rationale_tool_delivers_then_validates_original_excerpt(self):
        from .rationale import build_rationale
        from .test_rationale import view,event
        r=build_rationale(view(event(1,'render should escape untrusted input.')),
                          [{'path':'app.py','symbol':'render'}])
        r['events']=[];r['chars_used']=0;r['retrieval_chars_remaining']=5000
        self.history['rationale']=r
        h=hypothesis();h['rationale_refs']=[{'event_id':'m000001:rationale','quote':'should escape untrusted input',
                'assumption':'Input is escaped','verification_plan':'Read the current return expression'}]
        a=assess('supported',quote='return value')
        a['rationale_checks']=[{'event_id':'m000001:rationale','outcome':'contradicted',
                                'reason':'Current return expression does not escape input'}]
        script=[[read(),{'action':'rationale','path':'app.py','query':'escaping'}],[h],[a,FINISH]]
        result,traj,gateway,out,_=self.execute(script,arm='C2')
        self.assertEqual(result['status'],'finished')
        self.assertEqual(result['rationale_retrieval_calls'],1)
        self.assertNotIn('render should escape',gateway.messages[0][0][1])
        self.assertIn('render should escape',gateway.messages[1][-1][1])
        self.assertEqual(traj[0]['observations'][1]['events'][0]['event_id'],'m000001:rationale')
        self.assertEqual(json.loads((out/'rationale_exposure.json').read_text())['retrieval_calls'],1)
        for arm in ['C0','C1']:
            denied,traj,_,_,_=self.execute(script,arm=arm)
            self.assertEqual(traj[0]['observations'][1]['status'],'invalid_action')
            self.assertEqual(denied['rationale_cited_hypotheses'],0)

    def test_retrieved_excerpt_survives_feedback_bounding_without_false_exposure(self):
        feedback={'events':[{'event_id':'original','text':'A'*1000}],
                  'text_chars_remaining':4000,'status':'retrieved'}
        self.assertEqual(engine.feedback_for_model(feedback,limit=500),feedback)

    def test_rationale_citation_checks_survive_through_fix_note(self):
        from .rationale import build_rationale
        from .test_rationale import view, event
        self.history['rationale']=build_rationale(view(event(1,'render should escape untrusted input.')),
                                                [{'path':'app.py','symbol':'render'}])
        h=hypothesis();h['rationale_refs']=[{'event_id':'m000001:rationale','quote':'should escape untrusted input',
                'assumption':'Input is escaped','verification_plan':'Read the current return expression'}]
        a=assess('supported',quote='return value')
        missing=copy.deepcopy(a)
        a['rationale_checks']=[{'event_id':'m000001:rationale','outcome':'contradicted',
                               'reason':'Current return expression passes value through without escaping'}]
        result,traj,_,out,_=self.execute([[read(),h],[missing],[a,FINISH]],arm='C2')
        self.assertEqual(traj[1]['observations'][0]['status'],'invalid_action')
        self.assertEqual(result['status'],'finished')
        self.assertEqual(result['rationale_cited_hypotheses'],1)
        self.assertEqual(result['rationale_checks_recorded'],1)
        note=json.loads((out/'edit_note.json').read_text())
        self.assertTrue(note['hypotheses']['H001']['rationale_refs'][0]['citation_verified'])
        self.assertEqual(note['assessments'][0]['rationale_checks'][0]['outcome'],'contradicted')

    def test_rationale_cannot_replace_current_source_evidence(self):
        from .rationale import build_rationale
        from .test_rationale import view,event
        self.history['rationale']=build_rationale(view(event(1,'render should escape untrusted input.')),
                                                [{'path':'app.py','symbol':'render'}])
        h=hypothesis();h['rationale_refs']=[{'event_id':'m000001:rationale','quote':'should escape untrusted input',
                'assumption':'Input is escaped','verification_plan':'Inspect the current function'}]
        a=assess('refuted');a['rationale_checks']=[{'event_id':'m000001:rationale','outcome':'supported','reason':'Old text says so'}]
        result,trajectory,_,_,_=self.execute([[read(),h],[a,FINISH]],arm='C3')
        self.assertEqual(trajectory[1]['observations'][0]['status'],'invalid_action')
        self.assertNotEqual(result['status'],'finished')

    def test_native_schema_requires_action_specific_hypothesis_fields(self):
        variants = engine.ACTION_SCHEMA['properties']['actions']['items']['anyOf']
        hypothesis_schema = next(v for v in variants if v['properties']['action']['enum'] == ['hypothesis'])
        self.assertTrue({'mechanism', 'preconditions', 'security_property', 'history_use'} <= set(hypothesis_schema['required']))
        self.assertFalse(any('maxLength' in value for value in hypothesis_schema['properties'].values()
                             if isinstance(value, dict)))
        jsonschema.validate({'actions': [hypothesis()]}, engine.ACTION_SCHEMA)
        incomplete = hypothesis();incomplete.pop('mechanism')
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate({'actions': [incomplete]}, engine.ACTION_SCHEMA)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.baseline = self.root / 'baseline'
        source = self.baseline / 'source'
        source.mkdir(parents=True)
        for name in ['app.py', 'other.py']:
            (source / name).write_text('def render(value):\n    return value\n')
        self.alert = {'alert_id': 'scanner-1', 'tool': 'semgrep', 'rule_id': 'render-rule',
                      'path': 'app.py', 'line': 2, 'message': 'Review the rendering flow', 'gold_label': None}
        (self.baseline / 'alerts.json').write_text(json.dumps([self.alert]))
        (self.baseline / 'source_manifest.json').write_text(json.dumps({'files': []}))
        casepath = self.root / 'evaluator_only'
        casepath.mkdir()
        self.hidden_marker = 'DO_NOT_SEND_EVALUATOR_SECURITY_LABEL_91827'
        (casepath / 'task.json').write_text(json.dumps({'security_patch': self.hidden_marker,
                                                     'cve_id': self.hidden_marker}))
        self.case = {'case_key': 'case', 'baseline': str(self.baseline), 'case_path': str(casepath),
                     'official_baseline_score': {'func_pass': True, 'sec_pass': False, 'hidden': self.hidden_marker},
                     'published_baseline': {'security_property': self.hidden_marker}}
        self.common = {'protocol_revision':'v8-frozen-test','functional_request': 'Render a string supplied by a caller.', 'scanner_alerts': [self.alert],
                       'current_code': {'app.py': (source / 'app.py').read_text()}}
        self.history = {'temporal': {'evidence': 'TEMPORAL_ONLY_8821'},
                        'rationale': {'evidence': 'RATIONALE_ONLY_4482'}}
        self.number = 0

    def execute(self, script, *, arm='C0', check_feedback=None, functional_feedback=None):
        self.number += 1
        output = self.root / ('attempt-' + str(self.number))
        gateway = FakeGateway(script)
        instances = []
        def sandbox_factory(case, out, editor):
            instance = FakeSandbox(case, out, editor, check_feedback=check_feedback,
                                   functional_feedback=functional_feedback)
            instances.append(instance)
            return instance
        with patch.object(engine, 'Sandbox', side_effect=sandbox_factory):
            result = engine.run(self.case, self.common, self.history, arm, gateway, output, max_calls=len(script))
        trajectory = json.loads((output / 'trajectory.json').read_text()) if (output / 'trajectory.json').exists() else []
        return result, trajectory, gateway, output, instances[0]

    def test_four_arms_receive_identical_current_evidence_and_separate_history_components(self):
        payloads = {}
        for arm in engine.ARMS:
            _, _, gateway, output, _ = self.execute(
                [[read(), hypothesis()], [assess('refuted', quote='return value'), FINISH]], arm=arm)
            initial = json.loads(gateway.messages[0][0][1])
            self.assertEqual(initial, json.loads((output / 'input.json').read_text()))
            payloads[arm] = initial
            self.assertEqual({k: v for k, v in initial.items() if k not in ['temporal_history', 'developer_rationale']}, self.common)
            encoded = json.dumps(initial)
            self.assertEqual('TEMPORAL_ONLY_8821' in encoded, arm in ['C1', 'C3'])
            self.assertEqual('RATIONALE_ONLY_4482' in encoded, arm in ['C2', 'C3'])
        self.assertEqual(payloads['C0']['current_code'], payloads['C3']['current_code'])

    def test_initial_payload_excludes_hidden_case_labels_and_reference_patch(self):
        _, _, gateway, _, _ = self.execute(
            [[read(), hypothesis()], [assess('refuted', quote='return value'), FINISH]])
        initial = gateway.messages[0][0][1]
        self.assertNotIn(self.hidden_marker, initial)
        self.assertNotIn('official_baseline_score', initial)
        self.assertNotIn('security_patch', initial)

    def test_edit_requires_supported_assessment_on_same_path(self):
        scripts = [
            [[read(), edit()], [FINISH]],
            [[read(), hypothesis()], [edit(), FINISH]],
            [[read(), hypothesis('other.py')], [assess('supported', quote='return value'), edit(), FINISH]],
        ]
        for script in scripts:
            with self.subTest(script=script):
                result, trajectory, _, _, _ = self.execute(script)
                self.assertEqual(result['patch_bytes'], 0)
                self.assertTrue(any(obs.get('status') == 'invalid_action' for step in trajectory for obs in step['observations']))

    def test_conclusive_static_assessment_requires_exact_current_source_quote(self):
        for quote in ['', 'text that is absent']:
            with self.subTest(quote=quote):
                result, trajectory, _, _, _ = self.execute(
                    [[read(), hypothesis()], [assess('refuted', quote=quote), FINISH]])
                self.assertNotEqual(result['status'], 'finished')
                self.assertTrue(any(obs.get('status') == 'invalid_action'
                                    for step in trajectory for obs in step['observations']))
        valid, _, _, _, _ = self.execute(
            [[read(), hypothesis()], [assess('refuted', quote='return value'), FINISH]])
        self.assertEqual(valid['status'], 'finished')
        self.assertEqual(valid['static_conclusive_assessments'], 1)

    def test_poc_is_allowed_only_after_inconclusive_static_assessment(self):
        invalid, trajectory, _, _, _ = self.execute([[read(), hypothesis()], [check(), FINISH]])
        self.assertEqual(invalid['checks']['check'], 0)
        self.assertTrue(any(obs.get('status') == 'invalid_action'
                            for step in trajectory for obs in step['observations']))
        valid, _, _, _, _ = self.execute(
            [[read(), hypothesis()], [assess(), check()], [assess('refuted'), FINISH]])
        self.assertEqual(valid['status'], 'finished')
        self.assertEqual(valid['poc_fallbacks_attempted'], 1)
        self.assertEqual(valid['dynamic_fallback_assessments'], 1)

    def test_dismissal_accepts_static_refutation_or_valid_dynamic_refutation(self):
        bad_checks = [
            {'target_reached': False},
            {'source_identity': 'source_modified_during_check'},
            {'observations': []},
            {'status': 'tool_execution_error', 'target_reached': False},
        ]
        decision = {'action': 'decision', 'alert_id': 'scanner-1', 'decision': 'dismiss',
                    'reason': 'The observed flow safely escapes the supplied value.'}
        static, _, _, _, _ = self.execute(
            [[read(), hypothesis()], [assess('refuted', quote='return value'), decision, FINISH]])
        self.assertEqual(static['alert_decisions']['scanner-1']['decision'], 'dismiss')
        for feedback in bad_checks:
            with self.subTest(feedback=feedback):
                result, _, _, _, _ = self.execute(
                    [[read(), hypothesis()], [assess(), check()], [assess('refuted'), decision, FINISH]],
                    check_feedback=feedback)
                self.assertNotEqual(result['alert_decisions'].get('scanner-1', {}).get('decision'), 'dismiss')
        valid, _, _, _, _ = self.execute(
            [[read(), hypothesis()], [assess(), check()], [assess('refuted'), decision, FINISH]])
        self.assertEqual(valid['alert_decisions']['scanner-1']['decision'], 'dismiss')

    def test_changed_finish_requires_functional_validation_of_exact_current_patch(self):
        supported = assess('supported', quote='return value')
        post_edit = assess('refuted', quote='return str(value)')
        no_validation = [[read(), hypothesis()], [supported, edit()], [post_edit, FINISH]]
        stale_validation = [[read(), hypothesis()], [supported, edit()],
                            [post_edit, {'action': 'functional'}],
                            [assess('supported', quote='return str(value)'),
                             edit(old='return str(value)', new='return str(value).strip()')],
                            [assess('refuted', quote='return str(value).strip()'), FINISH]]
        wrong_hash = [[read(), hypothesis()], [supported, edit()],
                      [post_edit, {'action': 'functional'}, FINISH]]
        for script, feedback in [(no_validation, None), (stale_validation, None),
                                  (wrong_hash, {'candidate_patch_sha256': digest('different patch')})]:
            with self.subTest(script=script, feedback=feedback):
                result, _, _, output, _ = self.execute(script, functional_feedback=feedback)
                self.assertEqual(result['patch_bytes'], 0)
                self.assertTrue(result['unvalidated_patch_retained_separately'])
                self.assertGreater((output / 'unvalidated_candidate.patch').stat().st_size, 0)
                self.assertNotEqual(result['status'], 'finished')
        valid, _, _, output, sandbox = self.execute(wrong_hash)
        self.assertEqual(valid['status'], 'finished')
        self.assertEqual(sandbox.calls[-1]['patch_sha256'], digest((output / 'candidate.patch').read_text()))
        self.assertEqual((self.baseline / 'source/app.py').read_text(), 'def render(value):\n    return value\n')

    def test_dynamic_check_can_be_repeated_after_edit_and_must_be_reassessed(self):
        script = [[read(), hypothesis()], [assess(), check()], [assess('supported'), edit()],
                  [check()], [assess('refuted'), {'action': 'functional'}, FINISH]]
        result, _, _, _, sandbox = self.execute(script)
        self.assertEqual(result['status'], 'finished')
        self.assertEqual(result['checks']['check'], 2)
        self.assertEqual(len([call for call in sandbox.calls if not call['functional']]), 2)

    def test_duplicate_functional_check_preserves_post_edit_slot_in_every_arm(self):
        script = [[read(), hypothesis(), {'action': 'functional'}],
                  [{'action': 'functional'}],
                  [assess('supported', quote='return value'), edit()],
                  [assess('refuted', quote='return str(value)'), {'action': 'functional'}, FINISH]]
        for arm in engine.ARMS:
            with self.subTest(arm=arm):
                result, trajectory, _, _, sandbox = self.execute(script, arm=arm)
                self.assertEqual(result['status'], 'finished')
                self.assertGreater(result['patch_bytes'], 0)
                calls = [c for c in sandbox.calls if c['functional']]
                self.assertEqual(len(calls), 2)
                self.assertNotEqual(calls[0]['patch_sha256'], calls[1]['patch_sha256'])
                self.assertEqual(result['checks']['functional'], 2)
                self.assertEqual(len(result['public_functional_checks']), 2)
                reused = trajectory[1]['observations'][0]
                self.assertTrue(reused['reused_functional_result'])
                self.assertFalse(reused['functional_budget_consumed'])
                self.assertEqual(reused['functional_execution_index'], 1)

    def test_completed_functional_failure_is_reused_without_becoming_a_pass(self):
        feedback = {'functional_result': {'pass': False, 'test_status': 'completed',
                                         'terminal_result': {'recognized': True}}}
        script = [[read(), hypothesis()], [assess('supported', quote='return value'), edit()],
                  [{'action': 'functional'}], [{'action': 'functional'}],
                  [assess('refuted', quote='return str(value)'), FINISH]]
        result, trajectory, _, output, sandbox = self.execute(script, functional_feedback=feedback)
        self.assertEqual(len([c for c in sandbox.calls if c['functional']]), 1)
        self.assertTrue(trajectory[3]['observations'][0]['reused_functional_result'])
        self.assertFalse(trajectory[3]['observations'][0]['functional_result']['pass'])
        self.assertNotEqual(result['status'], 'finished')
        self.assertEqual(result['patch_bytes'], 0)
        self.assertGreater((output / 'unvalidated_candidate.patch').stat().st_size, 0)

    def test_incomplete_unrecognized_or_wrong_patch_functional_results_are_not_reused(self):
        variants = [
            {'status': 'tool_execution_error'},
            {'functional_result': {'pass': False, 'test_status': 'indeterminate',
                                   'terminal_result': {'recognized': False}}},
            {'functional_result': {'pass': False, 'test_status': 'completed',
                                   'terminal_result': {'recognized': False}}},
            {'functional_result': {'pass': False, 'test_status': 'completed'}},
            {'candidate_patch_sha256': digest('a different patch')},
        ]
        for feedback in variants:
            with self.subTest(feedback=feedback):
                result, trajectory, _, _, sandbox = self.execute(
                    [[{'action': 'functional'}], [{'action': 'functional'}]],
                    functional_feedback=feedback)
                self.assertEqual(len([c for c in sandbox.calls if c['functional']]), 2)
                self.assertEqual(result['checks']['functional'], 2)
                self.assertNotIn('reused_functional_result', trajectory[1]['observations'][0])

    def test_cached_check_metadata_survives_large_output_compaction(self):
        value = {'status': 'executed', 'stdout': 'x' * 30000,
                 'reused_functional_result': True, 'functional_execution_index': 1,
                 'functional_budget_consumed': False}
        bounded = engine.feedback_for_model(value)
        for key in ['reused_functional_result', 'functional_execution_index', 'functional_budget_consumed']:
            self.assertEqual(bounded[key], value[key])

    def test_gateway_failure_preserves_partial_candidate_and_records_error(self):
        result, trajectory, _, output, _ = self.execute([[read(), hypothesis()],
                                                        [assess('supported', quote='return value'), edit()],
                                                        RuntimeError('offline transport failed')])
        self.assertEqual(result['status'], 'repair_error')
        self.assertEqual(result['error']['type'], 'RuntimeError')
        self.assertEqual(result['patch_bytes'], 0)
        self.assertTrue(result['unvalidated_patch_retained_separately'])
        self.assertEqual(len(trajectory), 2)
        self.assertEqual(result, json.loads((output / 'result.json').read_text()))
        self.assertIn('return str(value)', (output / 'unvalidated_candidate.patch').read_text())
        self.assertTrue((output / 'edit_note.json').exists())

    def test_line_citation_auto_binds_current_source_after_edit(self):
        citation = {**assess('supported'), 'evidence_start_line': 2, 'evidence_end_line': 2}
        script = [[read(), hypothesis()], [citation, edit()],
                  [{**citation, 'decision': 'refuted'}],
                  [read(), {**citation, 'decision': 'refuted'}],
                  [{'action': 'functional'}, FINISH]]
        result, trajectory, _, output, _ = self.execute(script)
        self.assertEqual(result['status'], 'finished')
        self.assertEqual(trajectory[2]['observations'][0]['citation']['binding_owner'], 'harness')
        self.assertIn('return str(value)', trajectory[2]['observations'][0]['evidence_quote'])
        rows = json.loads((output / 'assessments.json').read_text())
        self.assertEqual(rows[0]['evidence_quote'], '    return value')
        self.assertEqual(rows[-1]['evidence_quote'], '    return str(value)')

    def test_related_edits_can_share_one_supporting_assessment_within_a_batch(self):
        script = [[read(), hypothesis()],
                  [assess('supported', quote='return value'), edit(),
                   edit(old='return str(value)', new='return str(value).strip()')],
                  [assess('refuted', quote='return str(value).strip()'), {'action': 'functional'}, FINISH]]
        result, trajectory, _, _, _ = self.execute(script)
        self.assertEqual(result['status'], 'finished')
        self.assertEqual([o['status'] for o in trajectory[1]['observations'][1:]], ['edited', 'edited'])

    def test_failed_poc_does_not_poison_later_valid_static_assessment(self):
        script = [[read(), hypothesis()], [assess(), check()],
                  [assess('refuted', quote='return value'), FINISH]]
        result, _, _, _, _ = self.execute(script, check_feedback={'target_reached': False})
        self.assertEqual(result['status'], 'finished')
        self.assertEqual(result['dynamic_fallback_assessments'], 0)
        self.assertEqual(result['static_conclusive_assessments'], 1)

    def test_supported_repair_can_be_corrected_in_later_turns_before_final_validation(self):
        script = [[read(), hypothesis()], [assess('supported', quote='return value'), edit()],
                  [assess('refuted', quote='return str(value)')],
                  [edit(old='return str(value)', new='return str(value).strip()')],
                  [assess('refuted', quote='return str(value).strip()'), {'action': 'functional'}, FINISH]]
        result, trajectory, _, _, _ = self.execute(script)
        self.assertEqual(result['status'], 'finished')
        self.assertEqual(trajectory[3]['observations'][0]['status'], 'edited')

    def test_shadowed_observer_is_rejected_before_execution_and_can_be_corrected(self):
        shadowed = {**check(), 'python_code': 'def tracer_observe(name, value):\n    print(name, value)\ntracer_observe("x", True)'}
        script = [[read(), hypothesis()], [assess(), shadowed], [check()], [assess('refuted'), FINISH]]
        result, trajectory, _, _, sandbox = self.execute(script)
        self.assertEqual(result['status'], 'finished')
        self.assertIn('supplied by the harness', trajectory[1]['observations'][1]['error'])
        self.assertEqual(len(sandbox.calls), 1)

    def test_finish_preserves_unassessed_unrelated_hypothesis_as_unresolved(self):
        result, _, _, _, _ = self.execute([[read(), hypothesis(), hypothesis('other.py')],
                                          [assess('refuted', quote='return value'), FINISH]])
        self.assertEqual(result['status'], 'finished')
        self.assertEqual(result['unresolved_hypothesis_ids'], ['H002'])

    def test_protocol_feedback_exposes_remaining_finish_requirements(self):
        _, _, gateway, _, _ = self.execute([[read(), hypothesis()],
                                             [assess('supported', quote='return value'), edit()],
                                             [assess('refuted', quote='return str(value)'), {'action': 'functional'}, FINISH]])
        feedback = json.loads(gateway.messages[2][-1][1])['protocol_state']
        self.assertEqual(feedback['turns_remaining'], 1)
        self.assertIn('H001:reassess_repaired_hypothesis_on_current_candidate', feedback['finish_requirements'])
        self.assertIn('run_passing_functional_validation_on_current_patch_or_revert', feedback['finish_requirements'])

    def test_stale_dismissal_does_not_survive_a_later_candidate_change(self):
        (self.baseline/'source/other.py').write_text('def render(value):\n    return value\ndef consumer(value):\n    result = render(value)\n    return result\n')
        decision = {'action': 'decision', 'alert_id': 'scanner-1', 'decision': 'dismiss', 'reason': 'Reviewed.'}
        supported=assess('supported',ident='H002',quote='return value')
        supported['unseeded_evidence']={'mode':'static_chain','input_trust_boundary':'Untrusted input',
            'path_to_sink':'Return to response renderer','downstream_protections':'No downstream escaping in this fixture',
            'violated_property':'Render input as text','source_anchors':[{'path':'other.py','quote':'return value'}]}
        script = [[read(), hypothesis()], [assess('refuted', quote='return value'), decision],
                  [read('other.py'), hypothesis('other.py')],
                  [supported, edit('other.py')],
                  [assess('refuted', ident='H002', quote='return str(value)'), {'action': 'functional'}, FINISH]]
        result, _, _, _, _ = self.execute(script)
        self.assertEqual(result['status'], 'finished')
        self.assertEqual(result['alert_decisions']['scanner-1']['decision'], 'unresolved')
        self.assertTrue(result['alert_decisions']['scanner-1']['stale_after_candidate_change'])

    def test_large_action_and_feedback_leave_room_for_exact_initial_treatment(self):
        initial = ('user', 'INITIAL_EVIDENCE' + '\\"' * 21000)
        answer = {'actions': [edit(old='x' * 20000, new='y' * 20000)]}
        state = {'hypotheses': [], 'finish_requirements': ['validate_current_patch']}
        exchange = engine.pack_exchange(initial, answer, [{'source': 'line\n' * 10000}], state)
        self.assertLessEqual(len(json.dumps([initial, *exchange]).encode()), 93000)
        self.assertEqual(json.loads(exchange[-1][1])['protocol_state']['finish_requirements'], ['validate_current_patch'])


if __name__ == '__main__':
    unittest.main()
