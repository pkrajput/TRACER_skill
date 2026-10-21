"""Offline regressions for v11 control-flow and evidence mechanics."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from security_ground_truth.repair_check.repair import SourceEditor
from . import engine, unseeded_gate, v10_protocol, v11_cards, v11_inputs, v11_protocol
from . import test_engine as fixtures


def location(path, lo, hi):
    return {'path': path, 'line_range': [lo, hi]}


class V11StaticEvidenceTests(unittest.TestCase):
    def editor(self, source):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / 'a.py').write_text(source)
        editor = SourceEditor(root)
        editor.read_paths.add('a.py')
        digest = hashlib.sha256(source.encode()).hexdigest()
        return editor, {'a.py': [(digest, 1, len(source.splitlines()))]}

    def test_continue_and_break_are_loop_local_rejecting_guards_only_in_v11(self):
        for statement in ['continue', 'break']:
            with self.subTest(statement=statement):
                source = 'def keep(xs):\n    for item in xs:\n        if item.bad:\n            '+statement+'\n    return True\n'
                editor, reads = self.editor(source)
                hypothesis = {'path': 'a.py', 'line': 1, 'target_symbol': {'symbol': 'keep'},
                              'scanner_linked_ids': []}
                assessment = {'decision': 'refuted', 'reason': 'Bad items leave the active loop path.',
                    'static_invariant': {'invariant': 'Bad items are rejected',
                        'enforcement_kind': 'rejecting_guard', 'evidence': location('a.py', 3, 4),
                        'consumer': None, 'coverage_argument': 'The branch skips or terminates processing.'}}
                result = v11_protocol.static_invariant(editor, hypothesis, assessment, reads)
                self.assertEqual(result['enforcement_kind'], 'rejecting_guard')
                with self.assertRaisesRegex(ValueError, 'explicit rejecting guard'):
                    v10_protocol.static_invariant(editor, hypothesis, assessment, reads)

    def test_inconclusive_stale_missing_gap_is_ignored(self):
        editor, reads = self.editor('def f(value):\n    return value\n')
        hypothesis = {'path': 'a.py', 'line': 2, 'target_symbol': {'symbol': 'f'},
                      'scanner_linked_ids': []}
        assessment = {'decision': 'inconclusive', 'reason': 'The API contract still needs review.',
                      'static_invariant': {'enforcement_kind': 'missing_boundary_guard'}}
        self.assertIsNone(v11_protocol.static_invariant(editor, hypothesis, assessment, reads))

    def test_refuted_stale_missing_gap_is_ignored(self):
        editor, reads = self.editor('def f(value):\n    return value\n')
        hypothesis = {'path': 'a.py', 'line': 2, 'target_symbol': {'symbol': 'f'},
                      'scanner_linked_ids': []}
        assessment = {'decision': 'refuted', 'reason': 'The current return is source-bound.',
                      'static_invariant': {'enforcement_kind': 'missing_boundary_guard'}}
        self.assertIsNone(v11_protocol.static_invariant(editor, hypothesis, assessment, reads))

    def test_scanner_linked_property_can_refute_with_stale_gap_object(self):
        source = 'def grouped(item):\n    return item.is_group\n'
        editor, reads = self.editor(source)
        hypothesis = {'path': 'a.py', 'line': 2, 'target_symbol': {'symbol': 'grouped'},
                      'scanner_linked_ids': ['stock-warning']}
        assessment = {'decision': 'refuted',
            'reason': 'is_group is a boolean property, so this is the documented attribute access rather than a missing call.',
            'evidence_start_line': 2, 'evidence_end_line': 2,
            'static_invariant': {'invariant': 'is_group is a property',
                'enforcement_kind': 'missing_boundary_guard', 'evidence': location('a.py', 2, 2),
                'consumer': None, 'coverage_argument': 'The cited expression is property access, not a dangerous sink.'}}
        result = v11_protocol.static_invariant(editor, hypothesis, assessment, reads)
        self.assertEqual(result['enforcement_kind'], 'non_security_construct')
        self.assertEqual(result['construct_kind'], 'attribute_access')
        unlinked = {**hypothesis, 'scanner_linked_ids': []}
        self.assertIsNone(v11_protocol.static_invariant(editor, unlinked, assessment, reads))

    def test_module_import_warning_can_be_source_bound_and_dismissed(self):
        source = 'import xml.dom.pulldom\n\ndef parse(value):\n    return xml.dom.pulldom.parseString(value)\n'
        editor, reads = self.editor(source)
        hypothesis = {'path': 'a.py', 'line': 1, 'target_symbol': None,
                      'scanner_linked_ids': ['stock-warning']}
        assessment = {'decision': 'refuted',
                      'reason': 'The cited line imports a module; it is not itself an XML parsing sink.',
                      'path': 'a.py', 'line_range': [1, 1]}
        result = v11_protocol.static_invariant(editor, hypothesis, assessment, reads)
        self.assertEqual(result['construct_kind'], 'module_import')
        self.assertEqual(result['evidence']['evidence_symbol'], '<module>')

    def test_scanner_linked_safe_api_call_can_be_source_bound(self):
        source = 'def normalized(value):\n    return value.casefold()\n'
        editor, reads = self.editor(source)
        hypothesis = {'path': 'a.py', 'line': 2, 'target_symbol': {'symbol': 'normalized'},
                      'scanner_linked_ids': ['stock-warning']}
        assessment = {'decision': 'refuted',
                      'reason': 'casefold is a normalization API, not the dangerous operation in the warning.',
                      'path': 'a.py', 'line_range': [2, 2]}
        result = v11_protocol.static_invariant(editor, hypothesis, assessment, reads)
        self.assertEqual(result['construct_kind'], 'api_call')
        self.assertEqual(result['enforcement_kind'], 'non_security_construct')

    def test_stock_refutation_must_cite_the_linked_warning_location(self):
        source = ('def mixed(value):\n'
                  '    safe = value.casefold()\n'
                  '    return dangerous(value)\n')
        editor, reads = self.editor(source)
        hypothesis = {'path': 'a.py', 'line': 3, 'target_symbol': {'symbol': 'mixed'},
                      'scanner_linked_ids': ['stock-warning'],
                      'scanner_linked_locations': [{'path': 'a.py', 'line': 3}]}
        assessment = {'decision': 'refuted',
                      'reason': 'The unrelated casefold call is safe.',
                      'path': 'a.py', 'line_range': [2, 2]}
        with self.assertRaisesRegex(ValueError, 'source-bound evidence'):
            v11_protocol.static_invariant(editor, hypothesis, assessment, reads)

    def test_module_import_binds_to_preferred_preloaded_consumer(self):
        source = ('import xml.dom.pulldom\n\n'
                  'def parse(value):\n    return xml.dom.pulldom.parseString(value)\n\n'
                  'def inspect_module():\n    return xml\n')
        bound = v11_protocol.bind_module_import_target(source, 1, ['parse'])
        self.assertEqual(bound['symbol'], 'parse')
        self.assertEqual(bound['binding_reason'], 'module_import_preloaded_consumer')


class V11EngineTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.EngineProtocolTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.configure_preload('def render(value):\n    return value\n', 1, 2, 'render')

    def configure_preload(self, source, lo, hi, symbol):
        (self.f.baseline / 'source/app.py').write_text(source)
        digest = hashlib.sha256(source.encode()).hexdigest()
        self.f.common = {
            'protocol_revision': v11_protocol.POLICY,
            'primary_preloaded_target': {'path': 'app.py', 'symbol': symbol,
                'selection_policy': v11_inputs.PRIMARY_TARGET_POLICY,
                'pattern_matched': True},
            'functional_request': 'Review the changed implementation.',
            'current_code_groups': [], 'change_audit_bases': [],
            'scanner_alerts': [self.f.alert], 'scanner_counts': {},
            'preloaded_source_ranges': [{
                'path': 'app.py', 'symbol': symbol, 'start_line': lo, 'end_line': hi,
                'source': '\n'.join(source.splitlines()[lo-1:hi]), 'source_sha256': digest,
                'relationship': 'selected_target'}],
            'preload_selection': {'selected_targets': 1},
        }

    def test_fourth_preloaded_file_read_is_blocked_until_primary_assessment(self):
        script = [[fixtures.read()], [fixtures.read()], [fixtures.read()], [fixtures.read()], []]
        # Keep actions explicit so the hypothesis and assessment execute in order
        # during one model turn, then demonstrate that the read gate reopens.
        script[4] = [fixtures.hypothesis(), fixtures.assess()]
        script.append([fixtures.read()])
        result, trajectory, *_ = self.f.execute(script)
        self.assertEqual(trajectory[3]['observations'][0]['status'], 'blocked_read_binge')
        self.assertIn('app.py:render', trajectory[3]['observations'][0]['error'])
        self.assertIn('source', trajectory[5]['observations'][0])
        self.assertEqual(result['read_discipline']['executed_read_actions'], 4)
        self.assertEqual(result['read_discipline']['blocked_read_actions'], 1)
        self.assertTrue(result['read_discipline']['primary_target_assessed'])

    def test_read_coaching_uses_declared_primary_instead_of_first_preload(self):
        source = ('def decoy(value):\n    return value\n\n'
                  'def render(value):\n    return value\n')
        self.configure_preload(source, 1, 2, 'decoy')
        digest = hashlib.sha256(source.encode()).hexdigest()
        self.f.common['preloaded_source_ranges'].append({
            'path': 'app.py', 'symbol': 'render', 'start_line': 4, 'end_line': 5,
            'source': 'def render(value):\n    return value', 'source_sha256': digest,
            'relationship': 'selected_target'})
        self.f.common['primary_preloaded_target'].update(symbol='render')
        _, trajectory, *_ = self.f.execute([[fixtures.read()] for _ in range(4)])
        blocked = trajectory[3]['observations'][0]
        self.assertEqual(blocked['status'], 'blocked_read_binge')
        self.assertIn('app.py:render', blocked['error'])

    def test_invalid_declared_primary_is_rejected_before_dispatch(self):
        self.f.common['primary_preloaded_target'].update(symbol='missing')
        with self.assertRaisesRegex(ValueError, 'does not identify exactly one'):
            self.f.execute([[fixtures.read()]])

    def test_first_provider_failure_archives_empty_trajectory(self):
        result, trajectory, _, output, _ = self.f.execute([RuntimeError('provider unavailable')])
        self.assertEqual(result['status'], 'repair_error')
        self.assertEqual(result['model_calls'], 0)
        self.assertEqual(trajectory, [])
        self.assertEqual(json.loads((output / 'trajectory.json').read_text()), [])

    def test_v10_read_behavior_is_unchanged(self):
        self.f.common['protocol_revision'] = 'v10-harness-assisted-probes-preloaded-symbols-ast-cues'
        _, trajectory, *_ = self.f.execute([[fixtures.read()] for _ in range(4)])
        self.assertTrue(all(step['observations'][0].get('status') != 'blocked_read_binge'
                            for step in trajectory))

    def test_engine_normalizes_stock_property_refutation_and_allows_dismissal(self):
        source = 'def render(value):\n    return value.is_group\n'
        self.configure_preload(source, 1, 2, 'render')
        assessment = fixtures.assess('refuted', quote='return value.is_group')
        assessment.update(evidence_start_line=2, evidence_end_line=2,
            static_invariant={'invariant': 'is_group is a property',
                'enforcement_kind': 'missing_boundary_guard', 'evidence': location('app.py', 2, 2),
                'consumer': None, 'coverage_argument': 'This is documented property access, not a sink.'})
        decision = {'action': 'decision', 'alert_id': 'scanner-1', 'decision': 'dismiss',
                    'reason': 'The warning mistakes a property for a call.'}
        result, _, _, output, _ = self.f.execute(
            [[fixtures.hypothesis()], [assessment, decision, fixtures.FINISH]])
        self.assertEqual(result['status'], 'finished')
        self.assertEqual(result['alert_decisions']['scanner-1']['decision'], 'dismiss')
        recorded = json.loads((output / 'assessments.json').read_text())[0]
        self.assertEqual(recorded['static_invariant']['enforcement_kind'], 'non_security_construct')

    def test_module_import_hypothesis_auto_binds_to_preloaded_consumer(self):
        source = 'import xml.dom.pulldom\n\ndef parse(value):\n    return xml.dom.pulldom.parseString(value)\n'
        self.configure_preload(source, 3, 4, 'parse')
        alert = {**self.f.alert, 'line': 1}
        self.f.alert = alert
        self.f.common['scanner_alerts'] = [alert]
        (self.f.baseline / 'alerts.json').write_text(json.dumps([alert]))
        hypothesis = {**fixtures.hypothesis(), 'line': 1}
        _, trajectory, *_ = self.f.execute([[hypothesis]])
        observed = trajectory[0]['observations'][0]
        self.assertEqual(observed['target_symbol']['symbol'], 'parse')
        self.assertEqual(observed['target_binding'], 'module_import_preloaded_consumer')


class V11PostEditGateTests(unittest.TestCase):
    def check(self, *, violated=False, reached=True, record_property=True):
        observations = ([{'property': 'unseeded_property_violated', 'value': violated}]
                        if record_property else [{'property': 'functional_result', 'value': 'ok'}])
        return {'hypothesis_id': 'H001', 'candidate_patch_sha256': 'patch',
                'code_sha256': 'adapted-program', 'purpose': 'post_edit_validation',
                'v11_protocol': True, 'consumer_context_verified': True,
                'probe_use_qualification': {'can_authorize_scanner_negative_edit': reached},
                'feedback': {'status': 'completed', 'source_identity': 'expected_files_match',
                             'target_reached': reached, 'target_identity_resolved': True,
                             'observations': observations}}

    def test_adapted_target_reaching_probe_can_validate_exact_candidate(self):
        gate = {'v11_protocol': True, 'before_check_code_sha256': 'original-program',
                'requires_html_consumer': False}
        self.assertTrue(unseeded_gate.after_control(gate, 'H001', [self.check()], 'patch'))
        self.assertTrue(unseeded_gate.after_control(
            gate, 'H001', [self.check(record_property=False)], 'patch'))
        self.assertFalse(unseeded_gate.after_control(gate, 'H001', [self.check(violated=True)], 'patch'))
        self.assertFalse(unseeded_gate.after_control(gate, 'H001', [self.check(reached=False)], 'patch'))
        self.assertFalse(unseeded_gate.after_control(gate, 'H001', [self.check()], 'other-patch'))

    def test_v10_still_requires_exact_probe_hash(self):
        gate = {'v10_protocol': True, 'before_check_code_sha256': 'original-program',
                'requires_html_consumer': False}
        check = self.check()
        check.pop('v11_protocol')
        check['v10_protocol'] = True
        self.assertFalse(unseeded_gate.after_control(gate, 'H001', [check], 'patch'))


class V11RealInputPrimaryTargetTests(unittest.TestCase):
    V10_INPUTS = Path(
        '/raid/prateek/ghost_code/security_experiments/20261018/'
        'temporal_security_v10_dev/inputs')

    @unittest.skipUnless(V10_INPUTS.exists(), 'local frozen v10 development inputs unavailable')
    def test_four_audited_cases_select_the_source_pattern_target(self):
        expected = {
            '618b26c2953dfbe1b7771184': '_StripTagsParser',
            '0bbe3a754966b259190a1326': 'RestrictingNodeTransformer.visit_Attribute',
            '14de7f39742985306a59335f': 'ParsedQuery.is_select',
            '4419233ae3110daf5a64be70': 'FormBuilder.get_field_options',
            'a1cb4d5ce2edd93a88aa345b': 'SparkJDBCHook._resolve_jdbc_connection',
        }
        for case_key, symbol in expected.items():
            with self.subTest(case_key=case_key):
                root = self.V10_INPUTS / case_key
                common = json.loads((root / 'common.json').read_text())
                history = json.loads((root / 'history.json').read_text())
                upgraded, _, verified = v11_inputs.upgrade(common, history)
                primary = upgraded['primary_preloaded_target']
                self.assertEqual(primary['symbol'], symbol)
                self.assertTrue(primary['pattern_matched'])
                self.assertTrue(verified['primary_preloaded_target_validated'])


if __name__ == '__main__':
    unittest.main()
