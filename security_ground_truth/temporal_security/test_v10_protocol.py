"""Offline v10 harness and evidence regressions. No provider calls."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from security_ground_truth.repair_check.repair import SourceEditor
from . import engine, unseeded_gate, v10_cards, v10_protocol
from . import test_engine as fixtures


def location(path, lo, hi):
    return {'path': path, 'line_range': [lo, hi]}


class V10EngineTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.EngineProtocolTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        source = (self.f.baseline / 'source/app.py').read_text()
        digest = hashlib.sha256(source.encode()).hexdigest()
        self.f.common = {
            'protocol_revision': v10_cards.POLICY,
            'functional_request': 'Render caller data.',
            'current_code_groups': [], 'change_audit_bases': [],
            'scanner_alerts': [self.f.alert], 'scanner_counts': {},
            'preloaded_source_ranges': [{
                'path': 'app.py', 'symbol': 'render', 'start_line': 1, 'end_line': 2,
                'source': source.rstrip('\n'), 'source_sha256': digest,
                'relationship': 'selected_target'}],
            'preload_selection': {'selected_targets': 1},
        }

    def test_normal_probe_executes_without_reserved_names_or_phases(self):
        normal = {'action': 'check', 'hypothesis_id': 'H001',
                  'python_code': 'value = 1\nprint(value)'}
        result, trajectory, _, _, sandbox = self.f.execute(
            [[fixtures.hypothesis()], [fixtures.assess(), normal]])
        self.assertEqual(result['checks']['check'], 1)
        self.assertEqual(len(sandbox.calls), 1)
        self.assertNotEqual(trajectory[1]['observations'][1].get('status'), 'invalid_action')

    def test_shadowed_harness_names_execute_but_cannot_qualify_evidence(self):
        code = ('def tracer_observe(name, value):\n    return None\n'
                'def tracer_phase(name):\n    return None\n'
                'tracer_observe("unseeded_property_violated", True)')
        action = {'action': 'check', 'hypothesis_id': 'H001', 'python_code': code}
        _, trajectory, _, output, sandbox = self.f.execute(
            [[fixtures.hypothesis()], [fixtures.assess(), action]])
        self.assertEqual(len(sandbox.calls), 1)
        check = json.loads((output / 'check_evidence.json').read_text())[0]
        self.assertFalse(check['probe_use_qualification']['can_authorize_scanner_negative_edit'])
        self.assertEqual(check['probe_use_qualification']['rule'], 'completed_target_and_boundary_specific_consumer')
        self.assertNotEqual(trajectory[1]['observations'][1].get('status'), 'invalid_action')

    def test_probe_execution_cannot_refute(self):
        action = fixtures.assess('refuted', quote='return value')
        action['reason'] = 'The executed probe did not trigger the problem.'
        result, trajectory, *_ = self.f.execute([[fixtures.hypothesis()], [action]])
        self.assertNotEqual(result['status'], 'finished')
        self.assertIn('cannot refute', trajectory[1]['observations'][0]['error'])

    def test_supported_target_without_retained_edit_cannot_finish(self):
        result, trajectory, *_ = self.f.execute([
            [fixtures.hypothesis()], [fixtures.assess('supported', quote='return value'), fixtures.FINISH]])
        self.assertNotEqual(result['status'], 'finished')
        self.assertIn('supported vulnerability hypothesis (H001) with no retained repair',
                      trajectory[1]['observations'][1]['error'])

    def test_preloaded_symbol_is_registered_as_current_read(self):
        result, _, _, output, _ = self.f.execute([[fixtures.hypothesis()], [fixtures.assess()]])
        self.assertEqual(len(result['preloaded_read_ranges']), 1)
        registered = result['preloaded_read_ranges'][0]
        self.assertEqual((registered['start_line'], registered['end_line']), (1, 2))
        self.assertEqual(json.loads((output / 'input.json').read_text())['preloaded_source_ranges'][0]['source'],
                         'def render(value):\n    return value')


class V10StaticEvidenceTests(unittest.TestCase):
    def test_wagtail_raw_label_probe_cannot_authorize_downstream_escape_edit(self):
        code = ('ordinary_label = field.label_from_instance(ordinary_page)\n'
                'malicious_label = field.label_from_instance(malicious_page)\n'
                'tracer_observe("unseeded_ordinary_control_pass", ordinary_label == "Normal Title")\n'
                'tracer_observe("unseeded_sink_reached", True)\n'
                'tracer_observe("unseeded_property_violated", "<script>" in malicious_label)')
        check = {'feedback': {'status': 'completed', 'source_identity': 'expected_files_match',
                 'target_reached': True, 'observations': [
                    {'property': 'unseeded_ordinary_control_pass', 'value': True},
                    {'property': 'unseeded_sink_reached', 'value': True},
                    {'property': 'unseeded_property_violated', 'value': True}]}}
        result = v10_protocol.probe_use_qualification(code, check, consumer_verified=False)
        self.assertFalse(result['can_authorize_scanner_negative_edit'])
        self.assertIn('producer_only_no_runtime_caller_or_static_consumer_review', result['reasons'])
        self.assertEqual(result['reasons'], ['producer_only_no_runtime_caller_or_static_consumer_review'])

    def test_public_entry_probe_needs_no_reserved_observations_or_caller(self):
        check = {'feedback': {'status': 'completed', 'source_identity': 'expected_files_match',
                             'target_reached': True, 'observations': []}}
        qualified = v10_protocol.probe_use_qualification(
            'print(target(value))', check, consumer_verified=False, requires_html_consumer=False)
        self.assertTrue(qualified['can_authorize_scanner_negative_edit'])
        for field, bad in [('status', 'check_exception'), ('source_identity', 'mismatch'),
                           ('target_reached', False), ('target_identity_resolved', False)]:
            invalid = copy.deepcopy(check)
            invalid['feedback'][field] = bad
            self.assertFalse(v10_protocol.probe_use_qualification(
                '', invalid, False, requires_html_consumer=False)['can_authorize_scanner_negative_edit'])

    def test_preloaded_callers_count_but_stale_reads_do_not(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = 'def target(x):\n    return x\ndef caller(x):\n    return target(x)\n'
            (root / 'a.py').write_text(source)
            editor = SourceEditor(root)
            h = {'path': 'a.py', 'line': 2, 'target_symbol': {'symbol': 'target'},
                 'mechanism': 'An output contract requires checking'}
            digest = hashlib.sha256(source.encode()).hexdigest()
            for reads, expected in [({'a.py': [(digest, 1, 4)]}, True),
                                     ({'a.py': [(digest, 1, 2)]}, False),
                                     ({'a.py': [('stale', 1, 4)]}, False)]:
                context = unseeded_gate.static_gap_context(h, {}, editor, reads)
                self.assertEqual(context['edit_authorized'], expected)
            h['mechanism'] = 'Validate input at the public authentication boundary'
            self.assertTrue(unseeded_gate.static_gap_context(h, {}, editor, {})['edit_authorized'])

    def test_public_probe_after_edit_is_execution_evidence_not_property_label(self):
        gate = {'v10_protocol': True, 'requires_html_consumer': False, 'before_check_code_sha256': 'program'}
        check = {'v10_protocol': True, 'hypothesis_id': 'H001', 'candidate_patch_sha256': 'after',
                 'code_sha256': 'program', 'feedback': {'status': 'completed',
                 'source_identity': 'expected_files_match', 'target_reached': True}}
        self.assertTrue(unseeded_gate.after_control(gate, 'H001', [check], 'after'))
        self.assertFalse(unseeded_gate.after_control(gate, 'H001', [check], 'stale'))
        gate['requires_html_consumer'] = True
        self.assertFalse(unseeded_gate.after_control(gate, 'H001', [check], 'after'))

    def test_escape_transformation_can_be_cited_and_join_cannot_refute_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = ('import os\nfrom html import escape\n'
                      'def safe(x):\n    return escape(x)\n'
                      'def unsafe(base, x):\n    return os.path.join(base, x)\n')
            (root / 'a.py').write_text(source)
            editor = SourceEditor(root)
            editor.read_paths.add('a.py')
            digest = hashlib.sha256(source.encode()).hexdigest()
            reads = {'a.py': [(digest, 1, 6)]}
            safe_h = {'path': 'a.py', 'line': 4, 'target_symbol': {'symbol': 'safe'}}
            safe = {'decision': 'refuted', 'reason': 'The returned escape transformation encodes markup.',
                'static_invariant': {'invariant': 'Markup is escaped', 'enforcement_kind': 'sanitizing_transformation',
                    'evidence': location('a.py', 4, 4), 'consumer': None,
                    'coverage_argument': 'escape transforms the value at the return boundary.'}}
            self.assertEqual(v10_protocol.static_invariant(editor, safe_h, safe, reads)['evidence']['evidence_symbol'], 'safe')
            unsafe_h = {'path': 'a.py', 'line': 6, 'target_symbol': {'symbol': 'unsafe'}}
            unsafe = {'decision': 'refuted', 'reason': 'The join normalizes traversal.',
                'static_invariant': {'invariant': 'Traversal is normalized', 'enforcement_kind': 'sanitizing_transformation',
                    'evidence': location('a.py', 6, 6), 'consumer': None,
                    'coverage_argument': 'os.path.join collapses dot segments.'}}
            with self.assertRaisesRegex(ValueError, 'does not normalize or collapse'):
                v10_protocol.static_invariant(editor, unsafe_h, unsafe, reads)

    def test_producer_only_dynamic_result_cannot_authorize_edit(self):
        check = {'v10_protocol': True, 'consumer_context_verified': False,
                 'probe_use_qualification': {'can_authorize_scanner_negative_edit': False},
                 'feedback': {'status': 'completed', 'source_identity': 'expected_files_match',
                              'target_reached': True, 'observations': []}}
        self.assertFalse(unseeded_gate.before_control(check))

    def test_unclassified_runtime_caller_counts_in_v10_only(self):
        check = {'feedback': {'target_caller_frames': [{
            'relationship': 'runtime_ancestor_of_target', 'source_sha256': 'current', 'phase': 'unclassified'}]}}
        self.assertTrue(unseeded_gate.verified_consumer_context(check, {}, {}, None, {}, protocol='v10'))
        self.assertFalse(unseeded_gate.verified_consumer_context(check, {}, {}, None, {}, protocol='v9'))


class V10CardsTests(unittest.TestCase):
    def test_ast_cues_are_treatment_only_and_detect_url_scheme_omission(self):
        source = ('from urllib.parse import urlparse\n'
                  'def links(base, value):\n'
                  '    a, b = urlparse(base), urlparse(value)\n'
                  '    return a.netloc == b.netloc and a.path == b.path\n')
        common = {'protocol_revision': v10_cards.POLICY, 'current_code_groups': [{
            'group_id': 'g', 'path': 'a.py', 'symbol': 'links', 'start_line': 2, 'end_line': 4,
            'source': source, 'source_abbreviated': False, 'alert_ids': [], 'calls': [], 'guards': []}],
            'change_audit_bases': [], 'scanner_alerts': [], 'scanner_counts': {},
            'preloaded_source_ranges': [], 'sibling_change_comparisons': {'pairs': []}}
        history = {'temporal': {}, 'rationale': {}}
        payloads = {arm: v10_cards.arm_input(common, history, arm) for arm in engine.ARMS}
        self.assertNotIn('ast_invariant_completeness_cards', payloads['C0'])
        for arm in ['C1', 'C2', 'C3']:
            text = json.dumps(payloads[arm]['ast_invariant_completeness_cards'])
            self.assertIn('omits scheme', text)


if __name__ == '__main__':
    unittest.main()
