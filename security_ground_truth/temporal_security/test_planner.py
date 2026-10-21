import json
from pathlib import Path
import tempfile
import unittest

from .planner import plan, patch_lines


class PlannerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def write(self, path, text):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def test_added_symbol_included_without_any_sast_alert(self):
        self.write('a.py', 'def validate(value):\n    return value\n')
        p = plan(self.root, '--- a/a.py\n+++ b/a.py\n@@ -0,0 +1,2 @@\n+def validate(value):\n+    return value\n', [])
        self.assertEqual(p['counts']['changed_symbols'], 1)
        self.assertEqual(p['selected_groups'][0]['symbol'], 'validate')
        self.assertEqual(p['selected_groups'][0]['changed_lines'], [1, 2])

    def test_old_unrelated_alert_cannot_evict_changed_function(self):
        self.write('a.py', 'def old():\n    eval("1")\n\ndef header(value):\n    return value\n')
        alerts = [{'alert_id': 'x', 'path': 'a.py', 'line': 2, 'tool': 'semgrep', 'rule_id': 'eval'}]
        p = plan(self.root, '--- a/a.py\n+++ b/a.py\n@@ -3,0 +4,2 @@\n+def header(value):\n+    return value\n', alerts, max_groups=1)
        self.assertEqual(p['selected_groups'][0]['symbol'], 'header')
        self.assertEqual(p['counts']['scanner_alerts'], 1)
        self.assertFalse(p['scanner_ledger'][0]['in_selected_context'])
        self.assertEqual(p['scanner_ledger'][0]['review_role'],'pre_existing_context')
        self.assertEqual(p['selected_groups'][0]['review_role'],'primary_agent_modified')

    def test_generated_validation_scripts_do_not_crowd_out_changed_production(self):
        self.write('final_verification.py','def verify_security():\n    run()\n')
        self.write('app.py','def parse_value(x):\n    return x\n')
        patch='--- a/final_verification.py\n+++ b/final_verification.py\n@@ -0,0 +1,2 @@\n+def verify_security():\n+    run()\ndiff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -0,0 +1,2 @@\n+def parse_value(x):\n+    return x\n'
        p=plan(self.root,patch,[],max_groups=1)
        self.assertEqual(p['selected_groups'][0]['path'],'app.py')
        self.assertEqual(p['unselected_groups'][0]['review_role'],'agent_validation_artifact')

    def test_flow_endpoint_links_alert_outside_changed_file(self):
        self.write('a.py', 'def transform(x):\n    return x\n')
        flow = [{'threadFlows': [{'locations': [{'location': {'physicalLocation': {'artifactLocation': {'uri': 'a.py'}, 'region': {'startLine': 2}}}}]}]}]
        alerts = [{'alert_id': 'x', 'path': 'other.py', 'line': 10, 'flow': flow, 'gold_label': 'NEVER_FORWARD'}]
        p = plan(self.root, '--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n def transform(x):\n-    return 1\n+    return x\n', alerts)
        self.assertEqual(p['selected_groups'][0]['alert_ids'], ['x'])
        self.assertIn('scanner_flow_intersects_change', p['selected_groups'][0]['reasons'])
        self.assertNotIn('NEVER_FORWARD', json.dumps(p))

    def test_deletion_anchor_and_nonpython_test_exclusion(self):
        patch = '--- a/a.py\n+++ b/a.py\n@@ -1,3 +1,2 @@\n def f():\n-    assert True\n     return 1\ndiff --git a/tests/test_x.py b/tests/test_x.py\n--- a/tests/test_x.py\n+++ b/tests/test_x.py\n@@ -0,0 +1 @@\n+secret\n'
        changed = patch_lines(patch)
        self.assertEqual(changed, {'a.py': {'added_lines': [], 'deletion_anchors': [2]}})

    def test_duplicate_function_definitions_have_distinct_identity(self):
        self.write('a.py', 'def f():\n    return 1\ndef f():\n    return 2\n')
        p = plan(self.root, '--- a/a.py\n+++ b/a.py\n@@ -0,0 +1,4 @@\n+def f():\n+    return 1\n+def f():\n+    return 2\n', [])
        self.assertEqual(len({r['group_id'] for r in p['changed_symbols']}), 2)

    def test_duplicate_alert_ids_match_runtime_lookup(self):
        from security_ground_truth.runtime.alert_identity import unique_alerts
        alerts = [{'alert_id': 'duplicate', 'path': 'a.py', 'line': 1},
                  {'alert_id': 'duplicate', 'path': 'a.py', 'line': 2}]
        p = plan(self.root, '', alerts)
        self.assertEqual([a['alert_id'] for a in p['scanner_ledger']],
                         [a['alert_id'] for a in unique_alerts(alerts)])

    def test_context_budget_preserves_complete_changed_inventory(self):
        text = ''.join(f'def f{i}(value):\n    return value\n' for i in range(20))
        self.write('a.py', text)
        patch = '--- a/a.py\n+++ b/a.py\n@@ -0,0 +1,40 @@\n' + ''.join('+' + line + '\n' for line in text.splitlines())
        p = plan(self.root, patch, [], max_groups=6, max_context_chars=1000)
        self.assertEqual(p['counts']['changed_symbols'], 20)
        self.assertEqual(p['counts']['selected_groups'], 6)
        self.assertEqual(len(p['unselected_groups']), 14)
        self.assertLessEqual(sum(len(r['source']) for r in p['selected_groups']), 1000)

    def test_symlink_and_traversal_do_not_read_outside_snapshot(self):
        (self.root / 'link.py').symlink_to('/etc/passwd')
        p = plan(self.root, '--- a/link.py\n+++ b/link.py\n@@ -0,0 +1 @@\n+x\n', [])
        self.assertEqual(p['counts']['selected_groups'], 0)
        self.assertEqual(p['source_errors'][0]['status'], 'missing_or_excluded_source')
        self.assertEqual(patch_lines('--- a/x.py\n+++ b/../x.py\n@@ -0,0 +1 @@\n+x\n'), {})

    def test_neighbors_and_parse_failure_are_explicit(self):
        self.write('a.py', 'def clean(x):\n    return x\ndef caller(x):\n    return clean(x)\n')
        p = plan(self.root, '--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n def clean(x):\n-    return 1\n+    return x\n', [])
        self.assertTrue(any(r['symbol'] == 'caller' for r in p['selected_groups']))
        self.write('broken.py', 'def broken(:\n')
        p = plan(self.root, '--- a/broken.py\n+++ b/broken.py\n@@ -0,0 +1 @@\n+def broken(:\n', [])
        self.assertEqual(p['source_errors'][0]['status'], 'ast_unavailable')
        self.assertEqual(p['selected_groups'][0]['kind'], 'ModuleFragment')


if __name__ == '__main__':
    unittest.main()
