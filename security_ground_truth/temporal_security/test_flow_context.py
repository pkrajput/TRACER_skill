import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from .flow_context import build_flows, annotate, flow_targets
from .engine import arm_input


class FlowContextTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.source='def render(value):\n    if value:\n        return sink(value)\n'
        (self.root/'app.py').write_text(self.source)
        locations=[{'location':{'physicalLocation':{'artifactLocation':{'uri':'app.py'},'region':{'startLine':n}}}} for n in [1,3]]
        self.alert={'alert_id':'a','tool':'codeql','rule_id':'q','path':'app.py','line':3,
                    'flow':[{'threadFlows':[{'locations':locations}]}]}

    def test_native_endpoints_and_syntactic_guards_are_separately_attributed(self):
        f=build_flows(self.root,[self.alert]);warning=f['warnings'][0]
        self.assertEqual([n['role'] for n in warning['paths'][0]['nodes']],['source_endpoint','sink_endpoint'])
        guard=next(n for n in warning['context_nodes'] if n['role']=='guard_candidate')
        self.assertFalse(guard['proves_sanitization']);self.assertEqual(guard['line'],2)
        self.assertIn({'path':'app.py','symbol':'render'},flow_targets(f))

    def test_missing_semgrep_flow_is_not_fabricated(self):
        f=build_flows(self.root,[{**self.alert,'tool':'semgrep','flow':None}])
        w=f['warnings'][0];self.assertEqual(w['path_status'],'no_native_flow_recorded')
        self.assertEqual(w['paths'],[]);self.assertEqual(w['primary']['role'],'warning_location')

    def test_out_of_root_scanner_locations_are_not_read(self):
        a={**self.alert,'flow':[], 'path':'../secret.py'}
        self.assertIsNone(build_flows(self.root,[a])['warnings'][0]['primary'])

    def test_duplicate_scanner_paths_and_budgets_preserve_endpoints(self):
        a={**self.alert,'flow':self.alert['flow']*5};f=build_flows(self.root,[a])
        self.assertEqual(len(f['warnings'][0]['paths']),1)
        f=build_flows(self.root,[{**a,'alert_id':str(i)} for i in range(40)],max_bytes=3000)
        self.assertLessEqual(len(json.dumps(f['warnings']).encode()),3000)
        self.assertTrue(f['omitted_alert_ids'])

    def test_exact_line_change_and_rationale_associations_respect_arm_isolation(self):
        flows=build_flows(self.root,[self.alert])
        change={'operation':'insert','node_type':'Call','before':None,
                'after':{'scope':'render','line':3,'end_line':3}}
        history={'temporal':{'agent':{'records':[{'path':'app.py','event_id':'edit1','after_sha256':hashlib.sha256(self.source.encode()).hexdigest(),
            'symbol_hints':[{'symbol':'render','hint':'insert call'}],'node_changes':[change]}]}},
            'rationale':{'events':[{'event_id':'reason1','span_id':'span1','text':'value is assumed trusted',
                        'links':[{'path':'app.py'}],'mentioned_target_symbols':['render']}]}}
        common={'scanner_flow_context':flows}
        arms={a:arm_input(common,history,a) for a in ['C0','C1','C2','C3']}
        for a in arms:self.assertEqual(arms[a]['scanner_flow_context'],flows)
        self.assertNotIn('flow_history_associations',arms['C0'])
        self.assertNotIn('reason1',json.dumps(arms['C1']))
        self.assertNotIn('edit1',json.dumps(arms['C2']))
        nodes=arms['C3']['flow_history_associations']['nodes']
        sink=next(n for n in nodes if n['role']=='sink_endpoint')
        self.assertTrue(sink['temporal'][0]['changes'][0]['current_node_overlap'])
        source=next(n for n in nodes if n['role']=='source_endpoint')
        self.assertFalse(source['temporal'][0]['changes'][0]['current_node_overlap'])


if __name__=='__main__':unittest.main()
