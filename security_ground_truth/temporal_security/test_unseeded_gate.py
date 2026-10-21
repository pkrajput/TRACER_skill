import copy
import hashlib
import unittest
from unittest.mock import patch
from . import engine, unseeded_gate
from . import test_engine as fixtures
from .test_engine import FakeSandbox, read, hypothesis, assess, edit, check, FINISH


def evidence(mode='static_chain'):
    return {'mode':mode,'input_trust_boundary':'Caller input is untrusted.',
            'path_to_sink':'The render return value is the final response body.',
            'downstream_protections':'The inspected response path has no further escaping.',
            'violated_property':'Input must remain text at the rendering boundary.',
            'source_anchors':[{'path':'other.py','quote':'return value'}]}


class UnseededGateTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.EngineProtocolTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)

    def script(self, ev=None):
        a=assess('supported',quote='return value')
        if ev is not None:a['unseeded_evidence']=ev
        return [[read('other.py'),hypothesis('other.py')],[a,edit('other.py')],
                [assess('refuted',quote='return str(value)'),{'action':'functional'},FINISH]]

    def test_bare_quote_or_benign_rationale_cannot_authorize_unseeded_edit_in_any_arm(self):
        for arm in engine.ARMS:
            r,t,*_=self.fixture.execute(self.script(),arm=arm)
            self.assertEqual(r['patch_bytes'],0)
            self.assertEqual(t[1]['observations'][0]['unseeded_gate']['mode'],'awaiting_downstream_inspection')
            self.assertIn('downstream',t[1]['observations'][1]['error'])

    def test_complete_static_chain_is_identical_for_C0_C3(self):
        (self.fixture.baseline/'source/other.py').write_text('def render(value):\n    return value\ndef consumer(value):\n    result = render(value)\n    return result\n')
        gates=[]
        for arm in ['C0','C3']:
            r,t,*_=self.fixture.execute(self.script(),arm=arm)
            self.assertEqual(r['status'],'finished');self.assertGreater(r['patch_bytes'],0)
            gates.append(r['unseeded_repair_gates'])
        self.assertEqual(gates[0],gates[1])

    def test_duplicated_gate_fields_are_unnecessary_but_producer_read_alone_is_insufficient(self):
        (self.fixture.baseline/'source/other.py').write_text('def render(value):\n    return value\ndef consumer(value):\n    result = render(value)\n    return escape(result)\n')
        script=self.script();script[0][0]['lines']=2
        r,t,*_=self.fixture.execute(script)
        self.assertEqual(r['patch_bytes'],0)
        self.assertIn('downstream',t[1]['observations'][1]['error'])
        # Entire caller is observed; its escaping is recorded for semantic review.
        r,t,*_=self.fixture.execute(self.script())
        self.assertGreater(r['patch_bytes'],0)
        anchors=r['unseeded_repair_gates']['H001']['source_anchors']
        self.assertTrue(any('escape(result)' in a.get('quote','') for a in anchors))

    def test_unrelated_scanner_ids_do_not_exempt_the_target(self):
        script=self.script();script[0][1]['alert_ids']=['scanner-1']
        r,t,*_=self.fixture.execute(script)
        self.assertEqual(t[0]['observations'][1]['scanner_linked_ids'],[])
        self.assertEqual(r['patch_bytes'],0)
        source='def first(x):\n    return x\n\ndef second(x):\n    return x\n'
        h={'path':'a.py','line':5,'alert_ids':['x']}
        self.assertEqual(unseeded_gate.scanner_links(h,{'x':{'path':'a.py','line':2,'alert_id':'x'}},source),[])

    def dynamic_script(self, after=True, changed_check=False):
        a=assess('supported');a['unseeded_evidence']=evidence('dynamic_control')
        c=check();c['python_code']='tracer_observe("unseeded_property_violated", bool(result))\ntracer_observe("unseeded_ordinary_control_pass", ordinary_result == expected_result)'
        steps=[[read('other.py'),hypothesis('other.py')],[assess(),c],[a,edit('other.py')]]
        if after:
            aftercheck=copy.deepcopy(c)
            if changed_check:aftercheck['python_code']+='\n# different check'
            steps.append([aftercheck])
        steps.append([assess('refuted',quote='return str(value)'),{'action':'functional'},FINISH])
        return steps

    def dynamic_execute(self, script, *, control=True, reached=True, arm='C0'):
        original=FakeSandbox.run
        def run(box,**kwargs):
            if kwargs.get('functional'):return original(box,**kwargs)
            return {'status':'completed','source_identity':'expected_files_match','target_reached':reached,
                    'candidate_patch_sha256':hashlib.sha256(box.editor.patch().encode()).hexdigest(),
                    'observations':[{'property':'unseeded_ordinary_control_pass','value':control},
                        {'property':'unseeded_sink_reached','value':True},
                        {'property':'unseeded_property_violated','value':not bool(box.editor.patch())}]}
        with patch.object(FakeSandbox,'run',run):return self.fixture.execute(script,arm=arm)

    def test_before_after_same_code_and_ordinary_control_preserve_dynamic_repair(self):
        for arm in ['C0','C3']:
            r,*_=self.dynamic_execute(self.dynamic_script(),arm=arm)
            self.assertEqual(r['status'],'finished');self.assertGreater(r['patch_bytes'],0)
            self.assertFalse(r['unseeded_final_gate_failures'])

    def test_missing_or_different_after_check_cannot_survive_even_passing_functional(self):
        for script in [self.dynamic_script(after=False),self.dynamic_script(changed_check=True)]:
            r,*_=self.dynamic_execute(script)
            self.assertEqual(r['patch_bytes'],0);self.assertTrue(r['unvalidated_patch_retained_separately'])
            self.assertTrue(r['unseeded_final_gate_failures'])

    def test_failed_control_or_unreached_before_cannot_authorize_edit(self):
        for kwargs in [{'control':False},{'reached':False}]:
            r,*_=self.dynamic_execute(self.dynamic_script(),**kwargs)
            self.assertEqual(r['patch_bytes'],0)

    def test_constant_control_cannot_authorize_even_with_forged_success_feedback(self):
        script=self.dynamic_script()
        script[1][1]['python_code']='tracer_observe("unseeded_ordinary_control_pass", True)'
        r,*_=self.dynamic_execute(script)
        self.assertEqual(r['patch_bytes'],0)

    def test_control_program_requires_computed_behavior_and_rejects_constant_aliases(self):
        for value in ['True','bool(True)','1 == 1','flag','bool(flag)']:
            code='flag=True\ntracer_observe("unseeded_ordinary_control_pass", '+value+')'
            self.assertFalse(unseeded_gate.control_program_qualified(code))
        self.assertFalse(unseeded_gate.control_program_qualified('result=target("ordinary")'))
        self.assertTrue(unseeded_gate.control_program_qualified('result=target("ordinary")\ntracer_observe("unseeded_ordinary_control_pass", result == expected)'))
