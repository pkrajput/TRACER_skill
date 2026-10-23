"""Offline regressions for context, evidence contracts and automatic release."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from contextlib import ExitStack
import types
from security_ground_truth.runtime.common import source_manifest,sha256
from security_ground_truth.runtime.dynamic_probe import execute_probe,target_line_matches
from security_ground_truth.repair_check.repair import SourceEditor
from .v12_context import pack,compact_state,encoded_size,rolling_messages,feedback
from .v12_contracts import intrinsic_contract
from .v12_campaign import gate_criteria,full_queue,WAGTAIL,check_reuse,budget_failure
from . import unseeded_gate,citations


class ContextTests(unittest.TestCase):
    def test_exact_citation_recovery_survives_duplicate_context_compaction(self):
        source='    return "'+'x'*2200+'"'
        recovery={'path':'a.py','source':source,'start_line':7,'end_line':7,
                  'citation_fields':{'evidence_start_line':7,'evidence_end_line':7},
                  'unique_current_edit_context':source}
        observation={'status':'invalid_action','error':'e'*1800,
                     'error_type':'ValueError','recovery':recovery}
        reduced=feedback(observation,4500)
        self.assertLessEqual(encoded_size(reduced),4500)
        self.assertEqual(reduced['recovery']['source'],source)
        self.assertEqual(reduced['recovery']['citation_fields'],recovery['citation_fields'])
        self.assertNotIn('recovery',feedback(observation,400))
        self.assertEqual(observation['recovery'],recovery)

    def test_twenty_two_turns_with_large_tool_outputs_fit(self):
        primary={'path':'a.py','symbol':'Main'}
        initial=('user',json.dumps({'primary_preloaded_target':primary,'evidence':'x'*65000}))
        rows=[{'id':'H%03d'%i,'path':'a.py','target_symbol':'Main.f','security_property':'preserve input',
               'decision':'unassessed','used_for_repair':False,'assessment_on_current_patch':False} for i in range(66)]
        state={'hypotheses':rows,'finish_requirements':['H%03d:attempt_PoC_fallback'%i for i in range(66)],
               'edited_branch_warnings':[{'source':'x'*50000}]*30}
        for turn in range(22):
            state['turns_remaining']=21-turn
            new,exchange=pack(initial,{'actions':[{'action':'check','python_code':'x'*80000}]},
                              [{'status':'completed','stdout':'a'*100000,'observations':list(range(5000))}]*3,state,92533)
            self.assertLessEqual(encoded_size([new,*exchange]),92533)
            self.assertEqual(new,initial)
            self.assertIn('H000',exchange[-1][1])
        self.assertEqual(len(rows),66)

    def test_distinct_properties_remain_distinct(self):
        rows=[{'id':'H001','path':'a.py','target_symbol':'f','security_property':'prefix'},
              {'id':'H002','path':'a.py','target_symbol':'f','security_property':'grammar'},
              {'id':'H003','path':'a.py','target_symbol':'f','security_property':'prefix'}]
        state=compact_state({'hypotheses':rows})
        self.assertEqual(len(state['hypotheses']),2)
        self.assertEqual(state['hypotheses'][0]['equivalent_ids'],['H003'])

    def test_recent_small_edit_is_retained_for_followup_validation(self):
        answer={'actions':[{'action':'edit','path':'a.py','old':'return value',
                           'new':'if value < 0: raise ValueError()\n    return value'}]}
        _,exchange=pack(('user','{}'),answer,[{'status':'edited'}],{'hypotheses':[]},92533)
        self.assertEqual(json.loads(exchange[0][1]),answer)

    def test_defensive_trim_preserves_primary(self):
        value={'primary_preloaded_target':{'path':'a.py','symbol':'main'},
               'preloaded_source_ranges':[{'path':'a.py','symbol':'main','source':'PRIMARY'},
                  {'path':'a.py','symbol':'caller','source':'x'*90000}]}
        initial,exchange=pack(('user',json.dumps(value)),{'actions':[]},[],{'hypotheses':[]},50000)
        parsed=json.loads(initial[1]);self.assertEqual(parsed['preloaded_source_ranges'][0]['source'],'PRIMARY')
        self.assertEqual(len(parsed['preloaded_source_ranges']),1)
        self.assertLessEqual(encoded_size([initial,*exchange]),50000)
    def test_recent_feedback_preserved_without_duplicating_old_state(self):
        initial=('user',json.dumps({'source':'x'*65000}))
        prior=[initial,('model','{"actions":[]}'),('user',json.dumps({
            'observations':[{'hypothesis_id':'H001','mechanism':'signature length'}],
            'protocol_state':{'old_duplicate':'x'*20000}}))]
        current=[('model','{"actions":[]}'),('user','{"protocol_state":{"turns_remaining":8}}')]
        messages=rolling_messages(initial,prior,current,92533)
        self.assertIn('signature length',str(messages));self.assertNotIn('old_duplicate',str(messages))
        self.assertEqual(messages[-2:],current)
        self.assertLessEqual(encoded_size(messages),92533)

    def test_huge_historical_action_is_compacted_but_current_action_is_exact(self):
        initial=('user',json.dumps({'source':'x'*65000}))
        huge={'actions':[{'action':'check','path':'a.py','hypothesis_id':'H001','python_code':'x'*50000}]}
        prior=[initial,('model',json.dumps(huge)),('user',json.dumps({'observations':[{'status':'completed','target_reached':True}]}))]
        current_answer={'actions':[{'action':'edit','path':'a.py','old':'x','new':'y'}]}
        current=[('model',json.dumps(current_answer)),('user','{"protocol_state":{"turns_remaining":8}}')]
        messages=rolling_messages(initial,prior,current,92533)
        self.assertIn('historical_action_summary',messages[1][1])
        self.assertNotIn('"python_code"',messages[1][1])
        self.assertEqual(json.loads(messages[-2][1]),current_answer)


class CoverageTests(unittest.TestCase):
    def test_class_method_execution_is_reached(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);root=base/'source';root.mkdir()
            (root/'sample.py').write_text('class Parser:\n    def parse(self, value):\n        return value.upper()\n\ndef outside():\n    return 1\n')
            expected=source_manifest(root)
            expected['_tracer_trace_target']={'path':'sample.py','symbol':'Parser','kind':'class','start_line':1,'end_line':3}
            (base/'expected.json').write_text(json.dumps(expected))
            check=base/'check.py';check.write_text('import runpy\np=runpy.run_path("sample.py")["Parser"]\ntracer_observe("ordinary", p().parse("abc"))\n')
            result=execute_probe(root,check,base/'expected.json',base/'result.json')
            self.assertEqual(result['status'],'completed')
            self.assertTrue(result['target_frame_executed'])
            self.assertIn(3,result['coverage']['sample.py'])
    def test_outside_class_and_other_file_do_not_reach(self):
        t={'path':'a.py','symbol':'A','kind':'class','start_line':10,'end_line':20}
        self.assertFalse(target_line_matches(t,'a.py',21,'f'))
        self.assertFalse(target_line_matches(t,'b.py',15,'f'))
        self.assertTrue(target_line_matches(t,'a.py',15,'f'))
    def test_function_identity_still_required(self):
        t={'path':'a.py','symbol':'A.f','kind':'function','start_line':10,'end_line':20}
        self.assertFalse(target_line_matches(t,'a.py',15,'other'))


class ContractTests(unittest.TestCase):
    def context(self,source,symbol,claim):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        root=Path(temp.name);(root/'a.py').write_text(source);editor=SourceEditor(root)
        scope=next(s for s in citations.symbols(source) if s['symbol']==symbol)
        h={'path':'a.py','line':scope['start_line'],'target_symbol':scope,
           'mechanism':claim,'security_property':claim,'preconditions':'untrusted text','contract_revision':'v12'}
        reads={'a.py':[(citations.source_hash(source),1,len(source.splitlines()))]}
        return unseeded_gate.static_gap_context(h,{},editor,reads)
    def test_entity_contract_needs_no_application_renderer(self):
        s='from html.parser import HTMLParser\nclass Parser(HTMLParser):\n    def handle_data(self, value):\n        self.data.append(value)\n'
        self.assertTrue(self.context(s,'Parser','preserve exact HTML entities when stripping tags')['edit_authorized'])
    def test_form_options_contract_needs_no_model_registry(self):
        s="class FormBuilder:\n    def get_field_options(self, field):\n        options = {}\n        options['help_text'] = field.help_text\n        options['label'] = field.label\n        options['required'] = field.required\n        return options\n"
        for target in ('FormBuilder','FormBuilder.get_field_options'):
            value=self.context(s,target,'unescaped help_text HTML must be conditionally escaped')
            self.assertTrue(value['edit_authorized']);self.assertFalse(value['requires_html_consumer'])
    def test_public_sanitizer_wrapper_uses_intrinsic_entity_contract(self):
        s='from html.parser import HTMLParser\nclass Parser(HTMLParser):\n    pass\ndef inner(value):\n    return Parser().feed(value)\ndef strip_tags(value):\n    return inner(value)\n'
        self.assertTrue(self.context(s,'strip_tags','preserve exact HTML entities while stripping tags')['edit_authorized'])
    def test_label_producer_still_blocked(self):
        s='class PageChoiceField:\n    def label_from_instance(self, obj):\n        return obj.title\n'
        for target in ('PageChoiceField','PageChoiceField.label_from_instance'):
            c=self.context(s,target,'unescaped HTML label may require escaping')
            self.assertTrue(c['requires_html_consumer']);self.assertFalse(c['edit_authorized'])
    def test_arbitrary_html_helper_gets_no_form_exception(self):
        self.assertIsNone(intrinsic_contract('def html(value):\n    return value\n','html','help_text is unescaped'))


class ReleaseTests(unittest.TestCase):
    def test_timeout_reservation_text_does_not_trigger_financial_stop(self):
        for kind,message in [('RequestDeadlineExceeded',
            'HTTP wall-clock deadline exceeded before any response tokens were returned; retain the unknown-cost reservation'),
            ('ValueError','Per-request evidence budget exceeded'),
            ('ConnectionError','HTTP transport failed: IncompleteRead')]:
            self.assertFalse(budget_failure({'error':{'type':kind,'message':message}}))
        self.assertTrue(budget_failure({'error':{'type':'BudgetExceeded','message':'Scope cap reached'}}))
        self.assertFalse(budget_failure({'error':None}))

    def rows(self):
        return [{'case_key':k,'arm':a,'terminal_phases':2,'repair_status':'finished','func_pass':True,
                 'sec_pass':k==WAGTAIL or (a=='C3' and k=='case1')} for k in [WAGTAIL]+['case'+str(i) for i in range(1,10)] for a in ('C0','C3')]
    def test_all_four_criteria_required(self):
        rows=self.rows();self.assertTrue(gate_criteria(rows)['passed'])
        for field,value in [('repair_status','repair_error'),('terminal_phases',1),('func_pass',False),('sec_pass',False)]:
            altered=copy.deepcopy(rows);altered[0][field]=value
            self.assertFalse(gate_criteria(altered)['passed'],field)
        tied=copy.deepcopy(rows)
        for r in tied:r['sec_pass']=r['case_key']==WAGTAIL
        self.assertFalse(gate_criteria(tied)['passed'])
        self.assertFalse(gate_criteria(rows[:-1])['passed'])
    def test_no_full_queue_before_gate_and_no_duplicate_pilot_billing(self):
        cases=[{'case_key':'%024x'%i} for i in range(391)]
        completed={(c['case_key'],a) for c in cases[:10] for a in ('C0','C3')}
        self.assertEqual(full_queue(cases,{'passed':False},completed),[])
        queue=full_queue(cases,gate_criteria(self.rows()),completed)
        self.assertEqual(len(queue),1544)
        self.assertFalse({(c['case_key'],a) for c,a in queue}&completed)
    def test_reuse_is_hash_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);p=root/'candidate.patch';p.write_text('patch')
            hashes={'candidate.patch':sha256(p)};check_reuse(root,hashes)
            p.write_text('different')
            with self.assertRaises(ValueError):check_reuse(root,hashes)


class EngineTests(unittest.TestCase):
    def test_v12_engine_uses_bounded_context_and_reuses_duplicate_id(self):
        from .test_v11_protocol import V11EngineTests
        from . import test_engine as f
        from .v12_protocol import POLICY
        fixture=V11EngineTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        fixture.f.common['protocol_revision']=POLICY
        result,trace,*_=fixture.f.execute([[f.hypothesis()],[f.hypothesis()],[f.assess()]])
        self.assertNotEqual(result['status'],'repair_error')
        self.assertEqual(trace[0]['observations'][0]['contract_revision'],'v12')
        self.assertEqual(trace[1]['observations'][0]['hypothesis_id'],'H001')
        self.assertTrue(trace[1]['observations'][0]['duplicate_reused'])


class PreloadTests(unittest.TestCase):
    def test_duplicate_property_names_resolve_once_to_class(self):
        from .v12_inputs import upgrade
        source='class A:\n    @property\n    def value(self):\n        return self._value\n    @value.setter\n    def value(self, item):\n        self._value = item\n'
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'source').mkdir();(root/'source/a.py').write_text(source)
            group={'path':'a.py','symbol':'A.value','group_id':'g','start_line':2,'end_line':4,'source':'','alert_ids':[],'calls':[],'guards':[]}
            common={'current_code_groups':[group],'change_audit_bases':[{'path':'a.py','symbol':'A.value','group_id':'g'}]*2,
                    'functional_request':'Preserve property behavior','scanner_alerts':[]}
            c,_,_=upgrade(common,{}, {'baseline':str(root)},92533)
            self.assertEqual([(r['path'],r['symbol']) for r in c['preloaded_source_ranges']],[('a.py','A')])

    def test_no_current_production_target_is_explicit_source_only_exclusion(self):
        from .v12_inputs import upgrade,AdmissionError
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'source').mkdir()
            with self.assertRaisesRegex(AdmissionError,'No current production-code'):
                upgrade({'current_code_groups':[],'change_audit_bases':[]},{},{'baseline':str(root)},92533)

    def test_module_primary_prefers_exact_changed_callable(self):
        from .v12_inputs import upgrade
        source='def changed(value):\n    return value\n\n'+'x = 1\n'*2000
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'source').mkdir();(root/'source/a.py').write_text(source)
            function={'path':'a.py','symbol':'changed','group_id':'f','start_line':1,'end_line':2,
                      'source':'def changed(value):\n    return value','alert_ids':[],'calls':[],'guards':[]}
            module={'path':'a.py','symbol':'<module>','group_id':'m','start_line':1,'end_line':2003,
                    'source':source,'alert_ids':[],'calls':[],'guards':[]}
            c,_,_=upgrade({'current_code_groups':[function,module],
                'change_audit_bases':[function,module],'functional_request':'change function',
                'scanner_alerts':[]},{},{'baseline':str(root)},92533)
            self.assertEqual(c['primary_preloaded_target']['symbol'],'changed')
            self.assertLess(len(c['preloaded_source_ranges'][0]['source']),100)


class CardTests(unittest.TestCase):
    def test_large_bundle_compaction_preserves_evidence_and_resolvable_joins(self):
        from .test_v11_cards import group,common
        from .v12_cards import arm_input,verify_arms
        source='def f(value):\n    return value\n';g=group('a.py','f',source,1);c=common([g])
        c.update(v12_compression=3,primary_preloaded_target={'path':'a.py','symbol':'f'},
                 preloaded_source_ranges=[{**g,'relationship':'selected_target'}])
        quote='For now assume that the ordinary input is valid.'
        record={'event_id':'AST_EVENT','path':'a.py','symbol_filter':'f',
                'guard_deltas':{'added':[{'condition':'value < 0'}],'removed':[]},
                'symbol_hints':[{'hint':'TEMPORAL_EVIDENCE'}]}
        h={'temporal':{'agent':{'records':[record]}},'rationale':{'events':[{
            'event_id':'RATIONALE_EVENT','text':quote,'start_char':0,'end_char':len(quote),
            'links':[{'path':'a.py','scope':'file_association_not_proven_symbol_intent'}]}]}}
        original_common=copy.deepcopy(c);original_history=copy.deepcopy(h)
        verify_arms(c,h,92533)
        values={a:arm_input(c,h,a) for a in ('C0','C1','C2','C3')}
        for a,v in values.items():
            self.assertEqual('TEMPORAL_EVIDENCE' in json.dumps(v),a in ('C1','C3'))
            self.assertEqual(quote in json.dumps(v),a in ('C2','C3'))
            self.assertEqual(v['preloaded_source_ranges'][0]['source'],source)
        combined=values['C3'];ids={r['group_id'] for r in combined['current_code_groups']}
        for card in combined['intent_implementation_divergence_cards']['cards']:
            self.assertIn(card['temporal_card_group_id'],ids)
        self.assertEqual(combined['temporal_history']['agent']['records'][0]['guard_deltas'],record['guard_deltas'])
        altered=copy.deepcopy(h);altered['temporal']['agent']['records'][0]['symbol_hints'][0]['hint']='OTHER_HISTORY'
        self.assertEqual(values['C0'],arm_input(c,altered,'C0'))
        self.assertEqual(values['C2'],arm_input(c,altered,'C2'))
        self.assertEqual(h,original_history)
        self.assertEqual(c,original_common)
        for a in ('C3','C2','C1','C0'):
            self.assertEqual(values[a],arm_input(c,h,a),'Rendering must not depend on arm order')

    def test_lifecycle_and_complete_grammar_cue_only_in_treatments(self):
        from .test_v11_cards import group,common
        from .v12_cards import arm_input,LIFECYCLE_CUE
        source='def _resolve_connection(self):\n    conn = self.get_connection()\n    return {"url": f"{conn.host}:{conn.port}", "schema": conn.schema}\n'
        c=common([group('a.py','Hook._resolve_connection',source,1)])
        c['primary_preloaded_target']={'path':'a.py','symbol':'Hook._resolve_connection'}
        for a in ('C0','C1','C2','C3'):
            value=arm_input(c,{},a)
            self.assertEqual(LIFECYCLE_CUE in str(value),a!='C0')

    def test_ground_truth_fields_are_rejected_from_every_arm(self):
        from .test_v11_cards import group,common
        from .v12_cards import verify_arms
        source='def f(value):\n    return value\n';g=group('a.py','f',source,1);c=common([g])
        c.update(primary_preloaded_target={'path':'a.py','symbol':'f'},
                 preloaded_source_ranges=[{**g,'relationship':'selected_target'}],
                 v12_shared_overrides={'leak':{'official_baseline_score':{'sec_pass':False}}})
        with self.assertRaises(AssertionError):verify_arms(c,{},92533)


class ControllerTests(unittest.TestCase):
    def exercise(self,broken,resuming=False,failed_provider_cells=False):
        from . import v12_campaign as campaign
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();root.joinpath('frozen_code').mkdir()
            ledger=root/'fixture_ledger.sqlite3'
            with campaign.sqlite3.connect(ledger) as db:
                db.execute('CREATE TABLE budget_scopes (id TEXT PRIMARY KEY, cap_micro_usd INTEGER, initial_total_micro_usd INTEGER)')
            cases=[{'case_key':WAGTAIL if i==0 else '%024x'%i,'baseline':'unused',
                    'v12_stratum':'development_exposed'} for i in range(391)]
            keys=[c['case_key'] for c in cases[:10]]
            for name,value in {'manifest.json':{'frozen_sha256':{}},
                'authorization.json':{'study_total_cap_micro_usd':699000000,'full_cases':391,
                                      'initial_ledger_micro_usd':0},'cases.json':cases,
                'pilot_keys.json':keys,'config.json':{}}.items():(root/name).write_text(json.dumps(value))
            for c in cases[:20]:
                p=root/'inputs'/c['case_key'];p.mkdir(parents=True)
                for name in ('common.json','history.json'):(p/name).write_text('{}')
            revision=None
            if resuming:
                for c in cases[:10]:
                    for a in ('C0','C3'):
                        p=root/'cells'/c['case_key']/a;p.mkdir(parents=True)
                        (p/'complete.json').write_text('{}')
                (root/'qualification_gate.json').write_text(json.dumps(gate_criteria(ReleaseTests().rows())))
                (root/'RELEASE.json').write_text('{}')
                (root/'qualification_reuse_manifest.json').write_text('{}')
                revision=root/'revision/manifest.json';revision.parent.mkdir()
                revision.write_text(json.dumps({'base_manifest_sha256':sha256(root/'manifest.json'),
                    'files_sha256':{},'existing_cell_artifacts_sha256':{},'reused_cells':20}))
            stages=[];paid=[];queued=[]
            class Gateway:
                def __init__(self,path,config,schema):
                    stages.append(config['budget_scope']['id'].rsplit(':',1)[-1]);self.config=config
                    self.ledger=types.SimpleNamespace(scope_summary=lambda:{},summary=lambda:{})
                def generate(self,*a,**kw):raise AssertionError('No provider transport in controller test')
            class Server:
                def __init__(self,*a):self.server_port=1
                def serve_forever(self):pass
                def shutdown(self):pass
                def server_close(self):pass
            def repair(c,common,history,arm,gateway,cell,max_calls):
                paid.append((c['case_key'],arm));cell.mkdir(parents=True)
                (cell/'candidate.patch').write_text('')
                result={'case_key':c['case_key'],'arm':arm,'patch_sha256':sha256(cell/'candidate.patch'),
                        'status':'finished','patch_bytes':0}
                if failed_provider_cells:
                    result.update(status='repair_error',error={'type':'HTTPError','message':'HTTP Error 429'})
                (cell/'result.json').write_text(json.dumps(result));return result
            def score(root,c,a,namespace):
                return {'case_key':c['case_key'],'arm':a,'terminal_phases':2,
                    'repair_status':'repair_error' if broken and c['case_key']==keys[1] and a=='C3' else 'finished',
                    'func_pass':True,'sec_pass':c['case_key']==WAGTAIL or (c['case_key']==keys[1] and a=='C3')}
            def full(cases,gate,completed):
                result=full_queue(cases,gate,completed);queued.extend(result)
                return [(c,a) for c in cases[10:20] for a in ('C0','C1','C2','C3')] if failed_provider_cells else []
            with ExitStack() as stack:
                stack.enter_context(patch.object(campaign,'LEDGER',ledger))
                for name,value in {'OpenRouterRepair':Gateway,'ThreadingHTTPServer':Server,
                    'load_authors_classes':lambda p:{},'validate_case_external_snapshot':lambda c:None,
                    'ledger_total':lambda:0,'cell_row':score,'full_queue':full,
                    'evaluate':lambda *a:{}}.items():stack.enter_context(patch.object(campaign,name,value))
                stack.enter_context(patch.object(campaign.engine,'run',repair))
                stack.enter_context(patch('security_ground_truth.temporal_security.v12_report.publish',lambda *a:None))
                stack.enter_context(patch.object(campaign.signal,'signal',lambda *a:None))
                stack.enter_context(patch.object(campaign.time,'sleep',lambda *a:None))
                if resuming:
                    stack.enter_context(patch.object(campaign,'__file__',str(revision.parent/'code/security_ground_truth/temporal_security/v12_campaign.py')))
                campaign.run(root,revision)
            if resuming:
                self.assertEqual(len(paid),40 if failed_provider_cells else 0)
                self.assertEqual(json.loads((root/'status.json').read_text())['errors'],[])
                self.assertEqual(stages,['full'])
                self.assertEqual(len(queued),1544)
                self.assertFalse({(c['case_key'],a) for c,a in queued}&{(k,a) for k in keys for a in ('C0','C3')})
                return
            self.assertEqual(len(paid),20)
            self.assertEqual(len(set(paid)),20)
            if broken:
                self.assertEqual(stages,['gate']);self.assertEqual(queued,[])
                self.assertFalse((root/'RELEASE.json').exists())
                self.assertEqual(json.loads((root/'status.json').read_text())['status'],'qualification_failed')
            else:
                self.assertEqual(stages,['gate','full']);self.assertEqual(len(queued),1544)
                self.assertFalse(set(paid)&{(c['case_key'],a) for c,a in queued})
                self.assertTrue((root/'qualification_reuse_manifest.json').exists())
    def test_gate_failure_stops_controller_after_twenty_cells(self):self.exercise(True)
    def test_gate_pass_reuses_exact_pilot_cells_before_release(self):self.exercise(False)
    def test_resume_skips_all_completed_model_and_evaluation_work(self):self.exercise(False,resuming=True)
    def test_forty_exhausted_provider_attempts_do_not_abort_remaining_queue(self):
        self.exercise(False,resuming=True,failed_provider_cells=True)


if __name__=='__main__':unittest.main()
