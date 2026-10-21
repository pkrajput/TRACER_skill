import copy
import json
from pathlib import Path
import tempfile
import unittest

from .rationale import build_rationale, public_rationale, RationaleSession, prose_spans
from .engine import arm_input


def event(n, text, path='app.py', command='view'):
    return [{'event_id':f'm{n:06d}:rationale','message_index':n,'kind':'rationale','text':text,
             'source_field':'content','rationale_kind':'original'},
            {'event_id':f'm{n:06d}:action:0','message_index':n,'kind':'action',
             'tool_name':'str_replace_editor','arguments':{'path':'/project/'+path,'command':command,
                                                         'view_range':[10,20]}}]


def view(events):
    return {'arm':'B4','events':events,'source_trace_sha256':'a'*64,'cutoff_message':100,
            'states':[],'edit_records':[],'rationale_links':{}}


class RationaleTests(unittest.TestCase):
    targets=[{'path':'app.py','symbol':'render'}]

    def test_partial_views_and_earlier_edits_do_not_need_ast_reconstruction(self):
        v=view(event(1,'render should preserve plain text and escape input.',command='str_replace')+
               event(2,'Because input is untrusted, validate before rendering.')+
               event(3,'Now inspect elsewhere.',path='other.py'))
        r=build_rationale(v,self.targets)
        self.assertEqual({e['event_id'] for e in r['events']},{'m000001:rationale','m000002:rationale'})
        self.assertEqual(r['events'][0]['links'][0]['relationship'],'same_message_explicit_editor_path')
        self.assertIn('not_proven_symbol_intent',r['events'][0]['links'][0]['scope'])

    def test_cutoff_and_different_file_are_excluded(self):
        v=view(event(1,'Before cutoff valid rationale.')+event(100,'FUTURE_HIDDEN_LABEL')+
               event(2,'OTHER_FILE',path='other.py'))
        r=build_rationale(v,self.targets)
        self.assertNotIn('FUTURE_HIDDEN_LABEL',json.dumps(r))
        self.assertNotIn('OTHER_FILE',json.dumps(r))

    def test_exact_changed_fragment_anchors_current_symbol_without_claiming_old_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'app.py').write_text('def render(value):\n    return escape(value)\n\ndef unrelated(value):\n    return value\n')
            v=view(event(1,'This change must escape untrusted input.',command='str_replace'))
            v['edit_records']=[{'action_event_id':'m000001:action:0','message_index':1,
                                'path':'app.py','success_acknowledged':True,
                                'fragments':{'old_str':'    return value','new_str':'    return escape(value)'}}]
            r=build_rationale(v,self.targets,source_root=root)
            anchors=r['events'][0]['links'][0]['current_symbol_anchors']
            self.assertEqual(len(anchors),1)
            self.assertEqual(anchors[0]['current_symbol'],'render')
            self.assertFalse(anchors[0]['historical_scope_identity_proven'])
            other=build_rationale(v,[{'path':'app.py','symbol':'unrelated'}],source_root=root)
            # The old text matches the unrelated function, so it is labelled only
            # as a current textual anchor, never proof that that function was edited.
            for a in other['events'][0]['links'][0]['current_symbol_anchors']:
                self.assertFalse(a['historical_scope_identity_proven'])

    def test_fenced_code_removed_but_offsets_reference_original(self):
        text='Assume the input must be escaped.\n\n```python\nSECRET_CODE = 1\n```\n\nHowever, render must preserve ordinary text.\n'
        r=build_rationale(view(event(1,text)),self.targets)
        self.assertNotIn('SECRET_CODE',json.dumps(r))
        for c in r['events']:
            self.assertEqual(text[c['start_char']:c['end_char']],c['text'])
        self.assertEqual(list(prose_spans('```python\ncode without a closing fence')),[])

    def test_budget_covers_initial_and_retrieved_prose(self):
        v=view(sum((event(i,('Because render must reject invalid input %d. '%i)*18) for i in range(1,20)),[]))
        r=build_rationale(v,self.targets)
        session=RationaleSession(r,True)
        self.assertLessEqual(session.used,3500)
        initial={c['span_id'] for c in session.exposed}
        reply=session.retrieve('app.py','invalid input')
        self.assertTrue(reply['events'])
        self.assertFalse(initial & {c['span_id'] for c in reply['events']})
        session.retrieve('app.py');session.retrieve('app.py')
        self.assertLessEqual(session.used,5000)
        self.assertEqual(session.calls,2)

    def test_selection_shares_budget_across_paths_and_prioritizes_later_corrections(self):
        v=view(event(1,'Starting to inspect file.')+event(2,'render must validate input because untrusted callers can use it.')+
               event(80,'However, render must reject invalid input instead of trusting previous assumptions.')+
               event(3,'process must reject invalid paths because they are untrusted.',path='other.py'))
        r=build_rationale(v,self.targets+[{'path':'other.py','symbol':'process'}],max_chars=200)
        self.assertEqual({l['path'] for c in r['events'] for l in c['links']},{'app.py','other.py'})
        self.assertIn('m000080:rationale',{c['event_id'] for c in r['events']})

    def test_shell_path_is_only_lexical_and_prefix_does_not_match(self):
        ev=event(1,'This operation should preserve text.')
        ev[1].update(tool_name='bash',arguments={'command':'cat /project/app.py.old'})
        self.assertFalse(build_rationale(view(ev),self.targets)['events'])
        ev[1]['arguments']['command']='cat /project/app.py'
        r=build_rationale(view(ev),self.targets)
        self.assertEqual(r['events'][0]['links'][0]['relationship'],'same_message_literal_path_in_unexecuted_command')

    def test_identical_rationale_for_c2_c3_and_no_private_index_sent(self):
        r=build_rationale(view(event(1,'render should escape the input.')),self.targets)
        history={'rationale':r,'temporal':{'irrelevant':'AST'}}
        inputs={a:arm_input({},history,a) for a in ['C0','C1','C2','C3']}
        self.assertEqual(inputs['C2']['developer_rationale'],inputs['C3']['developer_rationale'])
        self.assertFalse(any('_retrieval_index' in json.dumps(i) for i in inputs.values()))
        for a in ['C0','C1']:
            self.assertNotIn('render should',json.dumps(inputs[a]))
            with self.assertRaisesRegex(ValueError,'withheld'):
                RationaleSession(r,False).retrieve('app.py')
        changed=copy.deepcopy(history);changed['temporal']={}
        self.assertEqual(arm_input({},changed,'C2'),inputs['C2'])

    def test_citations_must_be_exposed_exact_path_linked_and_testable(self):
        r=build_rationale(view(event(1,'render should escape the input.')),self.targets)
        session=RationaleSession(r,True)
        ref={'event_id':'m000001:rationale','quote':'should escape the input',
             'assumption':'Input is escaped','verification_plan':'Inspect current render escaping call'}
        valid=session.validate_refs([ref],'app.py')[0]
        self.assertTrue(valid['citation_verified'])
        self.assertEqual(valid['source_start_char'],7)
        for bad in [{**ref,'quote':'This quotation was never exposed'},
                    {**ref,'event_id':'m000099:rationale'},{**ref,'verification_plan':''}]:
            with self.assertRaises(ValueError):session.validate_refs([bad],'app.py')
        with self.assertRaises(ValueError):session.validate_refs([ref],'elsewhere.py')
        with self.assertRaises(ValueError):RationaleSession(r,False).validate_refs([ref],'app.py')
        self.assertEqual(session.validate_refs([],'app.py'),[])


if __name__=='__main__': unittest.main()
