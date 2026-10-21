import json
import unittest
from .change_symmetry import profile,comparisons
from .engine import arm_input


class SiblingGuardTests(unittest.TestCase):
    def group(self,name,path='module.py',start=1,end=20):
        return {'path':path,'symbol':name,'group_id':path+name,'start_line':start,'end_line':end,'changed_lines':list(range(start,end+1))}

    def test_sibling_input_guard_difference_is_explicit_without_task_hints(self):
        source='def decode(data, width):\n    if len(data) != width: raise ValueError()\n    return unpack(data)\ndef authenticate(blob, width):\n    return unpack(blob)\n'
        a=profile(source,self.group('decode'));b=profile(source,self.group('authenticate',start=4))
        block=comparisons([a,b]);self.assertEqual(len(block['pairs']),1)
        pair=block['pairs'][0]
        self.assertEqual(pair['left']['unmatched_guard_examples'][0]['expression'],'len(data) != width')
        self.assertEqual(pair['right']['unmatched_guards_total'],0)
        self.assertIn('not proof',block['question'])

    def test_parameter_renames_do_not_create_false_syntax_asymmetry(self):
        a=profile('def f(data, width):\n    if len(data) != width: raise ValueError()\n',self.group('f'))
        b=profile('def g(blob, size):\n    if len(blob) != size: raise ValueError()\n',self.group('g'))
        self.assertFalse(comparisons([a,b])['pairs'][0]['asymmetry_observed'])

    def test_parallel_classes_across_files_are_compared_nested_functions_excluded(self):
        a=profile('class Store:\n def load(self, x):\n  if x is None: raise ValueError()\n',self.group('Store.load','a.py'))
        b=profile('class Store:\n def save(self, x):\n  def nested():\n   if x is None: raise ValueError()\n  return x\n',self.group('Store.save','b.py'))
        self.assertEqual(len(b['guards']),0)
        self.assertEqual(comparisons([a,b])['pairs'][0]['relationship'],'same_class_name_across_changed_symbols')

    def test_v9_sibling_comparisons_are_temporal_treatment_only(self):
        base={'path':'a.py','symbol':'f','group_id':'g'}
        pair={'comparison_id':'pair','left':base,'right':{**base,'symbol':'other','group_id':'h'}}
        common={'change_audit_bases':[base],'sibling_change_comparisons':{'pairs':[pair]}}
        history={'temporal':{'agent':{'records':[{'path':'a.py','symbol_filter':'f','event_id':'ONLY_TEMPORAL','symbol_hints':[]}]}}}
        for arm in ['C0','C1','C2','C3']:
            value=arm_input(common,history,arm)
            self.assertEqual('sibling_change_comparisons' in value,arm in ['C1','C3'])
            self.assertEqual('ONLY_TEMPORAL' in json.dumps(value),arm in ['C1','C3'])
            if arm in ['C1','C3']:
                self.assertEqual(value['temporal_change_cards']['cards'][0]['sibling_guard_comparison_ids'],['pair'])
