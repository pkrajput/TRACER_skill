import ast
import unittest
from paper.bio_study.splice import component_source, splice_method


class MethodSpliceTests(unittest.TestCase):
    def test_hoisted_nested_self_helper_is_bound_on_real_class(self):
        code='def run(self, x):\n self.value = self._helper(x)\n def _helper(self, x):\n  return x+1\n'
        source, meta=component_source(code,'Owner.run','')
        ns={};exec(source,ns)
        owner=ns['_TracerComponent']();owner.run(2)
        self.assertEqual(owner.value,3)
        self.assertEqual(meta['hoisted'],['_helper'])
        assembled,_=splice_method('class Owner:\n def run(self,x):\n  pass\n','Owner.run',code)
        ns={};exec(assembled,ns);owner=ns['Owner']();owner.run(3)
        self.assertEqual(owner.value,4)

    def test_sibling_method_and_module_import_preserved(self):
        code='def run(self,x):\n return self._helper(x)\nimport math\ndef _helper(self,x):\n return math.sqrt(x)\n'
        source,_=component_source(code,'Owner.run','')
        ns={};exec(source,ns);self.assertEqual(ns['_TracerComponent']().run(9),3)

    def test_closure_helper_stays_nested(self):
        code='def run(self,x):\n def helper():\n  return x+2\n return helper()\n'
        source,meta=component_source(code,'Owner.run','')
        self.assertEqual(meta['hoisted'],[])
        ns={};exec(source,ns);self.assertEqual(ns['_TracerComponent']().run(2),4)

    def test_existing_class_helper_collision_rejected(self):
        with self.assertRaises(ValueError):
            splice_method('class Owner:\n def run(self):pass\n def _helper(self):pass\n',
                          'Owner.run','def run(self):pass\ndef _helper(self):pass\n')
