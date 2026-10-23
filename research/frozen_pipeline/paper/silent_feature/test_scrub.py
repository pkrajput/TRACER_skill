import ast
import unittest
from paper.silent_feature.scrub import strip_documentation


class ScrubTests(unittest.TestCase):
    def test_comments_docstrings_and_literals(self):
        source = 'def f(x):\n    """security rationale"""\n    # external invariant\n    return "# literal" + x  # note\n'
        clean, receipt = strip_documentation(source)
        self.assertTrue(receipt['executable_ast_equal'])
        self.assertNotIn('rationale',clean)
        self.assertIn('"# literal"',clean)
        self.assertEqual(receipt['comments_removed'],2)
        ns={};exec(compile(clean,'test','exec'),ns)
        self.assertEqual(ns['f']('ok'),'# literalok')
        self.assertIsNone(ns['f'].__doc__)

    def test_empty_suites_unicode_and_nested(self):
        clean,r=strip_documentation('class C:\n    """é"""\n    def f(self):\n        """only doc"""\n')
        ast.parse(clean)
        self.assertIn('pass',clean)
        self.assertEqual(r['docstrings_removed'],2)

    def test_real_expression_string_not_docstring(self):
        clean,r=strip_documentation('def f():\n    x=1\n    "preserve expression"\n    return x\n')
        self.assertIn('preserve expression',clean)
        self.assertEqual(r['docstrings_removed'],0)

    def test_same_line_suite_fails_closed(self):
        with self.assertRaises(ValueError):strip_documentation('def f(): "doc"; return 1\n')
