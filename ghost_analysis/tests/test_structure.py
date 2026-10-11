import unittest

from ghost_analysis.structure import definitions, literal_definitions, payloads, state_at, maximal_matches
from ghost_analysis.swe import parsed


class StructuralControls(unittest.TestCase):
    def test_comments_locations_and_formatting_do_not_change_identity(self):
        a = definitions('def f(x):\n    return x + 1\n')[0]
        b = definitions('\n# note\ndef f( x ):\n    # note\n    return (x+1)\n')[0]
        self.assertEqual(a['ast_sha256'],b['ast_sha256'])

    def test_names_literals_and_operators_are_not_erased(self):
        base = definitions('def f(x):\n    return x+1')[0]['ast_sha256']
        for source in ['def g(x):\n    return x+1','def f(x):\n    return x+2','def f(x):\n    return x-1']:
            self.assertNotEqual(base,definitions(source)[0]['ast_sha256'])

    def test_same_file_change_is_not_symbol_supersession(self):
        a = definitions('def f():\n    return 1\ndef g():\n    return 2')
        b = definitions('def f():\n    return 1\ndef g():\n    return 3')
        self.assertEqual('current',state_at(a[0],b))
        self.assertEqual('superseded',state_at(a[1],b))

    def test_same_name_in_other_scope_is_not_current(self):
        a = definitions('class A:\n    def f(self):\n        return 1')[1]
        b = definitions('class B:\n    def f(self):\n        return 1')
        self.assertEqual('absent_or_renamed',state_at(a,b))

    def test_duplicate_definitions_are_not_silently_resolved(self):
        a = definitions('def f():\n    return 1')[0]
        b = definitions('def f():\n    return 1\ndef f():\n    return 2')
        self.assertEqual('ambiguous_duplicate_definition',state_at(a,b))

    def test_search_and_replacement_are_separate(self):
        source = 'old="def f():\\n return 1"\nnew="def f():\\n return 2"\ncontent=content.replace(old,new)'
        ps = payloads(source)
        self.assertEqual(['search_pattern'],ps[0]['roles'])
        self.assertEqual(['replacement_argument'],ps[1]['roles'])
        self.assertEqual([],definitions(source))
        self.assertEqual('f',ps[1]['definitions'][0]['qualified_name'])

    def test_unavailable_or_invalid_source_is_not_absence(self):
        self.assertEqual(([], 'unavailable_source'),parsed(None))
        self.assertTrue(parsed('def f(')[1])
        self.assertEqual(([],None),parsed(''))

    def test_class_and_contained_methods_are_not_independent_matches(self):
        ds = definitions('class A:\n    def f(self):\n        return 1')
        matches = [dict(target_unit=d) for d in ds]
        self.assertEqual([matches[0]],maximal_matches(matches))

    def test_docstring_only_change_is_visible_but_separately_identified(self):
        a = definitions('def f():\n    "before"\n    return 1')[0]
        b = definitions('def f():\n    "after"\n    return 1')[0]
        self.assertNotEqual(a['ast_sha256'],b['ast_sha256'])
        self.assertEqual(a['code_ast_sha256'],b['code_ast_sha256'])

    def test_reversion_returns_to_current(self):
        a = definitions('def f():\n return 1')[0]
        b = definitions('def f():\n return 2')
        self.assertEqual(['superseded','current'],[state_at(a,b),state_at(a,[a])])

    def test_indented_payload_preserves_multiline_string_values(self):
        fragment = '    def f(self):\n        """grammar\n        rule : TOKEN\n        """\n        return 1\n'
        original = definitions('class A:\n'+fragment)[1]
        lifted = literal_definitions(fragment)[0]
        self.assertEqual(original['ast_sha256'],lifted['ast_sha256'])
        self.assertEqual(1,lifted['start_line'])


if __name__=='__main__': unittest.main()
