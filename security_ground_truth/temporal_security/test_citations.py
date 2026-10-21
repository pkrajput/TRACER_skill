import tempfile
from pathlib import Path
import unittest

from .citations import matching_quote, resolve, recovery, source_hash
from security_ground_truth.repair_check.repair import SourceEditor


SOURCE = 'def render(value):\n    return escape(value)\n'


class CitationTests(unittest.TestCase):
    def test_whitespace_and_display_prefix_capture_current_exact_text(self):
        for quote in ['return escape( value )', '2:     return escape( value )']:
            result=resolve(SOURCE,{'evidence_quote':quote},{},[])
            self.assertEqual(result['evidence_quote'],'    return escape(value)')

    def test_literal_operator_and_relative_indentation_changes_rejected(self):
        for source,quote in [('return "a b"','return "ab"'),('return x < 2','return x > 2'),
                             ('if valid:\n    allow()\ndeny()','if valid:\n    allow()\n    deny()')]:
            self.assertIsNone(matching_quote(source,quote))

    def test_ambiguous_quote_requires_scope(self):
        source=SOURCE+'def other(value):\n    return escape(value)\n'
        with self.assertRaises(ValueError):resolve(source,{'evidence_quote':'return escape(value)'},{},[])
        result=resolve(source,{'evidence_quote':'return escape(value)','evidence_symbol':'other'},{},[])
        self.assertEqual(result['evidence_start_line'],4)

    def test_current_symbol_range_needs_no_redundant_read(self):
        result=resolve(SOURCE,{'evidence_start_line':2,'evidence_end_line':2,'evidence_symbol':'render'},{},[])
        self.assertEqual(result['evidence_quote'],'    return escape(value)')
        with self.assertRaises(ValueError):
            resolve(SOURCE,{'evidence_start_line':3,'evidence_symbol':'render'},{},[])

    def test_wrong_hash_is_auto_bound_and_recovery_remains_usable(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory);(p/'a.py').write_text(SOURCE);editor=SourceEditor(p);reads={}
            action={'hypothesis_id':'H001','evidence_start_line':2,'evidence_source_sha256':'stale'}
            h={'H001':{'path':'a.py','line':2,'target_line_text':'    return escape(value)'}}
            bound=resolve(SOURCE,action,h['H001'],[])
            self.assertEqual(bound['source_sha256'],source_hash(SOURCE))
            self.assertTrue(bound['model_hash_corrected'])
            context=recovery(editor,action,h,reads)
            valid=resolve(SOURCE,context['citation_fields'],h['H001'],reads['a.py'])
            self.assertIn('return escape(value)',valid['evidence_quote'])
            self.assertEqual(valid['source_sha256'],source_hash(SOURCE))

    def test_unique_current_quote_resolves_post_edit_line_drift(self):
        current='\n'+SOURCE
        result=resolve(current,{'evidence_start_line':2,'evidence_quote':'return escape(value)'},{},
                       [(source_hash(SOURCE),1,2)])
        self.assertEqual(result['evidence_start_line'],3)


if __name__=='__main__':unittest.main()
