"""Release interface controls: evidence boundaries, no execution, and safe outputs."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from ghost_analysis.cli import main, scan


class ReleaseInterfaceTests(unittest.TestCase):
    def test_scan_never_executes_input_and_preserves_unknown_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / 'executed.py'
            helper = root / 'helper.py'
            helper.write_text(f'open({str(marker)!r}, "w").write("executed")\n')
            report = scan(helper)
            self.assertEqual(report['source_writing_candidates'], 1)
            self.assertEqual(report['files'][0]['task_redundancy'], 'unknown')
            self.assertEqual(report['files'][0]['history_support'], 'not_checked')
            self.assertFalse(marker.exists())

    def test_parse_error_is_not_a_negative_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / 'broken.py'
            file.write_text('def broken(')
            report = scan(file)
            self.assertEqual(report['parse_errors'], 1)
            self.assertEqual(report['files'][0]['task_redundancy'], 'unknown')

    def test_demo_separates_static_history_and_deletion_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'demo'
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(['demo', '--out', str(out)]), 0)
            summary = json.loads((out / 'discovery/summary.json').read_text())
            self.assertEqual(summary['endpoint_static_writers'], 2)
            self.assertEqual(summary['detected_files'], 1)
            match = json.loads((out / 'correspondence.json').read_text())
            self.assertEqual(match['task_redundancy'], 'unknown')
            self.assertTrue(any(row['introduced_in_after'] and row['endpoint_status'] == 'superseded'
                                for row in match['matches']))
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(['demo', '--out', str(out)]), 2)

    def test_existing_json_report_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'input.py'
            source.write_text('print("example")\n')
            report = root / 'report.json'
            report.write_text('existing evidence')
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(['scan', str(source), '--json', str(report)]), 2)
            self.assertEqual(report.read_text(), 'existing evidence')


if __name__ == '__main__':
    unittest.main()
