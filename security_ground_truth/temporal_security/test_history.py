import json
from pathlib import Path
import tempfile
import unittest

from security_ground_truth.runtime.history.adapter import write_gzip_json
from .gumtree import digest
from .history import build_case_history


class FrozenHistoryTests(unittest.TestCase):
    def test_pinned_prepared_view_does_not_depend_on_ephemeral_raw_trace_path(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);path=root/'view.json.gz'
            trace_hash='a'*64
            view={'arm':'B4','source_trace_sha256':trace_hash,'cutoff_message':4,
                  'states':[],'edit_records':[],'events':[],'rationale_links':{}}
            write_gzip_json(path,view)
            case={'case_key':'b'*24,'record_id':'record','trajectory_sha256':trace_hash,
                  'trajectory_path':str(root/'missing-raw.json.gz'),'history_paths':{'B4':str(root/'missing-view.json.gz')},
                  'archived_history_path':str(path),'archived_history_sha256':digest(path.read_bytes()),
                  'archived_history_screening':{'status':'prepared_view_cutoff_applied'}}
            result=build_case_history(case,[{'path':'app.py','symbol':'f'}])
            self.assertEqual(result['rationale']['status'],'no_target_linked_exposed_rationale')
            self.assertTrue(result['provenance']['screening']['archived_normalized_view'])
            case['archived_history_sha256']='0'*64
            with self.assertRaisesRegex(ValueError,'SHA-256 mismatch'):
                build_case_history(case,[{'path':'app.py','symbol':'f'}])


if __name__=='__main__':unittest.main()
