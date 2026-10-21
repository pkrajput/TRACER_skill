import unittest
from unittest.mock import Mock
from .final_validation import finalize, current_verdict


def record(passed=True, patch='new', recognized=True):
    return {'candidate_patch_sha256':patch,'status':'executed',
            'functional_result':{'test_status':'completed','pass':passed,
                                 'terminal_result':{'recognized':recognized}}}


class FinalValidationTests(unittest.TestCase):
    def invoke(self,records,run,**extra):
        args=dict(enabled=True,status='turn_limit',patch='nonempty',patch_sha256='new',records=records,run_public=run)
        args.update(extra);return finalize(**args)

    def test_third_check_after_two_old_patch_executions(self):
        records=[record(patch='old1'),record(False,patch='old2')];run=Mock(return_value=record())
        out=self.invoke(records,run)
        self.assertTrue(out['pass']);self.assertEqual(len(records),3);run.assert_called_once_with()

    def test_current_failure_never_rerolled_or_promoted(self):
        run=Mock();out=self.invoke([record(False)],run)
        self.assertFalse(out['pass']);run.assert_not_called()

    def test_current_pass_reused(self):
        run=Mock();self.assertTrue(self.invoke([record()],run)['pass']);run.assert_not_called()

    def test_missing_terminal_summary_remains_unknown(self):
        records=[];out=self.invoke(records,Mock(return_value=record(recognized=False)))
        self.assertIsNone(out['pass']);self.assertIsNone(current_verdict(records,'new'))

    def test_wrong_patch_result_cannot_validate(self):
        self.assertIsNone(self.invoke([],Mock(return_value=record(patch='stale')))['pass'])

    def test_stopped_error_noop_and_disabled_do_not_execute(self):
        for extra in [{'status':'repair_error'},{'patch':''},{'enabled':False}]:
            with self.subTest(extra=extra):
                run=Mock();self.invoke([],run,**extra);run.assert_not_called()

    def test_exception_is_recorded_without_retention(self):
        records=[];out=self.invoke(records,Mock(side_effect=RuntimeError('runtime')))
        self.assertIsNone(out['pass']);self.assertEqual(records[0]['error_type'],'RuntimeError')

if __name__=='__main__':unittest.main()
