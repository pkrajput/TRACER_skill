import unittest
from paper.rq5_factorial.run import ARMS,feedback,gate_pass,combine

class ProtocolTests(unittest.TestCase):
    def test_security_cannot_enter_functional_feedback_or_retry_decision(self):
        receipt={k:{'status':'pass'} for k in ('application','functional','feature')}
        receipt.update(boundary={'status':'fail'},saved_boundary={'status':'fail','error':'SECRET'},extended_boundary={'status':'unknown'})
        for arm in ('B0','B1'):
            self.assertTrue(gate_pass(receipt,ARMS[arm][1]))
            self.assertEqual(set(feedback(receipt,ARMS[arm][1])),{'application','functional','feature'})
        for arm in ('B2','B3'):
            self.assertFalse(gate_pass(receipt,ARMS[arm][1]))
            self.assertIn('saved_boundary',feedback(receipt,ARMS[arm][1]))

    def test_unknown_is_not_an_observed_violation_or_a_pass(self):
        self.assertEqual(combine([{'status':'pass'},{'status':'unknown'}]),'unknown')
        self.assertEqual(combine([{'status':'fail'},{'status':'unknown'}]),'fail')
        self.assertEqual(combine([{'status':'pass'},{'status':'pass'}]),'pass')

if __name__=='__main__':unittest.main()
