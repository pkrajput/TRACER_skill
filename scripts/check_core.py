"""Run the shipped local regression suite with socket access disabled."""
import socket
import unittest
from unittest.mock import patch

def main():
    roots=['planner','citations','history','rationale','change_symmetry','unseeded_gate',
           'final_validation','flow_context','engine','v10_protocol','v11_cards','v12']
    modules=['security_ground_truth.temporal_security.test_'+name for name in roots]
    with patch.object(socket.socket,'connect',side_effect=RuntimeError('Network disabled for artifact regression tests')), \
         patch.object(socket,'create_connection',side_effect=RuntimeError('Network disabled for artifact regression tests')):
        suite=unittest.defaultTestLoader.loadTestsFromNames(modules)
        result=unittest.TextTestRunner(verbosity=1).run(suite)
    return 0 if result.wasSuccessful() else 1

if __name__=='__main__':raise SystemExit(main())
