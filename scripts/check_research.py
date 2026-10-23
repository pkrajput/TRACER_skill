"""Run the frozen maintenance protocol tests without provider or socket access."""
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]

def main():
    sys.path.insert(0,str(ROOT/'research/frozen_pipeline'))
    modules=['paper.rq5_factorial.test_protocol','paper.silent_feature.test_scrub',
             'paper.bio_study.test_splice']
    with patch.object(socket.socket,'connect',side_effect=RuntimeError('Network disabled')), \
         patch.object(socket,'create_connection',side_effect=RuntimeError('Network disabled')):
        suite=unittest.defaultTestLoader.loadTestsFromNames(modules)
        result=unittest.TextTestRunner(verbosity=1).run(suite)
    return 0 if result.wasSuccessful() else 1

if __name__=='__main__':raise SystemExit(main())
