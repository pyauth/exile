#!/usr/bin/env python

import os, sys, unittest, json, collections

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))  # noqa

from exile import YKOATH, SCardManager

class TestExile(unittest.TestCase):
    def test_exile(self):
        ykoath = YKOATH(SCardManager())

if __name__ == '__main__':
    unittest.main()
