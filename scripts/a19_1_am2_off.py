#!/usr/bin/env python3
"""Exercise A19.1 AM2's explicitly metadata-disabled signed Chromium workspace."""
import os
import sys

from a19_1_demo import harness, run_off

if __name__ == '__main__':
    sys.exit(harness.main(run_off, entry=os.path.abspath(__file__), name='a19-1-off',
                          browser_required=True, description=__doc__))
