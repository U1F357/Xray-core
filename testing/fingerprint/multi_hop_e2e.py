#!/usr/bin/env python3
"""Three-hop variant of the shared real-runsc packet capture harness."""
import os
import runpy
from pathlib import Path
os.environ['XRAY_FP_MULTI_HOP'] = '1'
runpy.run_path(str(Path(__file__).with_name('auto_select_e2e.py')), run_name='__main__')
