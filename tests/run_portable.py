"""Run unit fixtures on non-Windows; registry calls are mocked, not OS validation."""
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
if os.name != 'nt':
    sys.modules['winreg'] = MagicMock()
result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.discover(str(Path(__file__).parent), pattern='test_*.py'))
sys.exit(not result.wasSuccessful())
