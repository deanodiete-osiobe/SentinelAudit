import unittest
from types import SimpleNamespace
from unittest.mock import patch
import build_exe


class BuildRecipeTests(unittest.TestCase):
    def test_build_invokes_pyinstaller_module(self):
        with patch.object(build_exe, 'os', SimpleNamespace(name='nt')):
            with patch.object(build_exe.shutil, 'which', return_value='/trusted/npm.cmd'):
                with patch.object(build_exe.importlib.util, 'find_spec', return_value=object()):
                    with patch.object(build_exe.Path, 'is_file', return_value=True):
                        with patch.object(build_exe.subprocess, 'run') as run:
                            build_exe.main()
        self.assertEqual(run.call_count, 3)
        self.assertEqual(run.call_args.args[0][1:], ['-m', 'PyInstaller', '--noconfirm', '--clean', 'SentinelAudit.spec'])
        self.assertFalse(run.call_args.kwargs['shell'])
