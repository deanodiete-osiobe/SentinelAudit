from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

import winreg

from sentinelaudit.windows import reg_delete_value, safe_details, run_cmd, _system_tool_path


class TestWindowsHelpers(unittest.TestCase):
    def test_safe_details_drops_none(self) -> None:
        d = safe_details(a=1, b=None, c="x")
        self.assertEqual(d, {"a": 1, "c": "x"})

    def test_reg_delete_value_missing_returns_false(self) -> None:
        with patch("sentinelaudit.windows.winreg.OpenKey", side_effect=OSError):
            ok = reg_delete_value(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\X", "Y")
            self.assertFalse(ok)

    def test_reg_delete_value_success_returns_true(self) -> None:
        key_mock = MagicMock()
        cm = MagicMock()
        cm.__enter__.return_value = key_mock
        cm.__exit__.return_value = False
        with patch("sentinelaudit.windows.winreg.OpenKey", return_value=cm):
            with patch("sentinelaudit.windows.winreg.DeleteValue") as delv:
                ok = reg_delete_value(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\X", "Y")
                self.assertTrue(ok)
                delv.assert_called_once()


class TestCommandBoundary(unittest.TestCase):
    def test_invalid_command_never_starts_process(self):
        for args in ([], "net accounts", ["net", None], ["net", "bad\0value"]):
            with patch("sentinelaudit.windows.subprocess.run") as start:
                with self.assertRaises(ValueError):
                    run_cmd(args)
                start.assert_not_called()

    def test_unapproved_executable_rejected(self):
        for name in ("cmd", "evil.exe", r"C:\temp\net.exe"):
            with self.assertRaises(ValueError):
                _system_tool_path(name)

    def test_no_shell_and_resolved_path(self):
        result = MagicMock(stdout="ok", stderr="", returncode=0)
        with patch("sentinelaudit.windows._system_tool_path", return_value=r"C:\Windows\System32\net.exe"):
            with patch("sentinelaudit.windows.subprocess.run", return_value=result) as start:
                self.assertEqual(run_cmd(["net", "accounts"], timeout_s=7).stdout, "ok")
                self.assertFalse(start.call_args.kwargs["shell"])
                self.assertEqual(start.call_args.kwargs["timeout"], 7)
                self.assertEqual(start.call_args.args[0][0], r"C:\Windows\System32\net.exe")
