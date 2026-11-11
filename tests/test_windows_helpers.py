from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

import winreg

from sentinelaudit.windows import reg_delete_value, safe_details


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

