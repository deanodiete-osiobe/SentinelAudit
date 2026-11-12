from __future__ import annotations

import unittest
from datetime import timezone

from sentinelaudit.audit.checks.windows_update import _parse_windows_update_time


class TestWindowsUpdateParser(unittest.TestCase):
    def test_parse_basic_format(self) -> None:
        dt = _parse_windows_update_time("2026-01-02 03:04:05")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.tzinfo, timezone.utc)
        self.assertEqual(dt.year, 2026)
        self.assertEqual(dt.month, 1)
        self.assertEqual(dt.day, 2)

    def test_parse_invalid_returns_none(self) -> None:
        self.assertIsNone(_parse_windows_update_time("not-a-date"))

