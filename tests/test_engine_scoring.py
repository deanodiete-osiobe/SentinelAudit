from __future__ import annotations

import unittest

from sentinelaudit.audit.engine import compute_hardening_score
from sentinelaudit.models import Finding, FindingStatus, RiskLevel


class TestEngineScoring(unittest.TestCase):
    def test_score_ignores_unknown(self) -> None:
        findings = [
            Finding(
                finding_id="a",
                name="A",
                risk_level=RiskLevel.low,
                status=FindingStatus.pass_,
                description="",
            ),
            Finding(
                finding_id="b",
                name="B",
                risk_level=RiskLevel.low,
                status=FindingStatus.unknown,
                description="",
            ),
            Finding(
                finding_id="c",
                name="C",
                risk_level=RiskLevel.low,
                status=FindingStatus.fail,
                description="",
            ),
        ]
        self.assertEqual(compute_hardening_score(findings), 50)

    def test_score_empty_decided_is_zero(self) -> None:
        findings = [
            Finding(
                finding_id="x",
                name="X",
                risk_level=RiskLevel.low,
                status=FindingStatus.unknown,
                description="",
            )
        ]
        self.assertEqual(compute_hardening_score(findings), 0)

