from __future__ import annotations

from datetime import datetime, timedelta, timezone

import winreg

from sentinelaudit.audit.base import CheckContext
from sentinelaudit.models import Finding, FindingStatus, RiskLevel
from sentinelaudit.windows import reg_get_str, safe_details


class WindowsUpdateLastSuccessCheck:
    finding_id = "update_integrity.windows_update_last_success"
    name = "Update Integrity: Windows Update Last Success"
    description = (
        "Checks the last successful Windows Update install timestamp and flags stale patching."
    )
    risk_level = RiskLevel.medium
    fix_available = False

    _key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install"
    _value_name = "LastSuccessTime"

    def check(self, ctx: CheckContext) -> Finding:
        """
        Check Windows Update last success timestamp from registry.

        Args:
            ctx: Check context.

        Returns:
            Finding with age of last success.
        """
        raw = reg_get_str(winreg.HKEY_LOCAL_MACHINE, self._key_path, self._value_name)
        if not raw:
            return Finding(
                finding_id=self.finding_id,
                name=self.name,
                risk_level=self.risk_level,
                status=FindingStatus.unknown,
                description=self.description,
                details=safe_details(note="LastSuccessTime not present."),
                fix_available=False,
            )

        parsed = _parse_windows_update_time(raw)
        if not parsed:
            return Finding(
                finding_id=self.finding_id,
                name=self.name,
                risk_level=self.risk_level,
                status=FindingStatus.unknown,
                description=self.description,
                details=safe_details(
                    policy_source="Registry",
                    evidence_registry=[
                        {
                            "key_path": f"HKLM\\{self._key_path}",
                            "value_name": self._value_name,
                            "value": raw,
                        }
                    ],
                    last_success_raw=raw,
                ),
                fix_available=False,
            )

        now = datetime.now(timezone.utc)
        age_days = int((now - parsed).total_seconds() // 86400)
        stale = now - parsed > timedelta(days=30)
        return Finding(
            finding_id=self.finding_id,
            name=self.name,
            risk_level=self.risk_level,
            status=FindingStatus.fail if stale else FindingStatus.pass_,
            description=self.description,
            details=safe_details(
                policy_source="Registry",
                evidence_registry=[
                    {
                        "key_path": f"HKLM\\{self._key_path}",
                        "value_name": self._value_name,
                        "value": raw,
                    }
                ],
                last_success_utc=parsed.isoformat(),
                age_days=age_days,
                stale_days=30,
            ),
            fix_available=False,
        )

    def fix(self, ctx: CheckContext) -> Finding:
        """
        Windows Update is not automatically remediated.

        Args:
            ctx: Check context.

        Returns:
            Current finding.
        """
        return self.check(ctx)


def _parse_windows_update_time(value: str) -> datetime | None:
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue
    return None
