from __future__ import annotations

import winreg

from sentinelaudit.audit.base import CheckContext
from sentinelaudit.models import Finding, FindingStatus, RiskLevel
from sentinelaudit.windows import reg_get_dword, reg_set_dword, safe_details


class AutorunAutoplayCheck:
    finding_id = "device_control.autorun_autoplay"
    name = "Device Control: Disable Autorun/Autoplay"
    description = (
        "Verifies that Autorun/Autoplay is disabled to reduce removable-media based malware execution."
    )
    risk_level = RiskLevel.high
    fix_available = True

    _key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    _value_name = "NoDriveTypeAutoRun"
    _recommended = 255

    def check(self, ctx: CheckContext) -> Finding:
        """
        Check registry policy for Autorun/Autoplay.

        Args:
            ctx: Check context.

        Returns:
            Finding describing current policy.
        """
        value = reg_get_dword(winreg.HKEY_LOCAL_MACHINE, self._key_path, self._value_name)
        evidence = safe_details(
            policy_source="Registry",
            evidence_registry=[
                {
                    "key_path": f"HKLM\\{self._key_path}",
                    "value_name": self._value_name,
                    "value": value,
                }
            ],
        )
        if value is None:
            return Finding(
                finding_id=self.finding_id,
                name=self.name,
                risk_level=self.risk_level,
                status=FindingStatus.unknown,
                description=self.description,
                details=safe_details(**evidence, note="Registry value not present or not readable."),
                fix_available=bool(ctx.is_admin),
            )

        status = FindingStatus.pass_ if value == self._recommended else FindingStatus.fail
        return Finding(
            finding_id=self.finding_id,
            name=self.name,
            risk_level=self.risk_level,
            status=status,
            description=self.description,
            details=safe_details(
                **evidence,
                hive="HKLM",
                key_path=self._key_path,
                value_name=self._value_name,
                current=value,
                recommended=self._recommended,
            ),
            fix_available=bool(ctx.is_admin) and value != self._recommended,
        )

    def fix(self, ctx: CheckContext) -> Finding:
        """
        Set NoDriveTypeAutoRun to 255 in HKLM policy key.

        Args:
            ctx: Check context.

        Returns:
            Updated Finding after remediation attempt.
        """
        if not ctx.is_admin:
            return Finding(
                finding_id=self.finding_id,
                name=self.name,
                risk_level=self.risk_level,
                status=FindingStatus.fail,
                description=self.description,
                details=safe_details(error="Administrative privileges required."),
                fix_available=False,
            )

        before = reg_get_dword(winreg.HKEY_LOCAL_MACHINE, self._key_path, self._value_name)
        reg_set_dword(winreg.HKEY_LOCAL_MACHINE, self._key_path, self._value_name, self._recommended)
        finding = self.check(ctx)
        finding.details.update(
            safe_details(
                remediation="ok",
                rollback_supported=before is not None,
                rollback_state={"previous_value": before} if before is not None else None,
            )
        )
        return finding

    def preview(self, ctx: CheckContext) -> dict[str, object]:
        current = reg_get_dword(winreg.HKEY_LOCAL_MACHINE, self._key_path, self._value_name)
        return safe_details(
            supported=True,
            is_admin=bool(ctx.is_admin),
            changes=[
                f"Set HKLM\\{self._key_path}\\{self._value_name} to {self._recommended} (current: {current})"
            ],
            rollback_supported=current is not None,
        )

    def rollback(self, ctx: CheckContext, rollback_state: dict[str, object] | None) -> Finding:
        if not ctx.is_admin:
            return Finding(
                finding_id=self.finding_id,
                name=self.name,
                risk_level=self.risk_level,
                status=FindingStatus.fail,
                description=self.description,
                details=safe_details(error="Administrative privileges required."),
                fix_available=False,
            )

        prev = None if not rollback_state else rollback_state.get("previous_value")
        if not isinstance(prev, int):
            finding = self.check(ctx)
            finding.details.update(safe_details(rollback="not_supported"))
            return finding

        reg_set_dword(winreg.HKEY_LOCAL_MACHINE, self._key_path, self._value_name, prev)
        finding = self.check(ctx)
        finding.details.update(safe_details(rollback="ok"))
        return finding
