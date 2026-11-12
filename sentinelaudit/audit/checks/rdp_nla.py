from __future__ import annotations

import winreg

from sentinelaudit.audit.base import CheckContext
from sentinelaudit.models import Finding, FindingStatus, RiskLevel
from sentinelaudit.windows import reg_get_dword, reg_set_dword, safe_details


class RdpNetworkLevelAuthCheck:
    finding_id = "secure_config.rdp_nla_enabled"
    name = "Secure Config: RDP Network Level Authentication (NLA)"
    description = "Verifies RDP requires Network Level Authentication to reduce brute-force and pre-auth exposure."
    risk_level = RiskLevel.high
    fix_available = True

    _key_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    _value_name = "UserAuthentication"
    _recommended = 1

    def check(self, ctx: CheckContext) -> Finding:
        current = reg_get_dword(winreg.HKEY_LOCAL_MACHINE, self._key_path, self._value_name)
        evidence = safe_details(
            policy_source="Registry",
            evidence_registry=[
                {
                    "key_path": f"HKLM\\{self._key_path}",
                    "value_name": self._value_name,
                    "value": current,
                }
            ],
        )
        if current is None:
            return Finding(
                finding_id=self.finding_id,
                name=self.name,
                risk_level=self.risk_level,
                status=FindingStatus.unknown,
                description=self.description,
                details=safe_details(
                    **evidence,
                    note="Unable to read RDP NLA registry setting.",
                    key_path=f"HKLM\\{self._key_path}",
                    value_name=self._value_name,
                    recommended=self._recommended,
                ),
                fix_available=False,
            )

        ok = int(current) == self._recommended
        return Finding(
            finding_id=self.finding_id,
            name=self.name,
            risk_level=self.risk_level,
            status=FindingStatus.pass_ if ok else FindingStatus.fail,
            description=self.description,
            details=safe_details(
                **evidence,
                current=current,
                recommended=self._recommended,
                key_path=f"HKLM\\{self._key_path}",
                value_name=self._value_name,
            ),
            fix_available=bool(ctx.is_admin) and (not ok),
        )

    def preview(self, ctx: CheckContext) -> dict[str, object]:
        current = reg_get_dword(winreg.HKEY_LOCAL_MACHINE, self._key_path, self._value_name)
        return safe_details(
            supported=True,
            is_admin=bool(ctx.is_admin),
            changes=[
                f"Set HKLM\\{self._key_path}\\{self._value_name} to {self._recommended} (current: {current})"
            ],
            rollback_supported=isinstance(current, int),
        )

    def fix(self, ctx: CheckContext) -> Finding:
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
                rollback_supported=isinstance(before, int),
                rollback_state={"previous_value": before} if isinstance(before, int) else None,
            )
        )
        return finding

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
