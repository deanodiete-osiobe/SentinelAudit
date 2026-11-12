from __future__ import annotations

import winreg

from sentinelaudit.audit.base import CheckContext
from sentinelaudit.models import Finding, FindingStatus, RiskLevel
from sentinelaudit.windows import reg_get_dword, safe_details


class WindowsUpdatePolicyComplianceCheck:
    finding_id = "update_integrity.windows_update_policy_compliance"
    name = "Update Integrity: Windows Update Policy Compliance"
    description = "Checks common Windows Update policy settings for compliance (e.g., not disabled via policy)."
    risk_level = RiskLevel.medium
    fix_available = False

    _au_key = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

    def check(self, ctx: CheckContext) -> Finding:
        no_auto = reg_get_dword(winreg.HKEY_LOCAL_MACHINE, self._au_key, "NoAutoUpdate")
        au_options = reg_get_dword(winreg.HKEY_LOCAL_MACHINE, self._au_key, "AUOptions")
        sched_day = reg_get_dword(winreg.HKEY_LOCAL_MACHINE, self._au_key, "ScheduledInstallDay")
        sched_time = reg_get_dword(winreg.HKEY_LOCAL_MACHINE, self._au_key, "ScheduledInstallTime")

        evidence = [
            {"key_path": f"HKLM\\{self._au_key}", "value_name": "NoAutoUpdate", "value": no_auto},
            {"key_path": f"HKLM\\{self._au_key}", "value_name": "AUOptions", "value": au_options},
            {"key_path": f"HKLM\\{self._au_key}", "value_name": "ScheduledInstallDay", "value": sched_day},
            {"key_path": f"HKLM\\{self._au_key}", "value_name": "ScheduledInstallTime", "value": sched_time},
        ]

        if all(v["value"] is None for v in evidence):
            return Finding(
                finding_id=self.finding_id,
                name=self.name,
                risk_level=self.risk_level,
                status=FindingStatus.unknown,
                description=self.description,
                details=safe_details(policy_source="Registry", evidence_registry=evidence, note="No WSUS/GPO policy values found."),
                fix_available=False,
            )

        disabled = isinstance(no_auto, int) and int(no_auto) == 1
        status = FindingStatus.fail if disabled else FindingStatus.pass_

        details = safe_details(
            policy_source="Registry",
            evidence_registry=evidence,
            evaluation=safe_details(no_auto_update=bool(disabled)),
        )
        return Finding(
            finding_id=self.finding_id,
            name=self.name,
            risk_level=self.risk_level,
            status=status,
            description=self.description,
            details=details,
            fix_available=False,
        )

    def fix(self, ctx: CheckContext) -> Finding:
        return self.check(ctx)
