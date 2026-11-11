from __future__ import annotations

import re

from sentinelaudit.audit.base import CheckContext
from sentinelaudit.models import Finding, FindingStatus, RiskLevel
from sentinelaudit.windows import run_cmd, safe_details


class ControlledFolderAccessCheck:
    finding_id = "exploit_protection.controlled_folder_access"
    name = "Exploit Protection: Controlled Folder Access"
    description = "Verifies Microsoft Defender Controlled Folder Access (CFA) status."
    risk_level = RiskLevel.medium
    fix_available = True

    def check(self, ctx: CheckContext) -> Finding:
        """
        Query CFA status via PowerShell Get-MpPreference.

        Args:
            ctx: Check context.

        Returns:
            Finding describing CFA state.
        """
        res = run_cmd(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-MpPreference).EnableControlledFolderAccess",
            ],
            timeout_s=12.0,
        )
        evidence = safe_details(
            policy_source="Command",
            evidence_command=safe_details(
                args=[
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "(Get-MpPreference).EnableControlledFolderAccess",
                ],
                exit_code=res.exit_code,
                stdout_snippet=(res.stdout[:2000] if res.stdout else ""),
                stderr_snippet=(res.stderr[:800] if res.stderr else ""),
            ),
        )
        if res.exit_code != 0:
            return Finding(
                finding_id=self.finding_id,
                name=self.name,
                risk_level=self.risk_level,
                status=FindingStatus.unknown,
                description=self.description,
                details=evidence,
                fix_available=False,
            )

        m = re.search(r"(-?\d+)", res.stdout)
        if not m:
            return Finding(
                finding_id=self.finding_id,
                name=self.name,
                risk_level=self.risk_level,
                status=FindingStatus.unknown,
                description=self.description,
                details=safe_details(**evidence, raw=res.stdout),
                fix_available=False,
            )

        value = int(m.group(1))
        status = FindingStatus.pass_ if value == 1 else FindingStatus.fail
        return Finding(
            finding_id=self.finding_id,
            name=self.name,
            risk_level=self.risk_level,
            status=status,
            description=self.description,
            details=safe_details(**evidence, enable_controlled_folder_access=value, recommended=1),
            fix_available=bool(ctx.is_admin) and value != 1,
        )

    def fix(self, ctx: CheckContext) -> Finding:
        """
        Enable CFA (Set-MpPreference).

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

        before = _get_cfa_value()
        res = run_cmd(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Set-MpPreference -EnableControlledFolderAccess Enabled",
            ],
            timeout_s=20.0,
        )
        finding = self.check(ctx)
        finding.details.update(
            safe_details(
                remediation="ok" if res.exit_code == 0 else (res.stderr or res.stdout),
                rollback_supported=isinstance(before, int),
                rollback_state={"before_cfa": before} if isinstance(before, int) else None,
            )
        )
        return finding

    def preview(self, ctx: CheckContext) -> dict[str, object]:
        current = _get_cfa_value()
        return safe_details(
            supported=True,
            is_admin=bool(ctx.is_admin),
            changes=[f"Enable Controlled Folder Access (current: {current})"],
            rollback_supported=isinstance(current, int),
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

        before = None if not rollback_state else rollback_state.get("before_cfa")
        if not isinstance(before, int):
            finding = self.check(ctx)
            finding.details.update(safe_details(rollback="not_supported"))
            return finding

        desired = "Enabled" if before == 1 else "Disabled"
        res = run_cmd(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"Set-MpPreference -EnableControlledFolderAccess {desired}",
            ],
            timeout_s=20.0,
        )
        finding = self.check(ctx)
        finding.details.update(
            safe_details(rollback="ok" if res.exit_code == 0 else (res.stderr or res.stdout))
        )
        return finding


def _get_cfa_value() -> int | None:
    res = run_cmd(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-MpPreference).EnableControlledFolderAccess",
        ],
        timeout_s=12.0,
    )
    if res.exit_code != 0:
        return None
    m = re.search(r"(-?\d+)", res.stdout)
    if not m:
        return None
    return int(m.group(1))
