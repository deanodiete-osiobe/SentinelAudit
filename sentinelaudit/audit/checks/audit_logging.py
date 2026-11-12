from __future__ import annotations

import re

from sentinelaudit.audit.base import CheckContext
from sentinelaudit.models import Finding, FindingStatus, RiskLevel
from sentinelaudit.windows import run_cmd, safe_details


class AuditLoggingCheck:
    finding_id = "audit_logging.logon_auditing"
    name = "Audit Logging: Logon Success/Failure"
    description = "Verifies that logon auditing is enabled for both Success and Failure events."
    risk_level = RiskLevel.high
    fix_available = True

    def check(self, ctx: CheckContext) -> Finding:
        """
        Check audit policy settings via auditpol.

        Args:
            ctx: Check context.

        Returns:
            Finding describing success/failure auditing state.
        """
        res = run_cmd(
            ["auditpol", "/get", "/subcategory:Logon"],
            timeout_s=12.0,
        )
        evidence = safe_details(
            policy_source="Command",
            evidence_command=safe_details(
                args=["auditpol", "/get", "/subcategory:Logon"],
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

        setting = _parse_auditpol_setting(res.stdout)
        if not setting:
            return Finding(
                finding_id=self.finding_id,
                name=self.name,
                risk_level=self.risk_level,
                status=FindingStatus.unknown,
                description=self.description,
                details=safe_details(**evidence, raw=res.stdout),
                fix_available=False,
            )

        normalized = setting.lower()
        ok = "success" in normalized and "failure" in normalized
        return Finding(
            finding_id=self.finding_id,
            name=self.name,
            risk_level=self.risk_level,
            status=FindingStatus.pass_ if ok else FindingStatus.fail,
            description=self.description,
            details=safe_details(**evidence, setting=setting, recommended="Success and Failure"),
            fix_available=bool(ctx.is_admin) and (not ok),
        )

    def fix(self, ctx: CheckContext) -> Finding:
        """
        Enable success and failure auditing for Logon subcategory.

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

        before_res = run_cmd(
            ["auditpol", "/get", "/subcategory:Logon"],
            timeout_s=12.0,
        )
        before_setting = (
            _parse_auditpol_setting(before_res.stdout) if before_res.exit_code == 0 else None
        )
        res = run_cmd(
            [
                "auditpol",
                "/set",
                "/subcategory:Logon",
                "/success:enable",
                "/failure:enable",
            ],
            timeout_s=12.0,
        )
        finding = self.check(ctx)
        finding.details.update(
            safe_details(
                remediation="ok" if res.exit_code == 0 else (res.stderr or res.stdout),
                rollback_supported=bool(before_setting),
                rollback_state={"before_setting": before_setting} if before_setting else None,
            )
        )
        return finding

    def preview(self, ctx: CheckContext) -> dict[str, object]:
        res = run_cmd(["auditpol", "/get", "/subcategory:Logon"], timeout_s=12.0)
        if res.exit_code != 0:
            return safe_details(supported=False, error=res.stderr or res.stdout)
        setting = _parse_auditpol_setting(res.stdout)
        return safe_details(
            supported=True,
            is_admin=bool(ctx.is_admin),
            changes=[
                f"Enable Logon auditing for Success and Failure (current: {setting or 'Unknown'})"
            ],
            rollback_supported=bool(setting),
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

        before_setting = None if not rollback_state else rollback_state.get("before_setting")
        if not isinstance(before_setting, str) or not before_setting.strip():
            finding = self.check(ctx)
            finding.details.update(safe_details(rollback="not_supported"))
            return finding

        success = "enable" if "success" in before_setting.lower() else "disable"
        failure = "enable" if "failure" in before_setting.lower() else "disable"
        if "no auditing" in before_setting.lower():
            success = "disable"
            failure = "disable"

        res = run_cmd(
            [
                "auditpol",
                "/set",
                "/subcategory:Logon",
                f"/success:{success}",
                f"/failure:{failure}",
            ],
            timeout_s=12.0,
        )
        finding = self.check(ctx)
        finding.details.update(
            safe_details(rollback="ok" if res.exit_code == 0 else (res.stderr or res.stdout))
        )
        return finding


def _parse_auditpol_setting(output: str) -> str | None:
    for line in output.splitlines():
        if not line.strip():
            continue
        if re.search(r"\sLogon\s", line, flags=re.I):
            parts = re.split(r"\s{2,}", line.strip())
            if len(parts) >= 3:
                return parts[-1].strip()
    return None
