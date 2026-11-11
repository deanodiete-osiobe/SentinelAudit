from __future__ import annotations

import re

import tempfile
from pathlib import Path

from sentinelaudit.audit.base import CheckContext
from sentinelaudit.models import Finding, FindingStatus, RiskLevel
from sentinelaudit.windows import run_cmd, safe_details


class PasswordPolicyCheck:
    finding_id = "credential_protection.password_policy"
    name = "Credential Protection: Password Policy"
    description = "Verifies minimum password length and local password complexity policy."
    risk_level = RiskLevel.high
    fix_available = True

    def check(self, ctx: CheckContext) -> Finding:
        """
        Check password policy via net accounts + registry.

        Args:
            ctx: Check context.

        Returns:
            Finding with min length + complexity status.
        """
        policy = _export_password_policy()
        min_len = policy.get("MinimumPasswordLength")
        complexity = policy.get("PasswordComplexity")
        evidence = safe_details(policy_source="secedit securitypolicy export",
                                scope="Local computer policy; not a domain user password-policy assessment")

        if min_len is None and complexity is None:
            return Finding(
                finding_id=self.finding_id,
                name=self.name,
                risk_level=self.risk_level,
                status=FindingStatus.unknown,
                description=self.description,
                details=safe_details(**evidence, note="Unable to export local security policy."),
                fix_available=False,
            )

        meets_min = (min_len is not None) and (min_len >= 14)
        meets_complexity = (complexity is not None) and (complexity == 1)

        if min_len is None or complexity is None:
            status = FindingStatus.unknown
        else:
            status = FindingStatus.pass_ if (meets_min and meets_complexity) else FindingStatus.fail

        return Finding(
            finding_id=self.finding_id,
            name=self.name,
            risk_level=self.risk_level,
            status=status,
            description=self.description,
            details=safe_details(
                **evidence,
                min_password_length=min_len,
                password_complexity=complexity,
                target_min_length=14,
                target_complexity=1,
            ),
            fix_available=bool(ctx.is_admin) and (min_len is not None and min_len < 14),
        )

    def fix(self, ctx: CheckContext) -> Finding:
        """
        Raise minimum password length to 14 characters (does not change complexity).

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

        before_min_len = _net_accounts_min_pw_len()
        if before_min_len is None or before_min_len >= 14:
            return self.check(ctx)
        res = run_cmd(["net", "accounts", "/minpwlen:14"], timeout_s=10.0)
        finding = self.check(ctx)
        finding.details.update(
            safe_details(
                remediation="ok" if res.exit_code == 0 else (res.stderr or res.stdout),
                rollback_supported=isinstance(before_min_len, int),
                rollback_state={"before_min_pw_len": before_min_len}
                if isinstance(before_min_len, int)
                else None,
            )
        )
        return finding

    def preview(self, ctx: CheckContext) -> dict[str, object]:
        current = _net_accounts_min_pw_len()
        return safe_details(
            supported=True,
            is_admin=bool(ctx.is_admin),
            changes=[f"Set minimum password length to 14 (current: {current})"],
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

        before_min_len = None if not rollback_state else rollback_state.get("before_min_pw_len")
        if not isinstance(before_min_len, int):
            finding = self.check(ctx)
            finding.details.update(safe_details(rollback="not_supported"))
            return finding

        res = run_cmd(["net", "accounts", f"/minpwlen:{before_min_len}"], timeout_s=10.0)
        finding = self.check(ctx)
        finding.details.update(
            safe_details(rollback="ok" if res.exit_code == 0 else (res.stderr or res.stdout))
        )
        return finding


def _export_password_policy() -> dict[str, int]:
    with tempfile.TemporaryDirectory(prefix="sentinel-policy-") as directory:
        target = Path(directory) / "policy.inf"
        result = run_cmd(["secedit.exe", "/export", "/cfg", str(target),
                          "/areas", "SECURITYPOLICY", "/log", str(Path(directory) / "export.log"), "/quiet"], timeout_s=30)
        if result.exit_code != 0 or not target.exists():
            return {}
        raw = target.read_bytes()
        text = raw.decode("utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig", errors="replace")
        return {key: int(value) for key, value in re.findall(
            r"^\s*(MinimumPasswordLength|PasswordComplexity)\s*=\s*(\d+)\s*$", text, re.M)}


def _net_accounts_min_pw_len() -> int | None:
    return _export_password_policy().get("MinimumPasswordLength")


def _parse_net_accounts_min_pw_len(stdout: str) -> int | None:
    m = re.search(r"^\s*Minimum password length\s*:\s*(\d+)\s*$", stdout or "", flags=re.I | re.M)
    if not m:
        return None
    return int(m.group(1))
