from __future__ import annotations

from sentinelaudit.audit.base import CheckContext
from sentinelaudit.models import Finding, FindingStatus, RiskLevel
from sentinelaudit.windows import run_cmd, safe_details


def _parse_net_localgroup(stdout: str) -> list[str]:
    lines = [ln.rstrip() for ln in (stdout or "").splitlines()]
    members: list[str] = []
    in_list = False
    for ln in lines:
        if ln.strip().startswith("---"):
            in_list = True
            continue
        if not in_list:
            continue
        if "The command completed successfully" in ln:
            break
        value = ln.strip()
        if not value:
            continue
        members.append(value)
    return members


class LocalAdministratorsGroupReviewCheck:
    finding_id = "identity_access.local_administrators_group_review"
    name = "Identity & Access: Local Administrators Group Review"
    description = "Lists local Administrators group membership and flags obvious overly-broad entries."
    risk_level = RiskLevel.medium
    fix_available = False

    def check(self, ctx: CheckContext) -> Finding:
        res = run_cmd(["net", "localgroup", "administrators"], timeout_s=15.0)
        evidence = safe_details(
            policy_source="Command",
            evidence_command=safe_details(
                args=["net", "localgroup", "administrators"],
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

        members = _parse_net_localgroup(res.stdout)
        risky = []
        for m in members:
            ml = m.lower()
            if ml in ("everyone", "domain users", "authenticated users"):
                risky.append(m)
        status = FindingStatus.fail if risky else FindingStatus.pass_

        details = safe_details(
            **evidence,
            members=members,
            risky_members=risky,
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
