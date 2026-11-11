from __future__ import annotations

import re

from sentinelaudit.audit.base import CheckContext
from sentinelaudit.models import Finding, FindingStatus, RiskLevel
from sentinelaudit.windows import run_cmd, safe_details


class AccountSecurityCheck:
    finding_id = "account_security.local_builtin_accounts"
    name = "Account Security: Built-in Guest/Administrator Status"
    description = (
        "Verifies whether built-in Guest and Administrator accounts are disabled to reduce "
        "credential abuse and lateral movement opportunities."
    )
    risk_level = RiskLevel.high
    fix_available = True

    def check(self, ctx: CheckContext) -> Finding:
        """
        Check whether Guest and Administrator are disabled.

        Args:
            ctx: Check context.

        Returns:
            Finding with pass/fail/unknown status.
        """
        admin_res = run_cmd(["net", "user", "Administrator"], timeout_s=10.0)
        guest_res = run_cmd(["net", "user", "Guest"], timeout_s=10.0)
        admin_active = _parse_net_user_account_active(admin_res.stdout) if admin_res.exit_code == 0 else None
        guest_active = _parse_net_user_account_active(guest_res.stdout) if guest_res.exit_code == 0 else None

        evidence = safe_details(
            policy_source="Command",
            evidence_command=[
                safe_details(
                    args=["net", "user", "Administrator"],
                    exit_code=admin_res.exit_code,
                    stdout_snippet=(admin_res.stdout[:1500] if admin_res.stdout else ""),
                    stderr_snippet=(admin_res.stderr[:500] if admin_res.stderr else ""),
                ),
                safe_details(
                    args=["net", "user", "Guest"],
                    exit_code=guest_res.exit_code,
                    stdout_snippet=(guest_res.stdout[:1500] if guest_res.stdout else ""),
                    stderr_snippet=(guest_res.stderr[:500] if guest_res.stderr else ""),
                ),
            ],
        )

        if admin_active is None and guest_active is None:
            return Finding(
                finding_id=self.finding_id,
                name=self.name,
                risk_level=self.risk_level,
                status=FindingStatus.unknown,
                description=self.description,
                details=safe_details(**evidence, note="Unable to query account status via net.exe"),
                fix_available=False,
            )

        if admin_active is None or guest_active is None:
            status = FindingStatus.unknown
        else:
            status = (
                FindingStatus.pass_
                if (admin_active is False and guest_active is False)
                else FindingStatus.fail
            )
        return Finding(
            finding_id=self.finding_id,
            name=self.name,
            risk_level=self.risk_level,
            status=status,
            description=self.description,
            details=safe_details(
                **evidence,
                administrator_active=admin_active,
                guest_active=guest_active,
            ),
            fix_available=bool(ctx.is_admin) and status == FindingStatus.fail,
        )

    def fix(self, ctx: CheckContext) -> Finding:
        """
        Attempt to disable built-in Guest and Administrator accounts.

        Args:
            ctx: Check context.

        Returns:
            Updated Finding after attempting remediation.
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

        before_admin_active = _net_user_account_active("Administrator")
        before_guest_active = _net_user_account_active("Guest")

        actions: dict[str, str] = {}
        for account in ("Guest", "Administrator"):
            res = run_cmd(["net", "user", account, "/active:no"], timeout_s=10.0)
            actions[account] = "ok" if res.exit_code == 0 else (res.stderr or res.stdout or "error")

        finding = self.check(ctx)
        rollback_supported = before_admin_active is not None and before_guest_active is not None
        finding.details.update(
            safe_details(
                remediation=actions,
                rollback_supported=rollback_supported,
                rollback_state=(
                    {"before_administrator_active": before_admin_active, "before_guest_active": before_guest_active}
                    if rollback_supported
                    else None
                ),
            )
        )
        return finding

    def preview(self, ctx: CheckContext) -> dict[str, object]:
        admin_active = _net_user_account_active("Administrator")
        guest_active = _net_user_account_active("Guest")
        changes: list[str] = []
        if admin_active is not False:
            changes.append(f"Disable built-in Administrator account (current: {admin_active})")
        if guest_active is not False:
            changes.append(f"Disable built-in Guest account (current: {guest_active})")
        if not changes:
            changes.append("No changes required (Guest and Administrator are already disabled).")
        rollback_supported = admin_active is not None and guest_active is not None
        return safe_details(
            supported=True,
            is_admin=bool(ctx.is_admin),
            changes=changes,
            rollback_supported=rollback_supported,
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

        if not rollback_state:
            finding = self.check(ctx)
            finding.details.update(safe_details(rollback="not_supported"))
            return finding

        before_admin = rollback_state.get("before_administrator_active")
        before_guest = rollback_state.get("before_guest_active")
        if not isinstance(before_admin, bool) or not isinstance(before_guest, bool):
            finding = self.check(ctx)
            finding.details.update(safe_details(rollback="not_supported"))
            return finding

        actions: dict[str, str] = {}
        actions["Administrator"] = (
            "ok"
            if run_cmd(
                ["net", "user", "Administrator", f"/active:{'yes' if before_admin else 'no'}"],
                timeout_s=10.0,
            ).exit_code
            == 0
            else "error"
        )
        actions["Guest"] = (
            "ok"
            if run_cmd(
                ["net", "user", "Guest", f"/active:{'yes' if before_guest else 'no'}"],
                timeout_s=10.0,
            ).exit_code
            == 0
            else "error"
        )

        finding = self.check(ctx)
        finding.details.update(safe_details(rollback=actions))
        return finding


def _net_user_account_active(account_name: str) -> bool | None:
    res = run_cmd(["net", "user", account_name], timeout_s=10.0)
    if res.exit_code != 0:
        return None
    return _parse_net_user_account_active(res.stdout)


def _parse_net_user_account_active(stdout: str) -> bool | None:
    m = re.search(r"^\s*Account active\s+(\w+)\s*$", stdout or "", flags=re.IGNORECASE | re.MULTILINE)
    if not m:
        return None
    return m.group(1).strip().lower() in ("yes", "y", "true")
