from __future__ import annotations

import re

from sentinelaudit.audit.base import CheckContext
from sentinelaudit.models import Finding, FindingStatus, RiskLevel
from sentinelaudit.windows import run_cmd, safe_details


class FirewallProfilesCheck:
    finding_id = "network_defense.firewall_profiles"
    name = "Network Defense: Windows Firewall Profiles"
    description = "Verifies that Windows Firewall is enabled for Domain, Private, and Public profiles."
    risk_level = RiskLevel.high
    fix_available = True

    def check(self, ctx: CheckContext) -> Finding:
        """
        Check Windows Firewall status for all profiles.

        Args:
            ctx: Check context.

        Returns:
            Finding with per-profile state.
        """
        res = run_cmd(["netsh", "advfirewall", "show", "allprofiles"], timeout_s=12.0)
        evidence = safe_details(
            policy_source="Command",
            evidence_command=safe_details(
                args=["netsh", "advfirewall", "show", "allprofiles"],
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

        profile_states = _parse_firewall_states(res.stdout)
        if set(profile_states) != {"domain", "private", "public"}:
            return Finding(
                finding_id=self.finding_id,
                name=self.name,
                risk_level=self.risk_level,
                status=FindingStatus.unknown,
                description=self.description,
                details=safe_details(**evidence, note="Unable to parse netsh output."),
                fix_available=False,
            )

        all_on = all(v == "ON" for v in profile_states.values())
        return Finding(
            finding_id=self.finding_id,
            name=self.name,
            risk_level=self.risk_level,
            status=FindingStatus.pass_ if all_on else FindingStatus.fail,
            description=self.description,
            details=safe_details(**evidence, **{f"{k}_state": v for k, v in profile_states.items()}),
            fix_available=bool(ctx.is_admin) and (not all_on),
        )

    def fix(self, ctx: CheckContext) -> Finding:
        """
        Enable Windows Firewall for all profiles.

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

        before_res = run_cmd(["netsh", "advfirewall", "show", "allprofiles"], timeout_s=12.0)
        before_states = (
            _parse_firewall_states(before_res.stdout) if before_res.exit_code == 0 else {}
        )
        res = run_cmd(["netsh", "advfirewall", "set", "allprofiles", "state", "on"], timeout_s=12.0)
        finding = self.check(ctx)
        rollback_supported = set(before_states) == {"domain", "private", "public"}
        finding.details.update(
            safe_details(
                remediation="ok" if res.exit_code == 0 else (res.stderr or res.stdout),
                rollback_supported=rollback_supported,
                rollback_state=before_states if rollback_supported else None,
            )
        )
        return finding

    def preview(self, ctx: CheckContext) -> dict[str, object]:
        res = run_cmd(["netsh", "advfirewall", "show", "allprofiles"], timeout_s=12.0)
        if res.exit_code != 0:
            return safe_details(supported=False, error=res.stderr or res.stdout)
        states = _parse_firewall_states(res.stdout)
        if set(states) != {"domain", "private", "public"}:
            return safe_details(supported=False, error="Unable to parse netsh output.")
        changes: list[str] = []
        for profile in ("domain", "private", "public"):
            current = states.get(profile)
            if current and current != "ON":
                changes.append(f"Enable Windows Firewall for {profile.title()} profile (current: {current})")
        if not changes:
            changes.append("No changes required (all profiles already ON).")
        return safe_details(
            supported=True,
            is_admin=bool(ctx.is_admin),
            changes=changes,
            rollback_supported=bool(states),
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

        errors: list[str] = []
        mapping = {"domain": "domainprofile", "private": "privateprofile", "public": "publicprofile"}
        for profile, netsh_profile in mapping.items():
            state = rollback_state.get(profile)
            if not isinstance(state, str):
                continue
            desired = "on" if state.upper() == "ON" else "off"
            res = run_cmd(
                ["netsh", "advfirewall", "set", netsh_profile, "state", desired],
                timeout_s=12.0,
            )
            if res.exit_code != 0:
                errors.append(f"{profile}:{res.stderr or res.stdout}")

        finding = self.check(ctx)
        finding.details.update(safe_details(rollback="ok" if not errors else "\n".join(errors)))
        return finding


def _parse_firewall_states(output: str) -> dict[str, str]:
    current_profile: str | None = None
    states: dict[str, str] = {}

    for line in output.splitlines():
        header = re.match(
            r"^\s*(Domain|Private|Public)\s+Profile\s+Settings\b.*$",
            line,
            flags=re.I,
        )
        if header:
            current_profile = header.group(1).strip().lower()
            continue
        if not current_profile:
            continue
        m = re.match(r"^\s*State\b.*\b(ON|OFF)\b\s*$", line, flags=re.I)
        if m:
            states[current_profile] = m.group(1).strip().upper()

    return states
