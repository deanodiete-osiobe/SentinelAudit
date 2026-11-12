from __future__ import annotations

import re

from sentinelaudit.audit.base import CheckContext
from sentinelaudit.models import Finding, FindingStatus, RiskLevel
from sentinelaudit.windows import run_cmd, safe_details


class RiskyServicesCheck:
    finding_id = "service_hardening.high_risk_services"
    name = "Service Hardening: High-Risk Services"
    description = (
        "Checks for high-risk services (Remote Registry, Print Spooler) and flags insecure states."
    )
    risk_level = RiskLevel.high
    fix_available = True

    _services = {
        "RemoteRegistry": {"recommended_start": "DISABLED", "recommended_state": "STOPPED"},
        "Spooler": {"recommended_start": "DISABLED", "recommended_state": "STOPPED"},
    }

    def check(self, ctx: CheckContext) -> Finding:
        """
        Check service state and start type for selected services.

        Args:
            ctx: Check context.

        Returns:
            Finding with per-service details.
        """
        details: dict[str, object] = {}
        evidence_cmds: list[dict[str, object]] = []
        any_unknown = False
        any_fail = False

        for service, rec in self._services.items():
            q_res = run_cmd(["sc", "query", service], timeout_s=10.0)
            qc_res = run_cmd(["sc", "qc", service], timeout_s=10.0)
            evidence_cmds.append(
                safe_details(
                    args=["sc", "query", service],
                    exit_code=q_res.exit_code,
                    stdout_snippet=(q_res.stdout[:1500] if q_res.stdout else ""),
                    stderr_snippet=(q_res.stderr[:500] if q_res.stderr else ""),
                )
            )
            evidence_cmds.append(
                safe_details(
                    args=["sc", "qc", service],
                    exit_code=qc_res.exit_code,
                    stdout_snippet=(qc_res.stdout[:1500] if qc_res.stdout else ""),
                    stderr_snippet=(qc_res.stderr[:500] if qc_res.stderr else ""),
                )
            )
            state = _parse_sc_query_state(q_res.stdout) if q_res.exit_code == 0 else None
            start_type = _parse_sc_qc_start_type(qc_res.stdout) if qc_res.exit_code == 0 else None
            if state is None or start_type is None:
                any_unknown = True
            else:
                if state != rec["recommended_state"] or start_type != rec["recommended_start"]:
                    any_fail = True
            details[service] = {"state": state, "start_type": start_type, **rec}

        if any_unknown:
            status = FindingStatus.unknown
        else:
            status = FindingStatus.fail if any_fail else FindingStatus.pass_

        return Finding(
            finding_id=self.finding_id,
            name=self.name,
            risk_level=self.risk_level,
            status=status,
            description=self.description,
            details=safe_details(
                policy_source="Command",
                evidence_command=evidence_cmds,
                services=details,
                note="Disabling Spooler can break printing.",
            ),
            fix_available=bool(ctx.is_admin) and status == FindingStatus.fail,
        )

    def fix(self, ctx: CheckContext) -> Finding:
        """
        Stop and disable selected services.

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

        before: dict[str, dict[str, str | None]] = {}
        for service in self._services:
            before[service] = {
                "state": _sc_query_state(service),
                "start_type": _sc_qc_start_type(service),
            }

        remediation: dict[str, str] = {}
        for service in self._services:
            stop_res = run_cmd(["sc", "stop", service], timeout_s=12.0)
            cfg_res = run_cmd(["sc", "config", service, "start=", "disabled"], timeout_s=12.0)
            remediation[service] = (
                "ok"
                if stop_res.exit_code == 0 and cfg_res.exit_code == 0
                else (stop_res.stderr or stop_res.stdout or cfg_res.stderr or cfg_res.stdout or "error")
            )

        finding = self.check(ctx)
        rollback_supported = all(
            isinstance(before.get(s, {}).get("start_type"), str) and isinstance(before.get(s, {}).get("state"), str)
            for s in self._services
        )
        finding.details.update(
            safe_details(
                remediation=remediation,
                rollback_supported=rollback_supported,
                rollback_state=before if rollback_supported else None,
            )
        )
        return finding

    def preview(self, ctx: CheckContext) -> dict[str, object]:
        changes: list[str] = []
        rollback_supported = True
        for service, rec in self._services.items():
            state = _sc_query_state(service)
            start_type = _sc_qc_start_type(service)
            if state is None or start_type is None:
                rollback_supported = False
            if state != rec["recommended_state"] or start_type != rec["recommended_start"]:
                changes.append(
                    f"Stop {service} and set start type to DISABLED (current: state={state}, start_type={start_type})"
                )
        if not changes:
            changes.append("No changes required (services already stopped and disabled).")
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

        def start_mode_arg(start_type: str) -> str | None:
            st = start_type.upper()
            if st in ("AUTO_START", "AUTOMATIC"):
                return "auto"
            if st in ("DEMAND_START", "MANUAL"):
                return "demand"
            if st == "DISABLED":
                return "disabled"
            return None

        errors: dict[str, str] = {}
        for service in self._services:
            state_obj = rollback_state.get(service)
            if not isinstance(state_obj, dict):
                errors[service] = "missing rollback state"
                continue
            prev_state = state_obj.get("state")
            prev_start_type = state_obj.get("start_type")
            if not isinstance(prev_state, str) or not isinstance(prev_start_type, str):
                errors[service] = "invalid rollback state"
                continue

            arg = start_mode_arg(prev_start_type)
            if not arg:
                errors[service] = f"unsupported start_type: {prev_start_type}"
                continue

            cfg_res = run_cmd(["sc", "config", service, "start=", arg], timeout_s=12.0)
            if cfg_res.exit_code != 0:
                errors[service] = cfg_res.stderr or cfg_res.stdout or "config error"
                continue

            if prev_state.upper() == "RUNNING":
                run_cmd(["sc", "start", service], timeout_s=12.0)
            elif prev_state.upper() == "STOPPED":
                run_cmd(["sc", "stop", service], timeout_s=12.0)

        finding = self.check(ctx)
        finding.details.update(safe_details(rollback="ok" if not errors else errors))
        return finding


def _sc_query_state(service: str) -> str | None:
    res = run_cmd(["sc", "query", service], timeout_s=10.0)
    if res.exit_code != 0:
        return None
    return _parse_sc_query_state(res.stdout)


def _sc_qc_start_type(service: str) -> str | None:
    res = run_cmd(["sc", "qc", service], timeout_s=10.0)
    if res.exit_code != 0:
        return None
    return _parse_sc_qc_start_type(res.stdout)


def _parse_sc_query_state(stdout: str) -> str | None:
    m = re.search(r"^\s*STATE\s*:\s*\d+\s+(\w+)\s*$", stdout or "", flags=re.I | re.M)
    if not m:
        return None
    return m.group(1).strip().upper()


def _parse_sc_qc_start_type(stdout: str) -> str | None:
    m = re.search(r"^\s*START_TYPE\s*:\s*\d+\s+(\w+)\s*$", stdout or "", flags=re.I | re.M)
    if not m:
        return None
    return m.group(1).strip().upper()
