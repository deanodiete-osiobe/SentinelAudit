from __future__ import annotations

import json
import winreg

from sentinelaudit.audit.base import CheckContext
from sentinelaudit.models import Finding, FindingStatus, RiskLevel
from sentinelaudit.windows import reg_get_dword, run_cmd, safe_details


class RdpExposureBeyondNlaCheck:
    finding_id = "secure_config.rdp_exposure_beyond_nla"
    name = "Secure Config: RDP Exposure Beyond NLA"
    description = "Checks RDP enablement, firewall scope for 3389, and allowed users beyond NLA."
    risk_level = RiskLevel.high
    fix_available = False

    _ts_key = r"SYSTEM\CurrentControlSet\Control\Terminal Server"

    def check(self, ctx: CheckContext) -> Finding:
        deny = reg_get_dword(winreg.HKEY_LOCAL_MACHINE, self._ts_key, "fDenyTSConnections")
        rdp_enabled = isinstance(deny, int) and int(deny) == 0
        reg_evidence = [
            {
                "key_path": f"HKLM\\{self._ts_key}",
                "value_name": "fDenyTSConnections",
                "value": deny,
            }
        ]

        ps = (
            "$rules = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | "
            "Where-Object { "
            "$pf = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_; "
            "($pf.Protocol -eq 'TCP' -and $pf.LocalPort -eq '3389') "
            "} | ForEach-Object { "
            "$af = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_; "
            "[pscustomobject]@{Name=$_.Name;DisplayName=$_.DisplayName;Profile=$_.Profile;"
            "RemoteAddress=($af.RemoteAddress -join ',');} "
            "}; $rules | ConvertTo-Json -Compress"
        )
        fw_res = run_cmd(["powershell", "-NoProfile", "-Command", ps], timeout_s=25.0)
        fw_evidence = safe_details(
            policy_source="PowerShell",
            evidence_command=safe_details(
                args=["powershell", "-NoProfile", "-Command", ps],
                exit_code=fw_res.exit_code,
                stdout_snippet=(fw_res.stdout[:2000] if fw_res.stdout else ""),
                stderr_snippet=(fw_res.stderr[:800] if fw_res.stderr else ""),
            ),
        )

        rules: list[dict[str, object]] = []
        if fw_res.exit_code == 0 and fw_res.stdout:
            try:
                parsed = json.loads(fw_res.stdout)
                if isinstance(parsed, dict):
                    rules = [parsed]
                elif isinstance(parsed, list):
                    rules = [r for r in parsed if isinstance(r, dict)]
            except Exception:
                rules = []

        any_remote = False
        for r in rules:
            ra = r.get("RemoteAddress")
            if isinstance(ra, str) and ra:
                low = ra.lower()
                if "any" in low or "0.0.0.0/0" in low or "::/0" in low or "*" in low:
                    any_remote = True

        rdu_res = run_cmd(["net", "localgroup", "Remote Desktop Users"], timeout_s=15.0)
        rdu_members: list[str] = []
        if rdu_res.exit_code == 0 and rdu_res.stdout:
            for ln in rdu_res.stdout.splitlines():
                s = ln.strip()
                if not s or s.startswith("---"):
                    continue
                if "The command completed successfully" in s:
                    break
                if s.lower().startswith("alias name") or s.lower().startswith("comment"):
                    continue
                rdu_members.append(s)

        details = safe_details(
            policy_source="Registry/PowerShell/Command",
            evidence_registry=reg_evidence,
            firewall_rules_3389=rules,
            remote_desktop_users=rdu_members,
            **fw_evidence,
        )

        if deny is None and fw_res.exit_code != 0:
            return Finding(
                finding_id=self.finding_id,
                name=self.name,
                risk_level=self.risk_level,
                status=FindingStatus.unknown,
                description=self.description,
                details=details,
                fix_available=False,
            )

        if not rdp_enabled:
            return Finding(
                finding_id=self.finding_id,
                name=self.name,
                risk_level=self.risk_level,
                status=FindingStatus.pass_,
                description=self.description,
                details=safe_details(**details, evaluation=safe_details(rdp_enabled=False)),
                fix_available=False,
            )

        exposed = any_remote
        status = FindingStatus.fail if exposed else FindingStatus.pass_
        return Finding(
            finding_id=self.finding_id,
            name=self.name,
            risk_level=self.risk_level,
            status=status,
            description=self.description,
            details=safe_details(
                **details,
                evaluation=safe_details(rdp_enabled=True, firewall_scope_any=bool(any_remote)),
            ),
            fix_available=False,
        )

    def fix(self, ctx: CheckContext) -> Finding:
        return self.check(ctx)
