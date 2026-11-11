from __future__ import annotations

import json

from sentinelaudit.audit.base import CheckContext
from sentinelaudit.models import Finding, FindingStatus, RiskLevel
from sentinelaudit.windows import run_cmd, safe_details


def _ps_json(command: str) -> tuple[dict[str, object] | list[object] | None, dict[str, object]]:
    res = run_cmd(["powershell", "-NoProfile", "-Command", command], timeout_s=25.0)
    evidence = safe_details(
        policy_source="PowerShell",
        evidence_command=safe_details(
            args=["powershell", "-NoProfile", "-Command", command],
            exit_code=res.exit_code,
            stdout_snippet=(res.stdout[:1500] if res.stdout else ""),
            stderr_snippet=(res.stderr[:800] if res.stderr else ""),
        ),
    )
    if res.exit_code != 0 or not res.stdout:
        return (None, evidence)
    try:
        parsed = json.loads(res.stdout)
    except Exception:
        return (None, evidence)
    return (parsed, evidence)


class DefenderHealthCheck:
    finding_id = "endpoint_protection.defender_health"
    name = "Endpoint Protection: Microsoft Defender Health"
    description = "Checks Microsoft Defender health and core protections."
    risk_level = RiskLevel.high
    fix_available = False

    def check(self, ctx: CheckContext) -> Finding:
        parsed, evidence = _ps_json(
            "Get-MpComputerStatus | Select-Object "
            "AMServiceEnabled,AntivirusEnabled,AntispywareEnabled,RealTimeProtectionEnabled,"
            "IoavProtectionEnabled,NISEnabled,BehaviorMonitorEnabled,OnAccessProtectionEnabled,"
            "AntivirusSignatureAge,AntispywareSignatureAge,NISSignatureAge | "
            "ConvertTo-Json -Compress"
        )
        if not isinstance(parsed, dict):
            return Finding(
                finding_id=self.finding_id,
                name=self.name,
                risk_level=self.risk_level,
                status=FindingStatus.unknown,
                description=self.description,
                details=evidence,
                fix_available=False,
            )

        def b(key: str) -> bool | None:
            v = parsed.get(key)
            return v if isinstance(v, bool) else None

        def i(key: str) -> int | None:
            v = parsed.get(key)
            if isinstance(v, int):
                return v
            if isinstance(v, float):
                return int(v)
            return None

        am = b("AMServiceEnabled")
        av = b("AntivirusEnabled")
        rtp = b("RealTimeProtectionEnabled")
        sig_age = i("AntivirusSignatureAge")

        ok = bool(am) and bool(av) and bool(rtp) and (sig_age is None or sig_age <= 3)
        status = FindingStatus.pass_ if ok else FindingStatus.fail

        details = safe_details(
            **evidence,
            defender_status=parsed,
            checks=safe_details(
                am_service_enabled=am,
                antivirus_enabled=av,
                real_time_protection_enabled=rtp,
                antivirus_signature_age_days=sig_age,
            ),
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


class DefenderAsrRulesCheck:
    finding_id = "endpoint_protection.defender_asr_rules"
    name = "Endpoint Protection: Defender Attack Surface Reduction (ASR) Rules"
    description = "Checks ASR rules state and flags missing high-value ASR protections."
    risk_level = RiskLevel.medium
    fix_available = False

    _high_value_rules: dict[str, str] = {
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a": "Block credential stealing from LSASS",
        "3b576869-a4ec-4529-8536-b80a7769e899": "Block Office applications from creating executable content",
        "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84": "Block Office applications from injecting code into other processes",
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": "Block executable content from email client and webmail",
        "26190899-1602-49e8-8b27-eb1d0a1ce869": "Block Office communication application from creating child processes",
        "56a863a9-875e-4185-98a7-b882c64b5ce5": "Block Office applications from creating child processes",
    }

    def check(self, ctx: CheckContext) -> Finding:
        parsed, evidence = _ps_json(
            "Get-MpPreference | Select-Object "
            "AttackSurfaceReductionRules_Ids,AttackSurfaceReductionRules_Actions | "
            "ConvertTo-Json -Compress"
        )
        if not isinstance(parsed, dict):
            return Finding(
                finding_id=self.finding_id,
                name=self.name,
                risk_level=self.risk_level,
                status=FindingStatus.unknown,
                description=self.description,
                details=evidence,
                fix_available=False,
            )

        ids = parsed.get("AttackSurfaceReductionRules_Ids")
        actions = parsed.get("AttackSurfaceReductionRules_Actions")
        if not isinstance(ids, list) or not isinstance(actions, list) or len(ids) != len(actions):
            details = safe_details(**evidence, note="ASR rules not present or unreadable.")
            return Finding(
                finding_id=self.finding_id,
                name=self.name,
                risk_level=self.risk_level,
                status=FindingStatus.unknown,
                description=self.description,
                details=details,
                fix_available=False,
            )

        rule_map: dict[str, int] = {}
        for idx, rid in enumerate(ids):
            if not isinstance(rid, str):
                continue
            act = actions[idx]
            if isinstance(act, int):
                rule_map[rid.lower()] = int(act)
            elif isinstance(act, float):
                rule_map[rid.lower()] = int(act)

        missing_or_not_blocking: list[dict[str, object]] = []
        for rid, label in self._high_value_rules.items():
            act = rule_map.get(rid.lower())
            if act != 1:
                missing_or_not_blocking.append({"rule_id": rid, "name": label, "action": act})

        any_configured = len(rule_map) > 0
        ok = any_configured and len(missing_or_not_blocking) == 0
        status = FindingStatus.pass_ if ok else FindingStatus.fail

        details = safe_details(
            **evidence,
            asr_rules=safe_details(total=len(rule_map), rules=rule_map),
            high_value_missing_or_not_blocking=missing_or_not_blocking,
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
