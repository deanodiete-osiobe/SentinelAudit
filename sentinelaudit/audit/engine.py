from __future__ import annotations

from collections.abc import Iterable

from sentinelaudit.audit.base import AuditCheck, CheckContext
from sentinelaudit.models import AuditResult, Finding, FindingStatus


_FINDING_METADATA: dict[str, dict[str, object]] = {
    "account_security.local_builtin_accounts": {
        "references": [
            {"framework": "Microsoft Security Baseline", "control": "Local accounts / built-in accounts"},
            {"framework": "CIS Benchmarks", "control": "Local accounts hardening"},
        ],
        "why_it_matters": "Built-in accounts are frequently targeted. Disabling Guest/Administrator reduces credential abuse and lateral movement.",
        "risk": "If left enabled, an attacker may leverage weak/default configurations for persistence or privilege escalation.",
        "recommendation": "Disable built-in Guest and Administrator accounts where operationally feasible; use named admin accounts with MFA.",
    },
    "network_defense.firewall_profiles": {
        "references": [
            {"framework": "Microsoft Security Baseline", "control": "Windows Defender Firewall"},
            {"framework": "CIS Benchmarks", "control": "Firewall enabled for all profiles"},
        ],
        "why_it_matters": "A host firewall blocks unsolicited inbound traffic and reduces exposure to lateral movement and opportunistic scanning.",
        "risk": "Disabled firewall increases attack surface, especially on public/untrusted networks.",
        "recommendation": "Enable Windows Firewall for Domain/Private/Public and review inbound rule scope.",
    },
    "storage_security.bitlocker": {
        "references": [
            {"framework": "Microsoft Security Baseline", "control": "BitLocker / device encryption"},
            {"framework": "CIS Benchmarks", "control": "Full-disk encryption"},
        ],
        "why_it_matters": "Disk encryption protects data at rest if a device is lost or stolen.",
        "risk": "Unencrypted disks allow offline data theft and credential extraction.",
        "recommendation": "Enable BitLocker on OS and fixed data volumes; store recovery keys securely.",
    },
    "credential_protection.password_policy": {
        "references": [
            {"framework": "Microsoft Security Baseline", "control": "Password policy"},
            {"framework": "CIS Benchmarks", "control": "Account policy hardening"},
        ],
        "why_it_matters": "Stronger password policy raises the cost of guessing and limits credential stuffing impact.",
        "risk": "Weak policy increases likelihood of account compromise.",
        "recommendation": "Set minimum length >= 14 and require complexity; prefer MFA/Windows Hello for Business where possible.",
    },
    "device_control.autorun_autoplay": {
        "references": [
            {"framework": "Microsoft Security Baseline", "control": "Autorun/Autoplay policies"},
            {"framework": "CIS Benchmarks", "control": "Disable Autorun"},
        ],
        "why_it_matters": "Autorun/Autoplay can be abused for removable-media malware execution.",
        "risk": "Removable media can trigger unwanted execution or user-driven prompts leading to compromise.",
        "recommendation": "Disable Autorun/Autoplay via policy/registry; restrict removable media where appropriate.",
    },
    "update_integrity.windows_update_last_success": {
        "references": [
            {"framework": "Microsoft Security Baseline", "control": "Windows Update / patching"},
            {"framework": "CIS Benchmarks", "control": "Patch management"},
        ],
        "why_it_matters": "Patching reduces exposure to known vulnerabilities and commodity exploits.",
        "risk": "Outdated systems are vulnerable to publicly known exploits and worms.",
        "recommendation": "Ensure Windows Update runs regularly; enforce via WSUS/Intune when possible.",
    },
    "service_hardening.high_risk_services": {
        "references": [
            {"framework": "Microsoft Security Baseline", "control": "Service hardening"},
            {"framework": "CIS Benchmarks", "control": "Disable unnecessary services"},
        ],
        "why_it_matters": "High-risk services expand attack surface and can be abused for remote access or privilege escalation.",
        "risk": "Insecure service configuration can enable remote abuse or persistence.",
        "recommendation": "Disable Remote Registry. Disable Print Spooler where not required; otherwise restrict printing to trusted servers.",
    },
    "uac_policy.elevation_prompt_behavior": {
        "references": [
            {"framework": "Microsoft Security Baseline", "control": "UAC settings"},
            {"framework": "CIS Benchmarks", "control": "UAC hardening"},
        ],
        "why_it_matters": "Stronger UAC prompts reduce silent privilege escalation and increase user awareness.",
        "risk": "Weak UAC behavior can allow stealthier elevation paths and reduce user friction for malicious changes.",
        "recommendation": "Use secure desktop prompts and require consent/credentials consistent with organizational policy.",
    },
    "exploit_protection.controlled_folder_access": {
        "references": [
            {"framework": "Microsoft Security Baseline", "control": "Microsoft Defender Exploit Guard / CFA"},
            {"framework": "CIS Benchmarks", "control": "Anti-malware protections"},
        ],
        "why_it_matters": "Controlled Folder Access can block unauthorized file modifications and reduce ransomware impact.",
        "risk": "Without protections, ransomware can encrypt user and system data more easily.",
        "recommendation": "Enable CFA and tune allowed applications; validate business-critical workflows.",
    },
    "audit_logging.logon_auditing": {
        "references": [
            {"framework": "Microsoft Security Baseline", "control": "Audit policy"},
            {"framework": "CIS Benchmarks", "control": "Logging and auditing"},
        ],
        "why_it_matters": "Audit logs support detection, forensics, and accountability for authentication events.",
        "risk": "Insufficient logging reduces ability to detect compromise and investigate incidents.",
        "recommendation": "Enable success/failure auditing for Logon and forward security logs to centralized monitoring where possible.",
    },
    "secure_config.smbv1_disabled": {
        "references": [
            {"framework": "Microsoft Security Baseline", "control": "Disable SMBv1"},
            {"framework": "CIS Benchmarks", "control": "Network configuration / legacy protocols"},
        ],
        "why_it_matters": "SMBv1 is a legacy protocol with well-known weaknesses and has been used by worms and commodity exploits.",
        "risk": "If enabled, the host may be vulnerable to legacy SMB attacks and faster lateral spread.",
        "recommendation": "Disable SMBv1 on servers and clients unless a validated legacy dependency exists; monitor for SMBv1 traffic before removal.",
    },
    "secure_config.rdp_nla_enabled": {
        "references": [
            {"framework": "Microsoft Security Baseline", "control": "Remote Desktop Services hardening"},
            {"framework": "CIS Benchmarks", "control": "Require NLA for RDP"},
        ],
        "why_it_matters": "NLA reduces RDP exposure by requiring authentication before session setup, helping mitigate brute-force and pre-auth risks.",
        "risk": "Without NLA, RDP can be more exposed to credential attacks and may increase the impact of RDP vulnerabilities.",
        "recommendation": "Require NLA for RDP and restrict access via firewall/VPN and allowed users groups.",
    },
    "secure_config.rdp_exposure_beyond_nla": {
        "references": [
            {"framework": "Microsoft Security Baseline", "control": "Remote Desktop Services hardening"},
            {"framework": "CIS Benchmarks", "control": "Restrict RDP exposure"},
        ],
        "why_it_matters": "Even with NLA, exposed RDP increases attack surface and brute-force pressure and can enable credential-based access.",
        "risk": "Broad firewall scope and permissive allowed users can lead to remote compromise.",
        "recommendation": "Disable RDP where not required; otherwise restrict inbound scope to trusted IP/VPN and limit Remote Desktop Users membership.",
    },
    "endpoint_protection.defender_health": {
        "references": [
            {"framework": "Microsoft Security Baseline", "control": "Microsoft Defender Antivirus"},
            {"framework": "CIS Benchmarks", "control": "Anti-malware protections"},
        ],
        "why_it_matters": "Healthy endpoint protection reduces malware execution and improves detection and response coverage.",
        "risk": "Disabled or stale protections increase likelihood of compromise and reduce visibility.",
        "recommendation": "Ensure Defender (or approved AV) is healthy, real-time protection is enabled, and signatures are current.",
    },
    "endpoint_protection.defender_asr_rules": {
        "references": [
            {"framework": "Microsoft Security Baseline", "control": "Microsoft Defender Exploit Guard / ASR rules"},
            {"framework": "CIS Benchmarks", "control": "Attack surface reduction"},
        ],
        "why_it_matters": "ASR rules can block common initial access and post-exploitation behaviors (Office macros, child processes, LSASS abuse).",
        "risk": "Without ASR, commodity techniques are more likely to succeed.",
        "recommendation": "Enable high-value ASR rules in Block mode and validate business workflows; tune exclusions sparingly.",
    },
    "secure_config.tls_protocol_posture": {
        "references": [
            {"framework": "CIS Benchmarks", "control": "TLS protocol hardening"},
            {"framework": "Microsoft Security Baseline", "control": "SCHANNEL / TLS settings"},
        ],
        "why_it_matters": "Disabling legacy TLS versions reduces exposure to weaker cryptography and downgrade attacks.",
        "risk": "Enabled TLS 1.0/1.1 can allow weaker negotiation paths and legacy compatibility exposure.",
        "recommendation": "Disable TLS 1.0/1.1, ensure TLS 1.2 remains enabled, and validate application compatibility.",
    },
    "update_integrity.windows_update_policy_compliance": {
        "references": [
            {"framework": "Microsoft Security Baseline", "control": "Windows Update policy"},
            {"framework": "CIS Benchmarks", "control": "Patch management governance"},
        ],
        "why_it_matters": "Policy can disable updates entirely or misconfigure scheduling, leading to stale patch levels.",
        "risk": "Systems may remain unpatched and vulnerable to known exploits.",
        "recommendation": "Avoid disabling automatic updates via policy; enforce patch governance via WSUS/Intune where applicable.",
    },
    "identity_access.local_administrators_group_review": {
        "references": [
            {"framework": "CIS Benchmarks", "control": "Accounts and privileges"},
            {"framework": "Microsoft Security Baseline", "control": "Local administrators management"},
        ],
        "why_it_matters": "Local admin membership directly impacts privilege escalation and persistence opportunities.",
        "risk": "Overly broad group membership enables abuse and increases blast radius.",
        "recommendation": "Review and minimize membership; avoid broad principals like Domain Users/Everyone; use JIT/JEA where possible.",
    },
    "identity_access.lsa_protection_runasppl": {
        "references": [
            {"framework": "Microsoft Security Baseline", "control": "LSA protection (RunAsPPL)"},
            {"framework": "CIS Benchmarks", "control": "Credential theft mitigations"},
        ],
        "why_it_matters": "LSA protection makes LSASS harder to tamper with and reduces common credential dumping techniques.",
        "risk": "If disabled, attackers with local admin can more easily dump credentials from LSASS and move laterally.",
        "recommendation": "Enable RunAsPPL and validate compatibility with endpoint security tooling; plan for reboot to apply.",
    },
}


def enrich_finding(finding: Finding) -> Finding:
    meta = _FINDING_METADATA.get(finding.finding_id)
    if not meta:
        return finding
    for k, v in meta.items():
        if k not in finding.details:
            finding.details[k] = __import__("copy").deepcopy(v)
    return finding


def compute_hardening_score(findings: Iterable[Finding]) -> int:
    """
    Compute a 0-100 hardening score based on pass/fail findings.

    Unknown results are excluded from the denominator.

    Args:
        findings: Findings to score.

    Returns:
        Integer score (0-100).
    """
    findings_list = list(findings)
    decided = [f for f in findings_list if f.status in (FindingStatus.pass_, FindingStatus.fail)]
    if not decided:
        return 0
    passed = sum(1 for f in decided if f.status == FindingStatus.pass_)
    return int(round((passed / len(decided)) * 100))


class AuditCancelled(Exception):
    """Cooperative cancellation; completed findings remain explicitly partial."""
    def __init__(self, findings):
        super().__init__("Audit cancelled after the current check finished")
        self.findings = list(findings)


def run_checks(checks: Iterable[AuditCheck], ctx: CheckContext, *, cancel=None, progress=None) -> AuditResult:
    checks = list(checks)
    findings: list[Finding] = []
    for check in checks:
        if cancel is not None and cancel.is_set():
            raise AuditCancelled(findings)
        if progress:
            progress(len(findings), len(checks), check.name, list(findings))
        try:
            finding = enrich_finding(check.check(ctx))
        except Exception as exc:
            finding = enrich_finding(Finding(finding_id=check.finding_id,name=check.name,
                risk_level=check.risk_level,status=FindingStatus.unknown,description=check.description,
                details={"error":f"{type(exc).__name__}: {exc}",
                    "next_step":"Check Windows permissions and the supporting service/policy, then rerun this audit. Unknown is not a pass."},
                fix_available=False))
        findings.append(finding)
        if progress:
            progress(len(findings), len(checks), "", list(findings))
    if cancel is not None and cancel.is_set():
        raise AuditCancelled(findings)
    return AuditResult(hardening_score=compute_hardening_score(findings), findings=findings)
