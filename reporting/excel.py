from __future__ import annotations

import json
from io import BytesIO

import xlsxwriter

from sentinelaudit.models import AuditResult


def build_excel_report(result: AuditResult, host_info: dict[str, object] | None = None) -> bytes:
    """
    Build a multi-sheet Excel report from an audit result.

    Sheets:
        - Summary
        - Findings
        - Remediation Guide

    Args:
        result: Audit result payload.

    Returns:
        XLSX file content as bytes.
    """
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    header_fmt = workbook.add_format(
        {"bold": True, "bg_color": "#111827", "font_color": "#22d3ee", "border": 1}
    )
    wrap_fmt = workbook.add_format({"text_wrap": True, "valign": "top"})

    summary_rows: list[dict[str, object]] = [
        {"Key": "Generated (UTC)", "Value": result.generated_utc.isoformat()},
        {"Key": "Hardening Score", "Value": result.hardening_score},
        {"Key": "Total Findings", "Value": len(result.findings)},
    ]
    if host_info:
        for k, v in host_info.items():
            summary_rows.append({"Key": str(k), "Value": v})

    findings_rows: list[dict[str, object]] = []
    for f in result.findings:
        details = f.details or {}
        findings_rows.append(
            {
                "Finding ID": f.finding_id,
                "Name": f.name,
                "Risk Level": f.risk_level.value,
                "Status": f.status.value,
                "Last Checked (UTC)": f.last_checked_utc.isoformat(),
                "Description": f.description,
                "Fix Available": bool(f.fix_available),
                "Error": str(details.get("error", "")),
                "Why It Matters": str(details.get("why_it_matters", "")),
                "Risk": str(details.get("risk", "")),
                "Recommendation": str(details.get("recommendation", "")),
                "References": json.dumps(details.get("references", []), ensure_ascii=False),
                "Remediation": str(details.get("remediation", "")),
                "Reboot Required": bool(details.get("reboot_required", False)),
                "Rollback Supported": bool(details.get("rollback_supported", False)),
                "Rollback": str(details.get("rollback", "")),
                "Evidence": json.dumps(details, ensure_ascii=False),
            }
        )

    remediation_rows: list[dict[str, object]] = [
        {
            "Finding ID": f.finding_id,
            "Name": f.name,
            "Remediation Notes": _default_remediation_guide(f.finding_id),
        }
        for f in result.findings
    ]

    remediation_log_rows: list[dict[str, object]] = []
    try:
        from sentinelaudit.windows import read_remediation_audit_log

        for ev in read_remediation_audit_log(limit=2000):
            remediation_log_rows.append(
                {
                    "Timestamp (UTC)": str(ev.get("timestamp_utc", "")),
                    "Action": str(ev.get("action", "")),
                    "Result": str(ev.get("result", "")),
                    "Actor": str(ev.get("actor_username", "")),
                    "Finding ID": str(ev.get("finding_id", "")),
                    "Before Status": str(ev.get("before_status", "")),
                    "After Status": str(ev.get("after_status", "")),
                    "Before Evidence": json.dumps(ev.get("before_evidence", None), ensure_ascii=False),
                    "After Evidence": json.dumps(ev.get("after_evidence", None), ensure_ascii=False),
                    "New Username": str(ev.get("new_username", "")),
                    "Error": str(ev.get("error", "")),
                    "Raw": json.dumps(ev, ensure_ascii=False),
                }
            )
    except Exception:
        remediation_log_rows = []

    _write_table_sheet(
        workbook,
        "Summary",
        columns=["Key", "Value"],
        rows=summary_rows,
        header_fmt=header_fmt,
        cell_fmt=wrap_fmt,
    )
    _write_table_sheet(
        workbook,
        "Findings",
        columns=[
            "Finding ID",
            "Name",
            "Risk Level",
            "Status",
            "Last Checked (UTC)",
            "Description",
            "Fix Available",
            "Error",
            "Why It Matters",
            "Risk",
            "Recommendation",
            "References",
            "Remediation",
            "Reboot Required",
            "Rollback Supported",
            "Rollback",
            "Evidence",
        ],
        rows=findings_rows,
        header_fmt=header_fmt,
        cell_fmt=wrap_fmt,
    )
    _write_table_sheet(
        workbook,
        "Remediation Guide",
        columns=["Finding ID", "Name", "Remediation Notes"],
        rows=remediation_rows,
        header_fmt=header_fmt,
        cell_fmt=wrap_fmt,
    )
    _write_table_sheet(
        workbook,
        "Remediation Log",
        columns=[
            "Timestamp (UTC)",
            "Action",
            "Result",
            "Actor",
            "Finding ID",
            "Before Status",
            "After Status",
            "Before Evidence",
            "After Evidence",
            "New Username",
            "Error",
            "Raw",
        ],
        rows=remediation_log_rows,
        header_fmt=header_fmt,
        cell_fmt=wrap_fmt,
    )

    workbook.close()

    return output.getvalue()


def _write_table_sheet(
    workbook: xlsxwriter.Workbook,
    sheet_name: str,
    columns: list[str],
    rows: list[dict[str, object]],
    header_fmt: xlsxwriter.format.Format,
    cell_fmt: xlsxwriter.format.Format,
) -> None:
    ws = workbook.add_worksheet(sheet_name[:31])
    ws.freeze_panes(1, 0)

    for col_idx, col_name in enumerate(columns):
        ws.write(0, col_idx, col_name, header_fmt)

    col_widths = [len(c) for c in columns]
    for row_idx, row in enumerate(rows, start=1):
        for col_idx, col_name in enumerate(columns):
            value = row.get(col_name, "")
            if value is None:
                text = ""
            elif isinstance(value, bool):
                text = "TRUE" if value else "FALSE"
            else:
                text = str(value)
            ws.write(row_idx, col_idx, text, cell_fmt)
            if len(text) > col_widths[col_idx]:
                col_widths[col_idx] = len(text)

    for col_idx, width in enumerate(col_widths):
        ws.set_column(col_idx, col_idx, max(12, min(70, width + 2)))


def _default_remediation_guide(finding_id: str) -> str:
    guides: dict[str, str] = {
        "account_security.local_builtin_accounts": "Disable built-in Guest and Administrator accounts where operationally feasible.",
        "network_defense.firewall_profiles": "Enable Windows Firewall for all profiles and enforce inbound rules.",
        "storage_security.bitlocker": "Enable BitLocker on OS and fixed data volumes; store recovery keys securely.",
        "credential_protection.password_policy": "Set minimum length >= 14 and enable complexity; prefer MFA/Windows Hello for Business where possible.",
        "device_control.autorun_autoplay": "Disable Autorun/Autoplay via Group Policy/registry to block removable-media auto-execution.",
        "update_integrity.windows_update_last_success": "Ensure Windows Update runs regularly; consider WSUS/Intune policies for compliance.",
        "service_hardening.high_risk_services": "Disable Remote Registry. Disable Print Spooler where not required; otherwise restrict to trusted print servers.",
        "uac_policy.elevation_prompt_behavior": "Use secure desktop prompts and require consent/credentials to reduce stealthy privilege escalation.",
        "exploit_protection.controlled_folder_access": "Enable Controlled Folder Access and tune allowed apps to reduce ransomware impact.",
        "audit_logging.logon_auditing": "Enable success/failure auditing for Logon and forward security logs to a SIEM when possible.",
        "secure_config.smbv1_disabled": "Disable SMBv1 unless a validated legacy dependency exists; monitor for SMBv1 traffic before removal.",
        "secure_config.rdp_nla_enabled": "Require NLA for RDP and restrict remote access via firewall/VPN and allowed user groups.",
        "identity_access.lsa_protection_runasppl": "Enable RunAsPPL and validate endpoint tooling compatibility; reboot to apply.",
    }
    return guides.get(
        finding_id,
        "Apply CIS-aligned hardening for this control and verify via policy/telemetry.",
    )
