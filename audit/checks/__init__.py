from __future__ import annotations

from sentinelaudit.audit.checks.account_security import AccountSecurityCheck
from sentinelaudit.audit.checks.audit_logging import AuditLoggingCheck
from sentinelaudit.audit.checks.autorun import AutorunAutoplayCheck
from sentinelaudit.audit.checks.bitlocker import BitLockerCheck
from sentinelaudit.audit.checks.controlled_folder_access import ControlledFolderAccessCheck
from sentinelaudit.audit.checks.defender_asr import DefenderAsrRulesCheck, DefenderHealthCheck
from sentinelaudit.audit.checks.firewall import FirewallProfilesCheck
from sentinelaudit.audit.checks.lsa_protection import LsaProtectionRunAsPplCheck
from sentinelaudit.audit.checks.local_admins import LocalAdministratorsGroupReviewCheck
from sentinelaudit.audit.checks.password_policy import PasswordPolicyCheck
from sentinelaudit.audit.checks.rdp_exposure import RdpExposureBeyondNlaCheck
from sentinelaudit.audit.checks.rdp_nla import RdpNetworkLevelAuthCheck
from sentinelaudit.audit.checks.risky_services import RiskyServicesCheck
from sentinelaudit.audit.checks.smb1 import SmbV1DisabledCheck
from sentinelaudit.audit.checks.tls_posture import TlsProtocolPostureCheck
from sentinelaudit.audit.checks.uac_policy import UacPolicyCheck
from sentinelaudit.audit.checks.windows_update import WindowsUpdateLastSuccessCheck
from sentinelaudit.audit.checks.windows_update_policy import WindowsUpdatePolicyComplianceCheck


def get_all_checks() -> list[object]:
    return [
        AccountSecurityCheck(),
        DefenderHealthCheck(),
        DefenderAsrRulesCheck(),
        FirewallProfilesCheck(),
        BitLockerCheck(),
        PasswordPolicyCheck(),
        AutorunAutoplayCheck(),
        WindowsUpdateLastSuccessCheck(),
        WindowsUpdatePolicyComplianceCheck(),
        RiskyServicesCheck(),
        UacPolicyCheck(),
        ControlledFolderAccessCheck(),
        AuditLoggingCheck(),
        SmbV1DisabledCheck(),
        RdpNetworkLevelAuthCheck(),
        RdpExposureBeyondNlaCheck(),
        LocalAdministratorsGroupReviewCheck(),
        TlsProtocolPostureCheck(),
        LsaProtectionRunAsPplCheck(),
    ]
