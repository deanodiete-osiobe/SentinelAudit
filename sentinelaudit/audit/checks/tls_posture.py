from __future__ import annotations

import winreg

from sentinelaudit.audit.base import CheckContext
from sentinelaudit.models import Finding, FindingStatus, RiskLevel
from sentinelaudit.windows import reg_get_dword, safe_details


def _protocol_state(protocol: str, endpoint: str) -> dict[str, object]:
    key_path = rf"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\{protocol}\{endpoint}"
    enabled = reg_get_dword(winreg.HKEY_LOCAL_MACHINE, key_path, "Enabled")
    disabled_by_default = reg_get_dword(winreg.HKEY_LOCAL_MACHINE, key_path, "DisabledByDefault")
    return {
        "protocol": protocol,
        "endpoint": endpoint,
        "key_path": f"HKLM\\{key_path}",
        "Enabled": enabled,
        "DisabledByDefault": disabled_by_default,
    }


def _is_disabled(state: dict[str, object]) -> bool | None:
    enabled = state.get("Enabled")
    # DisabledByDefault does not prohibit an application enabling the protocol.
    return enabled == 0 if isinstance(enabled, int) else None


def _is_enabled(state: dict[str, object]) -> bool | None:
    enabled = state.get("Enabled")
    return enabled != 0 if isinstance(enabled, int) else None


class TlsProtocolPostureCheck:
    finding_id = "secure_config.tls_protocol_posture"
    name = "Secure Config: TLS Protocol Posture"
    description = "Checks SCHANNEL TLS protocol enablement (TLS 1.0/1.1 disabled, TLS 1.2 enabled)."
    risk_level = RiskLevel.medium
    fix_available = False

    def check(self, ctx: CheckContext) -> Finding:
        states = [
            _protocol_state("TLS 1.0", "Client"),
            _protocol_state("TLS 1.0", "Server"),
            _protocol_state("TLS 1.1", "Client"),
            _protocol_state("TLS 1.1", "Server"),
            _protocol_state("TLS 1.2", "Client"),
            _protocol_state("TLS 1.2", "Server"),
        ]
        tls10_disabled = _is_disabled(states[0]) and _is_disabled(states[1])
        tls11_disabled = _is_disabled(states[2]) and _is_disabled(states[3])
        tls12_enabled = _is_enabled(states[4]) and _is_enabled(states[5])

        unknown = any(_is_disabled(s) is None for s in states)
        if unknown:
            status = FindingStatus.unknown
        else:
            ok = bool(tls10_disabled) and bool(tls11_disabled) and bool(tls12_enabled)
            status = FindingStatus.pass_ if ok else FindingStatus.fail

        details = safe_details(
            policy_source="Registry",
            evidence_registry=states,
            evaluation=safe_details(
                tls10_disabled=tls10_disabled,
                tls11_disabled=tls11_disabled,
                tls12_enabled=tls12_enabled,
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
