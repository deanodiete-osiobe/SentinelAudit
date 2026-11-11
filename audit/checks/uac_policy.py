from __future__ import annotations

import winreg

from sentinelaudit.audit.base import CheckContext
from sentinelaudit.models import Finding, FindingStatus, RiskLevel
from sentinelaudit.windows import reg_get_dword, reg_set_dword, safe_details


class UacPolicyCheck:
    finding_id = "uac_policy.elevation_prompt_behavior"
    name = "UAC Policy: Elevation Prompt Behavior"
    description = (
        "Verifies UAC prompt behavior for administrators (secure desktop + consent/credentials)."
    )
    risk_level = RiskLevel.medium
    fix_available = True

    _key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    _consent_value = "ConsentPromptBehaviorAdmin"
    _secure_desktop_value = "PromptOnSecureDesktop"

    _recommended_consent_values = {2, 5}
    _recommended_secure_desktop = 1

    def check(self, ctx: CheckContext) -> Finding:
        """
        Check UAC prompt values from registry.

        Args:
            ctx: Check context.

        Returns:
            Finding describing current UAC policy.
        """
        consent = reg_get_dword(winreg.HKEY_LOCAL_MACHINE, self._key_path, self._consent_value)
        secure_desktop = reg_get_dword(
            winreg.HKEY_LOCAL_MACHINE, self._key_path, self._secure_desktop_value
        )
        evidence = safe_details(
            policy_source="Registry",
            evidence_registry=[
                {
                    "key_path": f"HKLM\\{self._key_path}",
                    "value_name": self._consent_value,
                    "value": consent,
                },
                {
                    "key_path": f"HKLM\\{self._key_path}",
                    "value_name": self._secure_desktop_value,
                    "value": secure_desktop,
                },
            ],
        )

        if consent is None or secure_desktop is None:
            return Finding(
                finding_id=self.finding_id,
                name=self.name,
                risk_level=self.risk_level,
                status=FindingStatus.unknown,
                description=self.description,
                details=safe_details(
                    **evidence,
                    consent_prompt_behavior_admin=consent,
                    prompt_on_secure_desktop=secure_desktop,
                ),
                fix_available=bool(ctx.is_admin),
            )

        ok = (consent in self._recommended_consent_values) and (
            secure_desktop == self._recommended_secure_desktop
        )
        return Finding(
            finding_id=self.finding_id,
            name=self.name,
            risk_level=self.risk_level,
            status=FindingStatus.pass_ if ok else FindingStatus.fail,
            description=self.description,
            details=safe_details(
                **evidence,
                consent_prompt_behavior_admin=consent,
                prompt_on_secure_desktop=secure_desktop,
                recommended_consent_values=sorted(self._recommended_consent_values),
                recommended_secure_desktop=self._recommended_secure_desktop,
            ),
            fix_available=bool(ctx.is_admin) and (not ok),
        )

    def fix(self, ctx: CheckContext) -> Finding:
        """
        Set ConsentPromptBehaviorAdmin=2 and PromptOnSecureDesktop=1.

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

        before_consent = reg_get_dword(winreg.HKEY_LOCAL_MACHINE, self._key_path, self._consent_value)
        before_secure = reg_get_dword(
            winreg.HKEY_LOCAL_MACHINE, self._key_path, self._secure_desktop_value
        )
        reg_set_dword(winreg.HKEY_LOCAL_MACHINE, self._key_path, self._consent_value, 2)
        reg_set_dword(winreg.HKEY_LOCAL_MACHINE, self._key_path, self._secure_desktop_value, 1)
        finding = self.check(ctx)
        rollback_supported = isinstance(before_consent, int) and isinstance(before_secure, int)
        finding.details.update(
            safe_details(
                remediation="ok",
                rollback_supported=rollback_supported,
                rollback_state=(
                    {"before_consent": before_consent, "before_secure_desktop": before_secure}
                    if rollback_supported
                    else None
                ),
            )
        )
        return finding

    def preview(self, ctx: CheckContext) -> dict[str, object]:
        consent = reg_get_dword(winreg.HKEY_LOCAL_MACHINE, self._key_path, self._consent_value)
        secure_desktop = reg_get_dword(
            winreg.HKEY_LOCAL_MACHINE, self._key_path, self._secure_desktop_value
        )
        return safe_details(
            supported=True,
            is_admin=bool(ctx.is_admin),
            changes=[
                f"Set HKLM\\{self._key_path}\\{self._consent_value} to 2 (current: {consent})",
                f"Set HKLM\\{self._key_path}\\{self._secure_desktop_value} to 1 (current: {secure_desktop})",
            ],
            rollback_supported=isinstance(consent, int) and isinstance(secure_desktop, int),
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

        before_consent = rollback_state.get("before_consent")
        before_secure = rollback_state.get("before_secure_desktop")
        if not isinstance(before_consent, int) or not isinstance(before_secure, int):
            finding = self.check(ctx)
            finding.details.update(safe_details(rollback="not_supported"))
            return finding

        reg_set_dword(winreg.HKEY_LOCAL_MACHINE, self._key_path, self._consent_value, before_consent)
        reg_set_dword(
            winreg.HKEY_LOCAL_MACHINE, self._key_path, self._secure_desktop_value, before_secure
        )
        finding = self.check(ctx)
        finding.details.update(safe_details(rollback="ok"))
        return finding
