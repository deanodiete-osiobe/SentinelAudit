from __future__ import annotations

import json
from sentinelaudit.audit.base import CheckContext
from sentinelaudit.models import Finding, FindingStatus, RiskLevel
from sentinelaudit.windows import run_cmd


class BitLockerCheck:
    finding_id = "storage_security.bitlocker"
    name = "Storage Security: BitLocker Drive Encryption"
    description = "Verifies protection, encryption and protector types for the OS volume."
    risk_level = RiskLevel.high
    fix_available = False

    def check(self, ctx: CheckContext) -> Finding:
        # Project only non-secret properties BEFORE serialization. Never collect
        # recovery passwords, key IDs or raw manage-bde -protectors output.
        script = ("$ErrorActionPreference='Stop'; "
                  "$v=Get-BitLockerVolume -MountPoint $env:SystemDrive; "
                  "[pscustomobject]@{protection=[int]$v.ProtectionStatus; "
                  "volume=[int]$v.VolumeStatus; "
                  "protectors=@($v.KeyProtector | ForEach-Object {[string]$_.KeyProtectorType})} "
                  "| ConvertTo-Json -Compress")
        res = run_cmd(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], timeout_s=30)
        details = {"policy_source": "Get-BitLockerVolume", "exit_code": res.exit_code}
        status = FindingStatus.unknown
        try:
            data = json.loads(res.stdout) if res.exit_code == 0 else {}
            protection, volume, protectors = data.get("protection"), data.get("volume"), data.get("protectors")
            if type(protection) is int and protection in (0, 1) and type(volume) is int and volume in range(6) and isinstance(protectors, list) and all(isinstance(x, str) for x in protectors):
                details.update(protection_on=protection == 1, fully_encrypted=volume == 1,
                               protector_types=protectors)
                status = FindingStatus.pass_ if protection == 1 and volume == 1 and protectors else FindingStatus.fail
            else:
                details["note"] = "BitLocker unavailable, inaccessible or response incomplete."
        except (ValueError, TypeError, AttributeError):
            details["note"] = "Unable to parse BitLocker status."
        return Finding(finding_id=self.finding_id, name=self.name, risk_level=self.risk_level,
                       status=status, description=self.description, details=details, fix_available=False)

    def fix(self, ctx: CheckContext) -> Finding:
        return self.check(ctx)
