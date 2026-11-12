from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from sentinelaudit.models import Finding, RiskLevel


@dataclass(frozen=True)
class CheckContext:
    is_admin: bool


class AuditCheck(Protocol):
    finding_id: str
    name: str
    description: str
    risk_level: RiskLevel
    fix_available: bool

    def check(self, ctx: CheckContext) -> Finding: ...

    def fix(self, ctx: CheckContext) -> Finding: ...
