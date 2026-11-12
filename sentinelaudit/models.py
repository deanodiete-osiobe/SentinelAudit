from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, computed_field


class RiskLevel(str, Enum):
    low = "Low"
    medium = "Medium"
    high = "High"


class FindingStatus(str, Enum):
    # Finding status label, not an authentication secret.
    pass_ = "Pass"  # nosec B105
    fail = "Fail"
    unknown = "Unknown"


class Finding(BaseModel):
    finding_id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    risk_level: RiskLevel
    status: FindingStatus
    description: str
    details: dict[str, Any] = Field(default_factory=dict)
    fix_available: bool = False
    last_checked_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AuditResult(BaseModel):
    hardening_score: int = Field(..., ge=0, le=100)
    findings: list[Finding]
    generated_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @computed_field
    @property
    def coverage_percent(self) -> int:
        return round(100 * sum(f.status != FindingStatus.unknown for f in self.findings) / len(self.findings)) if self.findings else 0

    @computed_field
    @property
    def unknown_count(self) -> int:
        return sum(f.status == FindingStatus.unknown for f in self.findings)
