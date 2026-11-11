from __future__ import annotations

from sentinelaudit.audit.base import AuditCheck
from sentinelaudit.audit.checks import get_all_checks


def load_checks() -> list[AuditCheck]:
    """
    Load all audit checks.

    Returns:
        List of instantiated checks.
    """
    checks = get_all_checks()
    return [c for c in checks if _looks_like_check(c)]


def get_check_by_id(finding_id: str) -> AuditCheck | None:
    """
    Retrieve an audit check by its finding_id.

    Args:
        finding_id: Stable identifier for a check.

    Returns:
        Matching check instance, or None.
    """
    for check in load_checks():
        if getattr(check, "finding_id", None) == finding_id:
            return check
    return None


def _looks_like_check(obj: object) -> bool:
    required = ("finding_id", "name", "description", "risk_level", "check", "fix")
    return all(hasattr(obj, k) for k in required)
