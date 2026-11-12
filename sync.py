"""Optional local handoff to an enrolled Client; no credentials enter the UI.

Only a fixed protected machine directory is used. The agent owns TLS, identity,
retry and Admin acknowledgement. Queued is not proof of remote receipt.
"""

import configparser
import json
import os
from pathlib import Path
import tempfile
import uuid


def client_directory():
    if os.name != "nt":
        raise ValueError("Admin sync requires the enrolled Windows System Agent Client on this PC.")
    from sentinelaudit.windows import is_admin

    if not is_admin():
        raise ValueError(
            "Run SentinelAudit as Administrator to hand reports to the protected Client queue. Offline scanning and export remain available."
        )
    return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "SystemAgentClient"


def queue_report(report, directory=None):
    root = client_directory() if directory is None else Path(directory)
    config = configparser.ConfigParser(interpolation=None)
    if not (root / "config.ini").is_file():
        raise ValueError(
            "Install and enroll System Agent Client on this PC before syncing. Your local audit is still available."
        )
    try:
        config.read(root / "config.ini")
    except configparser.Error:
        raise ValueError("Client configuration is invalid. Open Client configuration, correct it and retry.") from None
    credential = config.get("admin", "api_key", fallback="").strip()
    if credential in {"", "new"}:
        raise ValueError("Client is not enrolled. Complete enrollment in Client and retry.")
    # Never return or copy the credential; the agent reads its own configuration.
    folder = root / "posture"
    folder.mkdir(exist_ok=True)
    run_id = str(uuid.UUID(report["run_id"]))
    target = folder / (run_id + ".json")
    payload = json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(payload) > 512 * 1024:
        raise ValueError("Report exceeds the handoff size limit")
    if target.exists():
        if json.loads(target.read_text()) != report:
            raise ValueError("Conflicting queued run ID; run a fresh audit.")
        return {"queued": True, "run_id": run_id, "already_queued": True}
    if len(list(folder.glob("*.json"))) >= 32:
        raise ValueError("Client queue is full. Start/reconnect Client and retry; no local report was deleted.")
    fd, name = tempfile.mkstemp(prefix="desktop-", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(payload)
            out.flush()
            os.fsync(out.fileno())
        try:
            os.link(name, target)  # atomic publication, never overwrite a colliding report
        except FileExistsError:
            if json.loads(target.read_text()) != report:
                raise ValueError("Conflicting queued run ID")
    finally:
        Path(name).unlink(missing_ok=True)
    return {"queued": True, "run_id": run_id, "already_queued": False}
