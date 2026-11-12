from __future__ import annotations

import http.server
import json
import os
import secrets
import socketserver
import sys
import threading
import time
import webbrowser
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

import webview

from sentinelaudit.activity import record_export


logger = logging.getLogger("sentinelaudit")


def _configure_logging() -> None:
    log_dir = Path.home() / "SentinelAuditLogs"
    log_dir.mkdir(parents=True, exist_ok=True)

    handler = RotatingFileHandler(
        log_dir / "sentinelaudit.log",
        maxBytes=5_000_000,
        backupCount=5,
        encoding="utf-8",
    )

    logging.basicConfig(
        level=logging.INFO,
        handlers=[handler],
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def _rollback_storage_path() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")

    storage_dir = Path(base) / "SentinelAudit"
    storage_dir.mkdir(parents=True, exist_ok=True)

    rollback_path = storage_dir / "rollback.json"

    if not rollback_path.exists():
        rollback_path.touch()

    try:
        os.chmod(rollback_path, 0o600)
    except OSError:
        logger.warning("_rollback_storage_path: optional operation or cleanup failed; inspect application state")

    return rollback_path


def _start_local_server(dist_dir: Path) -> tuple[int, str]:
    """
    Start a loopback-bound HTTP server that serves the built UI under a
    per-launch random URL prefix. Returns (port, token).

    The token gates all requests so other local processes can't fetch the
    bundle just by probing 127.0.0.1:<port>/index.html.
    """
    import mimetypes

    mimetypes.add_type("application/javascript", ".js")
    mimetypes.add_type("application/javascript", ".mjs")
    mimetypes.add_type("text/css", ".css")

    token = secrets.token_urlsafe(24)
    token_prefix = f"/{token}/"

    class _Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(dist_dir), **kwargs)

        def log_message(self, format, *args):  # noqa: A002
            pass

        def _host_is_loopback(self) -> bool:
            host = (self.headers.get("Host") or "").split(":", 1)[0].strip().lower()
            return host in ("127.0.0.1", "localhost", "")

        def send_head(self):  # gates both GET and HEAD
            if not self._host_is_loopback():
                self.send_error(403, "forbidden")
                return None
            if not self.path.startswith(token_prefix):
                self.send_error(404, "not found")
                return None
            self.path = self.path[len(token_prefix) - 1 :]
            return super().send_head()

        def do_POST(self):  # not used by the UI; reject explicitly
            self.send_error(405, "method not allowed")

    class _LoopbackServer(socketserver.TCPServer):
        allow_reuse_address = False

    httpd = _LoopbackServer(("127.0.0.1", 0), _Handler)
    port: int = httpd.server_address[1]

    server_thread = threading.Thread(
        target=httpd.serve_forever,
        daemon=True,
        name="sentinelaudit-http-server",
    )

    server_thread.start()
    return port, token


def main() -> None:
    """
    Launch SentinelAudit as a native desktop window using PyWebView.
    """
    if getattr(sys, "frozen", False):
        project_root = Path(getattr(sys, "_MEIPASS"))
    else:
        project_root = Path(__file__).resolve().parents[1]
        if str(project_root) not in sys.path:
            sys.path.insert(0, str(project_root))

    _configure_logging()
    logger.info("Launching SentinelAudit desktop application")

    api = DesktopApi()

    dist_dir = project_root / "frontend" / "dist"
    if not (dist_dir / "index.html").exists():
        raise RuntimeError("frontend/dist/index.html not found. Run `npm run build` in ./frontend.")
    port, ui_token = _start_local_server(dist_dir)
    ui_target = f"http://127.0.0.1:{port}/{ui_token}/index.html"

    start_hidden = False
    try:
        from sentinelaudit.windows import is_admin

        start_hidden = bool(is_admin())
    except (ImportError, OSError, AttributeError) as exc:
        logger.warning("Admin status detection failed: %s", exc)
        start_hidden = False

    window = webview.create_window(
        "SentinelAudit",
        ui_target,
        width=1080,
        height=720,
        min_size=(620, 580),
        background_color="#0b0f1a",
        js_api=api,
        hidden=start_hidden,
    )
    api._window = window
    api._start_hidden = start_hidden
    if hasattr(window, "events") and hasattr(window.events, "closing"):
        try:
            window.events.closing += api._on_window_closing
        except (AttributeError, TypeError) as exc:
            logger.warning("Window closing hook registration failed: %s", exc)
    exposed_methods = (
        api.get_admin_status,
        api.get_access_policy,
        api.verify_pin,
        api.verify_login,
        api.set_initial_login,
        api.change_login,
        api.keep_session_alive,
        api.run_audit,
        api.start_audit,
        api.get_audit_progress,
        api.cancel_audit,
        api.sync_last_audit,
        api.fix_finding,
        api.preview_fix,
        api.rollback_fix,
        api.export_excel,
        api.backup_registry,
        api.open_updates_page,
        api.set_tray_score,
        api.exit_app,
    )
    if hasattr(window, "expose"):
        window.expose(*exposed_methods)
    elif hasattr(webview, "expose"):
        webview.expose(*exposed_methods)
    debug_enabled = os.environ.get("SENTINEL_DEBUG") == "1" and not bool(getattr(sys, "frozen", False))
    webview.start(api.on_start, gui="edgechromium", debug=debug_enabled)




class DesktopApi:
    def __init__(self) -> None:
        self._window: webview.Window | None = None
        self._rollback_cache: dict[str, dict[str, object]] = self._load_rollback_cache()
        self._allow_exit = False
        self._start_hidden = False
        self._tray = None
        self._session_timeout_s = 15 * 60
        self._session_expires_unix: float | None = None
        self._session_username: str | None = None
        # Cache of the most recent full audit so we can splice in fix/rollback
        # results and return an engine-computed score the frontend can trust.
        from sentinelaudit.models import Finding  # local import to avoid cycles

        self._last_findings: list[Finding] = []
        # Streaming audit state: a worker thread appends serialized findings as
        # checks complete; the UI polls get_audit_progress for incremental
        # results instead of blocking on one big run_audit round-trip.
        self._audit_lock = threading.Lock()
        self._audit_cancel = threading.Event()
        self._audit_thread = None
        self._last_report = None
        self._last_generated_utc = None
        self._activity_lock = threading.RLock()
        self._activity_ledger = None
        self._audit_state: dict[str, object] = {
            "running": False,
            "done": False,
            "total": 0,
            "completed": 0,
            "hardening_score": 0,
            "findings": [],
        }

    def _activity(self, action, **details):
        from sentinelaudit.activity import Ledger, activity_directory

        with self._activity_lock:
            if self._activity_ledger is None:
                self._activity_ledger = Ledger(activity_directory() / "activity-ledger.sqlite3")
            self._activity_ledger.verify()
            self._activity_ledger.append(
                {"action": action, "time": time.time(), "actor": self._session_username or "local-user", **details}
            )
            sequence, hashed = self._activity_ledger.verify()
            self._activity_ledger.acknowledge(sequence, hashed)  # local checkpoint, not remote attestation

    def sync_last_audit(self):
        from sentinelaudit.sync import queue_report

        ok, err = self._require_session()
        if not ok:
            return err or {"error": "Sign in before syncing."}
        with self._audit_lock:
            if self._audit_state.get("running") or not self._last_report:
                return {
                    "error": "Complete a fresh audit before syncing; cancelled or modified results are not uploaded."
                }
            report = json.loads(json.dumps(self._last_report))
        try:
            self._activity("sync_requested", run_id=report["run_id"])
            result = queue_report(report)
        except Exception as exc:
            return {"error": str(exc)}
        try:
            self._activity("sync_queued", run_id=report["run_id"])
        except Exception:
            result["warning"] = "Queued, but the audit-trail outcome could not be recorded."
        result["message"] = (
            "Queued in the local Client. Keep Client running to deliver it; Admin receipt is not yet confirmed."
        )
        return result

    def cancel_audit(self):
        with self._audit_lock:
            if not self._audit_state.get("running"):
                return {"ok": True, "already_finished": True}
            self._audit_cancel.set()
            self._audit_state["cancelling"] = True
        return {"ok": True, "message": "Cancellation requested. Waiting for the current Windows check to finish."}

    @staticmethod
    def _load_rollback_cache() -> dict[str, dict[str, object]]:
        path = _rollback_storage_path()
        try:
            if not path.is_file():
                return {}
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return {}
            # Filter: only keep entries whose values are dicts.
            return {str(k): v for k, v in data.items() if isinstance(v, dict)}
        except Exception:
            return {}

    def _save_rollback_cache(self) -> None:
        path = _rollback_storage_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(self._rollback_cache, default=str), encoding="utf-8")
            os.replace(tmp, path)
        except Exception:
            # Persistence is best-effort; in-memory cache is still authoritative
            # for the current session.
            logger.warning("_save_rollback_cache: optional operation or cleanup failed; inspect application state")

    def _splice_finding_and_score(self, updated) -> int:
        """Replace any cached finding with the same id, return new score."""
        from sentinelaudit.audit.engine import compute_hardening_score

        self._last_report = None  # require a fresh assessment before fleet handoff
        replaced = False
        for i, f in enumerate(self._last_findings):
            if f.finding_id == updated.finding_id:
                self._last_findings[i] = updated
                replaced = True
                break
        if not replaced:
            self._last_findings.append(updated)
        return int(compute_hardening_score(self._last_findings))

    def _session_remaining_s(self) -> int:
        exp = self._session_expires_unix
        if exp is None:
            return 0
        remaining = int(exp - time.time())
        return remaining if remaining > 0 else 0

    def _session_info(self) -> dict[str, object]:
        remaining = self._session_remaining_s()
        return {"remaining_s": int(remaining), "expired": bool(remaining <= 0)}

    def _require_session(self) -> tuple[bool, dict[str, object] | None]:
        if self._session_remaining_s() <= 0:
            self._session_expires_unix = None
            self._session_username = None
            return (
                False,
                {
                    "error": "Session expired. Please login again.",
                    "session": {"remaining_s": 0, "expired": True},
                },
            )
        self._session_expires_unix = time.time() + float(self._session_timeout_s)
        return (True, None)

    def get_admin_status(self) -> dict[str, bool]:
        from sentinelaudit import __version__
        from sentinelaudit.windows import is_admin

        return {"is_admin": bool(is_admin()), "version": __version__}

    def get_access_policy(self) -> dict[str, object]:
        from sentinelaudit.windows import get_remediation_pin_hash, is_app_login_configured

        return {
            "pin_required": bool(get_remediation_pin_hash()),
            "session_timeout_s": int(self._session_timeout_s),
            "setup_required": not bool(is_app_login_configured()),
        }

    def verify_pin(self, pin: str) -> dict[str, object]:
        from sentinelaudit.windows import verify_remediation_pin_detailed

        ok, retry_after_s = verify_remediation_pin_detailed(pin)
        return {"ok": bool(ok), "retry_after_s": int(retry_after_s)}

    def verify_login(self, username: str, password: str) -> dict[str, object]:
        from sentinelaudit.windows import verify_app_login_detailed

        ok, err, retry_after_s = verify_app_login_detailed(username, password)
        if ok:
            self._session_expires_unix = time.time() + float(self._session_timeout_s)
            self._session_username = (username or "").strip() or None
            return {"ok": True, "session_timeout_s": int(self._session_timeout_s)}
        if (err or "").strip().lower() == "setup required.":
            return {"ok": False, "error": err, "setup_required": True, "retry_after_s": 0}
        return {"ok": False, "error": err or "Invalid login.", "retry_after_s": int(retry_after_s or 0)}

    def set_initial_login(self, username: str, password: str) -> dict[str, object]:
        from sentinelaudit.windows import append_remediation_audit_log, set_initial_app_login

        ok, err = set_initial_app_login(username=username, password=password)
        if not ok:
            append_remediation_audit_log(
                {
                    "action": "set_initial_login",
                    "result": "failure",
                    "actor_username": (username or "").strip(),
                    "new_username": (username or "").strip(),
                    "error": err or "Setup failed.",
                }
            )
            return {"ok": False, "error": err or "Setup failed."}
        append_remediation_audit_log(
            {
                "action": "set_initial_login",
                "result": "success",
                "actor_username": (username or "").strip(),
                "new_username": (username or "").strip(),
            }
        )
        self._session_expires_unix = time.time() + float(self._session_timeout_s)
        self._session_username = (username or "").strip() or None
        return {"ok": True, "session_timeout_s": int(self._session_timeout_s)}

    def keep_session_alive(self) -> dict[str, object]:
        """Extend the active session (if any) and return the new session info.

        Returns `{session: {...}}` so the frontend can use the standard
        `isSessionExpired` helper and update its local idle clock from the
        authoritative server-side value.
        """
        ok_session, err = self._require_session()
        if not ok_session and err:
            return err
        return {"ok": True, "session": self._session_info()}

    def change_login(self, current_password: str, new_username: str, new_password: str) -> dict[str, object]:
        from sentinelaudit.windows import append_remediation_audit_log, change_app_login

        ok_session, err = self._require_session()
        if not ok_session and err:
            return {"ok": False, **err}
        ok, err = change_app_login(
            current_password=current_password,
            new_username=new_username,
            new_password=new_password,
        )
        if not ok:
            append_remediation_audit_log(
                {
                    "action": "change_login",
                    "result": "failure",
                    "actor_username": self._session_username,
                    "new_username": (new_username or "").strip(),
                    "error": err or "Change failed.",
                }
            )
            return {"ok": False, "error": err or "Change failed."}
        append_remediation_audit_log(
            {
                "action": "change_login",
                "result": "success",
                "actor_username": self._session_username,
                "new_username": (new_username or "").strip(),
            }
        )
        return {"ok": True, "session": self._session_info()}

    def _json_safe(self, obj: object) -> object:
        if obj is None or isinstance(obj, (bool, int, float)):
            return obj
        if isinstance(obj, str):
            if len(obj) <= 2000:
                return obj
            return obj[:2000] + "…"
        if isinstance(obj, dict):
            return {str(k): self._json_safe(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self._json_safe(v) for v in obj]
        return str(obj)

    def _extract_evidence(self, finding: object) -> dict[str, object] | None:
        details = getattr(finding, "details", None)
        if not isinstance(details, dict):
            return None
        out: dict[str, object] = {}
        for k in ("policy_source", "evidence_registry", "evidence_command"):
            if k in details:
                out[k] = self._json_safe(details.get(k))
        return out or None

    def run_audit(self):
        started = self.start_audit()
        if started.get("error"):
            return started
        thread = self._audit_thread
        if thread:
            thread.join()
        return self.get_audit_progress()

    def start_audit(self) -> dict[str, object]:
        from sentinelaudit.services.audit_registry import load_checks
        from sentinelaudit.windows import is_admin

        if is_admin():
            ok, err = self._require_session()
            if not ok:
                return err or {"ok": False, "error": "Sign in before scanning."}
        with self._audit_lock:
            if self._audit_state.get("running"):
                return {"ok": True, "already_running": True}
            try:
                checks = load_checks()
                self._activity("scan_started", total=len(checks))
            except Exception:
                return {
                    "ok": False,
                    "error": "Cannot start: check local storage permissions and audit-trail integrity. Preserve the ledger if verification failed.",
                }
            self._audit_cancel.clear()
            self._last_report = None
            self._audit_state = {
                "running": True,
                "done": False,
                "cancelled": False,
                "cancelling": False,
                "total": len(checks),
                "completed": 0,
                "hardening_score": 0,
                "findings": [],
                "current_check": "",
            }
            self._audit_thread = threading.Thread(
                target=self._audit_worker, args=(checks,), name="sentinel-audit", daemon=False
            )
            self._audit_thread.start()
        return {"ok": True, "already_running": False}

    def _audit_worker(self, checks):
        from datetime import datetime, timezone
        from sentinelaudit.audit.base import CheckContext
        from sentinelaudit.audit.engine import run_checks, compute_hardening_score, AuditCancelled
        from sentinelaudit.posture import build_posture_report
        from sentinelaudit.windows import is_admin

        def progress(completed, total, current, findings):
            with self._audit_lock:
                self._audit_state.update(
                    completed=completed,
                    total=total,
                    current_check=current,
                    findings=[f.model_dump(mode="json") for f in findings],
                    hardening_score=compute_hardening_score(findings),
                )

        try:
            result = run_checks(checks, CheckContext(is_admin=is_admin()), cancel=self._audit_cancel, progress=progress)
            report = build_posture_report(result)
            import hashlib

            self._activity(
                "scan_completed",
                run_id=report["run_id"],
                total=len(result.findings),
                report_sha256=hashlib.sha256(
                    json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
                ).hexdigest(),
            )
            with self._audit_lock:
                self._last_findings = list(result.findings)
                self._last_generated_utc = result.generated_utc
                self._last_report = report
        except AuditCancelled as exc:
            with self._audit_lock:
                self._audit_state["cancelled"] = True
            try:
                self._activity("scan_cancelled", completed=len(exc.findings), total=len(checks))
            except Exception:
                with self._audit_lock:
                    self._audit_state["error"] = (
                        "Cancelled; activity recording failed. Check ledger integrity and storage permissions."
                    )
        except Exception as exc:
            logger.exception("Audit worker failed")
            with self._audit_lock:
                self._audit_state["error"] = (
                    f"Audit could not complete ({type(exc).__name__}). Check storage permissions, Windows services and the local log, then retry."
                )
            try:
                self._activity("scan_failed", error_type=type(exc).__name__)
            except Exception:
                logger.warning("Could not record scan failure; inspect activity ledger and storage permissions")
        finally:
            with self._audit_lock:
                self._audit_state.update(
                    running=False,
                    done=True,
                    cancelling=False,
                    current_check="",
                    generated_utc=datetime.now(timezone.utc).isoformat(),
                    rollback_available_finding_ids=sorted(self._rollback_cache),
                )

    def get_audit_progress(self) -> dict[str, object]:
        with self._audit_lock:
            return dict(self._audit_state)

    def fix_finding(self, finding_id: str) -> dict[str, object]:
        with self._audit_lock:
            if self._audit_state.get("running"):
                return {"error": "Wait for the current scan or cancel it before changing settings."}
        from sentinelaudit.audit.base import CheckContext
        from sentinelaudit.audit.engine import enrich_finding
        from sentinelaudit.services.audit_registry import get_check_by_id
        from sentinelaudit.windows import append_remediation_audit_log, is_admin

        ok_session, err = self._require_session()
        if not ok_session and err:
            return err
        check = get_check_by_id(finding_id)
        if not check:
            return {"error": "Unknown finding_id"}
        ctx = CheckContext(is_admin=is_admin())
        before = None
        try:
            before = check.check(ctx)
        except Exception:
            before = None
        try:
            finding = check.fix(ctx)
            rollback_state = finding.details.get("rollback_state")
            if isinstance(rollback_state, dict):
                self._rollback_cache[finding_id] = rollback_state
                self._save_rollback_cache()
            append_remediation_audit_log(
                {
                    "action": "fix",
                    "result": "success",
                    "actor_username": self._session_username,
                    "finding_id": finding_id,
                    "before_status": getattr(before, "status", None).value if before else None,
                    "after_status": getattr(finding, "status", None).value,
                    "before_evidence": self._extract_evidence(before),
                    "after_evidence": self._extract_evidence(finding),
                }
            )
            enriched = enrich_finding(finding)
            new_score = self._splice_finding_and_score(enriched)
            return {
                "finding": enriched.model_dump(mode="json"),
                "hardening_score": new_score,
                "session": self._session_info(),
            }
        except Exception as exc:
            append_remediation_audit_log(
                {
                    "action": "fix",
                    "result": "failure",
                    "actor_username": self._session_username,
                    "finding_id": finding_id,
                    "before_status": getattr(before, "status", None).value if before else None,
                    "before_evidence": self._extract_evidence(before),
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            return {"error": f"{type(exc).__name__}: {exc}"}

    def preview_fix(self, finding_id: str) -> dict[str, object]:
        from sentinelaudit.audit.base import CheckContext
        from sentinelaudit.services.audit_registry import get_check_by_id
        from sentinelaudit.windows import is_admin

        ok_session, err = self._require_session()
        if not ok_session and err:
            return err
        check = get_check_by_id(finding_id)
        session = self._session_info()
        if not check:
            return {"error": "Unknown finding_id", "session": session}
        if not hasattr(check, "preview"):
            return {"supported": False, "session": session}
        preview = check.preview(CheckContext(is_admin=is_admin()))
        if not isinstance(preview, dict):
            return {"supported": False, "session": session}
        preview = dict(preview)
        preview["session"] = session
        return preview

    def rollback_fix(self, finding_id: str) -> dict[str, object]:
        with self._audit_lock:
            if self._audit_state.get("running"):
                return {"error": "Wait for the current scan or cancel it before changing settings."}
        from sentinelaudit.audit.base import CheckContext
        from sentinelaudit.audit.engine import enrich_finding
        from sentinelaudit.services.audit_registry import get_check_by_id
        from sentinelaudit.windows import append_remediation_audit_log, is_admin

        ok_session, err = self._require_session()
        if not ok_session and err:
            return err
        check = get_check_by_id(finding_id)
        if not check:
            return {"error": "Unknown finding_id"}
        rollback_state = self._rollback_cache.get(finding_id)
        if not rollback_state:
            return {"error": "No rollback data available for this finding."}
        if not hasattr(check, "rollback"):
            return {"error": "Rollback not supported for this finding."}
        ctx = CheckContext(is_admin=is_admin())
        before = None
        try:
            before = check.check(ctx)
        except Exception:
            before = None
        try:
            finding = check.rollback(ctx, rollback_state)
            append_remediation_audit_log(
                {
                    "action": "rollback",
                    "result": "success",
                    "actor_username": self._session_username,
                    "finding_id": finding_id,
                    "before_status": getattr(before, "status", None).value if before else None,
                    "after_status": getattr(finding, "status", None).value,
                    "before_evidence": self._extract_evidence(before),
                    "after_evidence": self._extract_evidence(finding),
                }
            )
            enriched = enrich_finding(finding)
            new_score = self._splice_finding_and_score(enriched)
            # Rollback consumed the saved state; drop it.
            if finding_id in self._rollback_cache:
                del self._rollback_cache[finding_id]
                self._save_rollback_cache()
            return {
                "finding": enriched.model_dump(mode="json"),
                "hardening_score": new_score,
                "session": self._session_info(),
            }
        except Exception as exc:
            append_remediation_audit_log(
                {
                    "action": "rollback",
                    "result": "failure",
                    "actor_username": self._session_username,
                    "finding_id": finding_id,
                    "before_status": getattr(before, "status", None).value if before else None,
                    "before_evidence": self._extract_evidence(before),
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            return {"error": f"{type(exc).__name__}: {exc}"}

    @record_export("report_export")
    def export_excel(self) -> dict[str, object]:
        from datetime import datetime, timezone
        import platform

        from sentinelaudit import __version__
        from sentinelaudit.audit.base import CheckContext
        from sentinelaudit.audit.engine import compute_hardening_score, run_checks
        from sentinelaudit.models import AuditResult
        from sentinelaudit.reporting.excel import build_excel_report
        from sentinelaudit.services.audit_registry import load_checks
        from sentinelaudit.windows import is_admin, pick_save_path

        admin = bool(is_admin())
        # Elevated runs require the app login; exporting carries the same
        # posture data as the dashboard, so gate it like other privileged calls.
        # Non-elevated runs have no login/session, so they export freely.
        if admin:
            ok_session, err = self._require_session()
            if not ok_session and err:
                return {"saved_to": None, **err}
        with self._audit_lock:
            if (
                self._audit_state.get("running")
                or self._audit_state.get("cancelled")
                or self._audit_state.get("error")
                or not self._last_findings
            ):
                return {
                    "saved_to": None,
                    "error": "Complete a successful audit before exporting. Partial/cancelled scans are not exported as complete reports.",
                }
            export_findings = list(self._last_findings)
            export_generated_utc = self._last_generated_utc
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
        suggested = f"SentinelAudit_Report_{ts}.xlsx"

        chosen_path = pick_save_path(
            default_filename=suggested,
            title="Save SentinelAudit Report",
            file_filter="Excel Workbook (*.xlsx)\0*.xlsx\0\0",
        )
        if not chosen_path and self._window:
            dialog_type = None
            file_dialog = getattr(webview, "FileDialog", None)
            if file_dialog is not None:
                dialog_type = getattr(file_dialog, "SAVE", None)
            if dialog_type is None:
                dialog_type = getattr(webview, "SAVE_DIALOG", None)

            if dialog_type is not None:
                try:
                    selection = self._window.create_file_dialog(
                        dialog_type,
                        save_filename=suggested,
                        file_types=("Excel Workbook (*.xlsx)",),
                    )
                    if selection:
                        chosen_path = selection[0] if isinstance(selection, list) else selection
                except Exception:
                    chosen_path = None

        if not chosen_path:
            return {"saved_to": None}

        # Export what the dashboard is showing (including applied fixes) rather
        # than re-running the whole audit; fall back to a fresh run only when
        # no audit has happened yet.
        if export_findings:
            findings = export_findings
            result = AuditResult(
                hardening_score=int(compute_hardening_score(findings)),
                findings=findings,
                generated_utc=export_generated_utc or datetime.now(timezone.utc),
            )
        else:
            result = run_checks(load_checks(), CheckContext(is_admin=admin))
        host_info = {
            "hostname": platform.node(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "is_admin": admin,
            "sentinelaudit_version": __version__,
        }
        content = build_excel_report(result, host_info=host_info)

        out_path = Path(chosen_path)
        try:
            import tempfile

            fd, temporary = tempfile.mkstemp(prefix=".sentinel-", suffix=".tmp", dir=out_path.parent)
            try:
                with os.fdopen(fd, "wb") as output:
                    output.write(content)
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temporary, out_path)
            finally:
                Path(temporary).unlink(missing_ok=True)
            return {"saved_to": str(out_path)}
        except Exception as exc:
            return {"saved_to": None, "error": f"{type(exc).__name__}: {exc}"}

    @record_export("registry_export")
    def backup_registry(self) -> dict[str, object]:
        import time as _time
        from sentinelaudit.windows import backup_registry_keys, pick_save_path

        ts = _time.strftime("%Y%m%d_%H%M%S")
        suggested = f"SentinelAudit_RegBackup_{ts}.reg"

        chosen_path = pick_save_path(
            default_filename=suggested,
            title="Save Registry Backup",
            file_filter="Registry File (*.reg)\0*.reg\0All Files (*.*)\0*.*\0\0",
            default_ext="reg",
        )
        if not chosen_path and self._window:
            dialog_type = None
            file_dialog = getattr(webview, "FileDialog", None)
            if file_dialog is not None:
                dialog_type = getattr(file_dialog, "SAVE", None)
            if dialog_type is None:
                dialog_type = getattr(webview, "SAVE_DIALOG", None)
            if dialog_type is not None:
                try:
                    selection = self._window.create_file_dialog(
                        dialog_type,
                        save_filename=suggested,
                        file_types=("Registry File (*.reg)",),
                    )
                    if selection:
                        chosen_path = selection[0] if isinstance(selection, list) else selection
                except Exception:
                    chosen_path = None

        if not chosen_path:
            return {"saved_to": None}

        ok, err = backup_registry_keys(chosen_path)
        if not ok:
            return {"saved_to": None, "error": err or "Backup failed."}
        return {"saved_to": chosen_path}

    def open_updates_page(self) -> dict[str, object]:
        from sentinelaudit.windows import get_update_url

        url = get_update_url()
        if not url:
            return {"ok": False, "error": "Update URL is not configured."}
        try:
            ok = bool(webbrowser.open(url, new=2))
            return {"ok": bool(ok), "url": url}
        except Exception as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    def on_start(self) -> None:
        from sentinelaudit.windows import TrayController, is_admin

        if not self._window:
            return

        if not is_admin():
            try:
                self._window.show()
            except Exception:
                logger.warning("on_start: optional operation or cleanup failed; inspect application state")
            return

        try:
            self._tray = TrayController(
                title="SentinelAudit",
                on_open=self._tray_open,
                on_exit=self._tray_exit,
            )
            ok = self._tray.start(initial_score=0)
            if not ok:
                self._tray = None
                try:
                    self._window.show()
                except Exception:
                    logger.warning("on_start: optional operation or cleanup failed; inspect application state")
        except Exception:
            self._tray = None
            try:
                self._window.show()
            except Exception:
                logger.warning("on_start: optional operation or cleanup failed; inspect application state")

    def _tray_open(self) -> None:
        if not self._window:
            return
        try:
            self._window.show()
            try:
                self._window.restore()
            except Exception:
                logger.warning("_tray_open: optional operation or cleanup failed; inspect application state")
        except (AttributeError, TypeError) as exc:
            logger.warning("Window closing hook registration failed: %s", exc)

    def _tray_exit(self) -> None:
        self.exit_app()

    def _on_window_closing(self, *args: object, **kwargs: object) -> bool:
        if self._allow_exit:
            return True
        if self._tray is None:
            return True
        if not self._window:
            return True
        try:
            self._window.hide()
        except (AttributeError, TypeError) as exc:
            logger.warning("Window closing hook registration failed: %s", exc)
        return False

    def set_tray_score(self, score: int) -> dict[str, bool]:
        tray = self._tray
        if tray is None:
            return {"ok": False}
        try:
            tray.set_score(int(score))
            return {"ok": True}
        except Exception:
            return {"ok": False}

    def exit_app(self) -> dict[str, bool]:
        if not self._window:
            return {"ok": False}
        try:
            self.cancel_audit()
            worker = self._audit_thread
            if worker and worker.is_alive():
                worker.join(timeout=30)
                if worker.is_alive():
                    return {
                        "ok": False,
                        "error": "A Windows check is still finishing. Wait for cancellation, then exit again.",
                    }
            self._allow_exit = True
            try:
                if self._tray is not None:
                    self._tray.stop()
            except Exception:
                logger.warning("exit_app: optional operation or cleanup failed; inspect application state")
            self._window.destroy()
            return {"ok": True}
        except Exception:
            return {"ok": False}


if __name__ == "__main__":
    main()
