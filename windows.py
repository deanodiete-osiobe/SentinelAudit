from __future__ import annotations

import logging
import ntpath
import ctypes
import base64
import json
import os
# Required for reviewed Windows audit commands; no shell execution.
import subprocess  # nosec B404
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from hmac import compare_digest
from hashlib import pbkdf2_hmac, sha256
from typing import Any

import winreg

logger = logging.getLogger(__name__)


def is_admin() -> bool:
    """
    Determine whether the current process has administrative privileges.

    Returns:
        True if the process is elevated (admin), otherwise False.
    """
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


@dataclass(frozen=True)
class CommandResult:
    stdout: str
    stderr: str
    exit_code: int


def _system_tool_path(name: str) -> str:
    """Resolve only supported tools beneath the OS-reported system directory.

    Do not trust the working directory, PATH or a caller-supplied executable path
    when running elevated audit/remediation commands.
    """
    tools = {
        "net": "net.exe", "net.exe": "net.exe",
        "reg": "reg.exe", "reg.exe": "reg.exe",
        "sc": "sc.exe", "sc.exe": "sc.exe",
        "netsh": "netsh.exe", "netsh.exe": "netsh.exe",
        "auditpol": "auditpol.exe", "auditpol.exe": "auditpol.exe",
        "secedit.exe": "secedit.exe",
        "powershell": r"WindowsPowerShell\v1.0\powershell.exe",
        "powershell.exe": r"WindowsPowerShell\v1.0\powershell.exe",
    }
    relative = tools.get(name.lower())
    if relative is None:
        raise ValueError("Unsupported audit executable")
    if sys.platform != "win32":
        raise OSError("Windows audit commands require Windows")
    directory = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(directory, len(directory))
    if not 0 < length < len(directory):
        raise OSError("Could not resolve trusted Windows system directory")
    return ntpath.join(directory.value, relative)


def run_cmd(args: list[str], timeout_s: float = 10.0) -> CommandResult:
    """
    Execute a command with stdout/stderr capture.

    Args:
        args: Command argument list (no shell).
        timeout_s: Timeout in seconds.

    Returns:
        Captured stdout/stderr and exit code.
    """
    creationflags = 0
    startupinfo = None
    if sys.platform.startswith("win"):
        creationflags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if hasattr(subprocess, "STARTUPINFO") and hasattr(subprocess, "STARTF_USESHOWWINDOW"):
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0

    if not isinstance(args, list) or not args or not all(isinstance(arg, str) and "\0" not in arg for arg in args):
        raise ValueError("Command must be a nonempty list of strings without NUL characters")
    if not 0 < timeout_s <= 120:
        raise ValueError("Command timeout must be between 0 and 120 seconds")
    # Only supported OS-directory tools; internal argument lists; shell disabled.
    command = [_system_tool_path(args[0]), *args[1:]]
    completed = subprocess.run(  # nosec B603
        command,
        shell=False,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
        encoding="utf-8",
        errors="replace",
        creationflags=creationflags,
        startupinfo=startupinfo,
    )
    return CommandResult(
        stdout=completed.stdout.strip(),
        stderr=completed.stderr.strip(),
        exit_code=int(completed.returncode),
    )


def reg_get_dword(
    hive: int,
    key_path: str,
    value_name: str,
) -> int | None:
    """
    Read a REG_DWORD value from the Windows Registry.

    Args:
        hive: winreg.HKEY_* constant.
        key_path: Subkey path.
        value_name: Value name.

    Returns:
        The DWORD value, or None if missing / unreadable.
    """
    try:
        with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
            value, value_type = winreg.QueryValueEx(key, value_name)
        if value_type != winreg.REG_DWORD:
            return None
        return int(value)
    except OSError:
        return None


def reg_set_dword(
    hive: int,
    key_path: str,
    value_name: str,
    value: int,
) -> None:
    """
    Write a REG_DWORD value to the Windows Registry.

    Args:
        hive: winreg.HKEY_* constant.
        key_path: Subkey path.
        value_name: Value name.
        value: DWORD value to set.
    """
    with winreg.CreateKeyEx(hive, key_path, 0, access=winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, value_name, 0, winreg.REG_DWORD, int(value))


def reg_set_str(
    hive: int,
    key_path: str,
    value_name: str,
    value: str,
) -> None:
    with winreg.CreateKeyEx(hive, key_path, 0, access=winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, str(value))


def reg_get_str(
    hive: int,
    key_path: str,
    value_name: str,
) -> str | None:
    """
    Read a REG_SZ value from the Windows Registry.

    Args:
        hive: winreg.HKEY_* constant.
        key_path: Subkey path.
        value_name: Value name.

    Returns:
        The string value, or None if missing / unreadable.
    """
    try:
        with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
            value, value_type = winreg.QueryValueEx(key, value_name)
        if value_type not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
            return None
        return str(value)
    except OSError:
        return None


def reg_delete_value(hive: int, key_path: str, value_name: str) -> bool:
    try:
        with winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, value_name)
        return True
    except OSError:
        return False


def safe_details(**kwargs: Any) -> dict[str, Any]:
    """
    Normalize structured details for UI display.

    Returns:
        A JSON-serializable dict.
    """
    normalized: dict[str, Any] = {}
    for k, v in kwargs.items():
        if v is None:
            continue
        normalized[k] = v
    return normalized


def get_remediation_audit_log_path() -> str | None:
    if not sys.platform.startswith("win"):
        return None
    base = None
    if is_admin():
        base = os.environ.get("ProgramData")
    if not base:
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
    if not base:
        return None
    return os.path.join(base, "SentinelAudit", "logs", "remediation_audit.jsonl")


def append_remediation_audit_log(event: dict[str, Any]) -> bool:
    path = get_remediation_audit_log_path()
    if not path:
        return False
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        payload = dict(event)
        if "timestamp_utc" not in payload:
            payload["timestamp_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        line = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        with open(path, "a", encoding="utf-8", errors="replace") as f:
            f.write(line + "\n")
        return True
    except Exception:
        return False


def read_remediation_audit_log(limit: int = 2000) -> list[dict[str, Any]]:
    path = get_remediation_audit_log_path()
    if not path:
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return []
    entries: list[dict[str, Any]] = []
    for raw in lines[-int(limit) :]:
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("Skipping malformed remediation audit record")
            continue
        if isinstance(obj, dict):
            entries.append(obj)
    return entries


def pick_save_path(
    *,
    default_filename: str,
    title: str = "Save As",
    file_filter: str = "Excel Workbook (*.xlsx)\0*.xlsx\0\0",
    default_ext: str = "xlsx",
) -> str | None:
    if not sys.platform.startswith("win"):
        return None

    class OPENFILENAMEW(ctypes.Structure):
        _fields_ = [
            ("lStructSize", ctypes.c_uint32),
            ("hwndOwner", ctypes.c_void_p),
            ("hInstance", ctypes.c_void_p),
            ("lpstrFilter", ctypes.c_wchar_p),
            ("lpstrCustomFilter", ctypes.c_wchar_p),
            ("nMaxCustFilter", ctypes.c_uint32),
            ("nFilterIndex", ctypes.c_uint32),
            ("lpstrFile", ctypes.c_wchar_p),
            ("nMaxFile", ctypes.c_uint32),
            ("lpstrFileTitle", ctypes.c_wchar_p),
            ("nMaxFileTitle", ctypes.c_uint32),
            ("lpstrInitialDir", ctypes.c_wchar_p),
            ("lpstrTitle", ctypes.c_wchar_p),
            ("Flags", ctypes.c_uint32),
            ("nFileOffset", ctypes.c_uint16),
            ("nFileExtension", ctypes.c_uint16),
            ("lpstrDefExt", ctypes.c_wchar_p),
            ("lCustData", ctypes.c_void_p),
            ("lpfnHook", ctypes.c_void_p),
            ("lpTemplateName", ctypes.c_wchar_p),
            ("pvReserved", ctypes.c_void_p),
            ("dwReserved", ctypes.c_uint32),
            ("FlagsEx", ctypes.c_uint32),
        ]

    OFN_EXPLORER = 0x00080000
    OFN_OVERWRITEPROMPT = 0x00000002
    OFN_PATHMUSTEXIST = 0x00000800
    OFN_NOCHANGEDIR = 0x00000008

    buf = ctypes.create_unicode_buffer(32768)
    buf.value = default_filename
    owner = None
    try:
        owner = ctypes.windll.user32.GetForegroundWindow()
    except Exception:
        owner = None

    ofn = OPENFILENAMEW()
    ofn.lStructSize = ctypes.sizeof(OPENFILENAMEW)
    ofn.hwndOwner = owner
    ofn.lpstrFilter = file_filter
    ofn.lpstrFile = ctypes.cast(buf, ctypes.c_wchar_p)
    ofn.nMaxFile = ctypes.sizeof(buf) // ctypes.sizeof(ctypes.c_wchar)
    ofn.lpstrTitle = title
    ofn.Flags = int(OFN_EXPLORER | OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR)
    ofn.lpstrDefExt = default_ext

    ok = bool(ctypes.windll.comdlg32.GetSaveFileNameW(ctypes.byref(ofn)))
    if not ok:
        return None
    chosen = buf.value.strip()
    return chosen or None


_REMEDIATION_REG_KEYS = [
    r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
    r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
    r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
]


def backup_registry_keys(save_path: str) -> tuple[bool, str | None]:
    """Export all registry keys touched by SentinelAudit remediation to a .reg file."""
    if not sys.platform.startswith("win"):
        return (False, "Unsupported platform.")

    _HEADER = "Windows Registry Editor Version 5.00"
    parts: list[str] = [_HEADER + "\r\n\r\n"]
    exported_any = False

    for key in _REMEDIATION_REG_KEYS:
        fd, tmp = tempfile.mkstemp(suffix=".reg")
        os.close(fd)
        try:
            result = run_cmd(["reg", "export", key, tmp, "/y"], timeout_s=15.0)
            if result.exit_code == 0:
                try:
                    with open(tmp, "r", encoding="utf-16", errors="replace") as f:
                        content = f.read()
                    idx = content.find(_HEADER)
                    if idx >= 0:
                        body = content[idx + len(_HEADER):].lstrip("\r\n")
                        if body.strip():
                            parts.append(body.rstrip("\r\n") + "\r\n\r\n")
                            exported_any = True
                except Exception:
                    logger.warning("backup_registry_keys: optional operation or cleanup failed; inspect application state")
        except Exception:
            logger.warning("backup_registry_keys: optional operation or cleanup failed; inspect application state")
        finally:
            try:
                os.unlink(tmp)
            except Exception:
                logger.warning("backup_registry_keys: optional operation or cleanup failed; inspect application state")

    if not exported_any:
        return (False, "No registry keys could be exported. Make sure the app is running as Administrator.")

    try:
        with open(save_path, "w", encoding="utf-16", errors="replace") as f:
            f.write("".join(parts))
        return (True, None)
    except Exception as exc:
        return (False, f"{type(exc).__name__}: {exc}")


def get_remediation_pin_hash() -> str | None:
    value = reg_get_str(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\SentinelAudit", "RemediationPIN_SHA256")
    if not value:
        return None
    v = value.strip().lower()
    if len(v) != 64:
        return None
    for ch in v:
        if ch not in "0123456789abcdef":
            return None
    return v


def get_update_url() -> str | None:
    value = reg_get_str(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\SentinelAudit", "UpdateUrl")
    if not value:
        return None
    v = value.strip()
    return v or None


def verify_remediation_pin_detailed(pin: str) -> tuple[bool, int]:
    """Verify the remediation access PIN with exponential lockout.

    Returns:
        (ok, retry_after_s). retry_after_s > 0 means the caller is locked out.
    """
    configured = get_remediation_pin_hash()
    if not configured:
        return (True, 0)
    now = int(time.time())
    remaining = _get_lockout_remaining_seconds(now, prefix=_PIN_LOCKOUT_PREFIX)
    if remaining > 0:
        return (False, remaining)
    candidate = sha256(pin.encode("utf-8")).hexdigest()
    if compare_digest(candidate, configured):
        _reset_lockout_state(prefix=_PIN_LOCKOUT_PREFIX)
        return (True, 0)
    return (False, _register_failed_login(now, prefix=_PIN_LOCKOUT_PREFIX))


def verify_remediation_pin(pin: str) -> bool:
    ok, _ = verify_remediation_pin_detailed(pin)
    return bool(ok)


_ADMIN_REG_PATH = r"SOFTWARE\SentinelAudit"
_ADMIN_USER_KEY = "AdminUsername"
_ADMIN_SALT_KEY = "AdminSalt_B64"
_ADMIN_HASH_KEY = "AdminPass_PBKDF2_SHA256_B64"
_ADMIN_ITER_KEY = "AdminPass_Iter"


@dataclass(frozen=True)
class AdminCredential:
    username: str
    salt_b64: str
    hash_b64: str
    iterations: int


_CRED_TARGET = "SentinelAudit.AdminLogin.v1"
_CRED_TYPE_GENERIC = 1
_CRED_PERSIST_LOCAL_MACHINE = 2


class _FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", ctypes.c_uint32), ("dwHighDateTime", ctypes.c_uint32)]


class _CREDENTIALW(ctypes.Structure):
    _fields_ = [
        ("Flags", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
        ("TargetName", ctypes.c_wchar_p),
        ("Comment", ctypes.c_wchar_p),
        ("LastWritten", _FILETIME),
        ("CredentialBlobSize", ctypes.c_uint32),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
        ("Persist", ctypes.c_uint32),
        ("AttributeCount", ctypes.c_uint32),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", ctypes.c_wchar_p),
        ("UserName", ctypes.c_wchar_p),
    ]


def _credman_read(target: str) -> tuple[str | None, bytes | None]:
    if not sys.platform.startswith("win"):
        return (None, None)
    pcred = ctypes.c_void_p()
    ok = bool(ctypes.windll.advapi32.CredReadW(ctypes.c_wchar_p(target), _CRED_TYPE_GENERIC, 0, ctypes.byref(pcred)))
    if not ok:
        return (None, None)
    try:
        cred = ctypes.cast(pcred, ctypes.POINTER(_CREDENTIALW)).contents
        size = int(cred.CredentialBlobSize)
        blob = b""
        if size > 0 and cred.CredentialBlob:
            blob = ctypes.string_at(cred.CredentialBlob, size)
        uname = cred.UserName if cred.UserName else None
        return (uname, blob)
    finally:
        try:
            ctypes.windll.advapi32.CredFree(pcred)
        except Exception:
            logger.warning("_credman_read: optional operation or cleanup failed; inspect application state")


def _credman_write(*, target: str, username: str, blob: bytes) -> bool:
    if not sys.platform.startswith("win"):
        return False
    if not isinstance(blob, (bytes, bytearray)):
        return False
    buf = ctypes.create_string_buffer(bytes(blob))
    cred = _CREDENTIALW()
    cred.Flags = 0
    cred.Type = _CRED_TYPE_GENERIC
    cred.TargetName = ctypes.c_wchar_p(target)
    cred.Comment = ctypes.c_wchar_p("SentinelAudit Admin Login")
    cred.LastWritten = _FILETIME(0, 0)
    cred.CredentialBlobSize = int(len(blob))
    cred.CredentialBlob = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))
    cred.Persist = _CRED_PERSIST_LOCAL_MACHINE
    cred.AttributeCount = 0
    cred.Attributes = None
    cred.TargetAlias = None
    cred.UserName = ctypes.c_wchar_p(username)
    ok = bool(ctypes.windll.advapi32.CredWriteW(ctypes.byref(cred), 0))
    return ok


def _credman_delete(target: str) -> bool:
    if not sys.platform.startswith("win"):
        return False
    ok = bool(ctypes.windll.advapi32.CredDeleteW(ctypes.c_wchar_p(target), _CRED_TYPE_GENERIC, 0))
    return ok


def _encode_admin_credential(cred: AdminCredential) -> bytes:
    payload = {
        "username": cred.username,
        "salt_b64": cred.salt_b64,
        "hash_b64": cred.hash_b64,
        "iterations": int(cred.iterations),
    }
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _decode_admin_credential(blob: bytes) -> AdminCredential | None:
    try:
        raw = json.loads(blob.decode("utf-8"))
    except Exception:
        return None
    if not isinstance(raw, dict):
        return None
    username = raw.get("username")
    salt_b64 = raw.get("salt_b64")
    hash_b64 = raw.get("hash_b64")
    iters = raw.get("iterations")
    if not isinstance(username, str) or not isinstance(salt_b64, str) or not isinstance(hash_b64, str):
        return None
    try:
        iterations = int(iters)
    except Exception:
        return None
    if iterations < 50_000:
        return None
    return AdminCredential(username=username, salt_b64=salt_b64, hash_b64=hash_b64, iterations=iterations)



def _validate_password_strength(p: str) -> str | None:
    """Return an error string if the password doesn't meet strength requirements, else None."""
    import re
    if len(p) < 12:
        return "Password must be at least 12 characters."
    if not re.search(r"[A-Z]", p):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", p):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"\d", p):
        return "Password must contain at least one number."
    if not re.search(r"[^A-Za-z0-9]", p):
        return "Password must contain at least one special character."
    return None


def _pbkdf2_sha256(password: str, salt: bytes, iterations: int) -> bytes:
    return pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations), dklen=32)

def _load_admin_credential() -> AdminCredential | None:
    uname, blob = _credman_read(_CRED_TARGET)
    if blob:
        decoded = _decode_admin_credential(blob)
        if decoded:
            return decoded
    configured_user = reg_get_str(winreg.HKEY_LOCAL_MACHINE, _ADMIN_REG_PATH, _ADMIN_USER_KEY)
    salt_b64 = reg_get_str(winreg.HKEY_LOCAL_MACHINE, _ADMIN_REG_PATH, _ADMIN_SALT_KEY)
    hash_b64 = reg_get_str(winreg.HKEY_LOCAL_MACHINE, _ADMIN_REG_PATH, _ADMIN_HASH_KEY)
    iters = reg_get_dword(winreg.HKEY_LOCAL_MACHINE, _ADMIN_REG_PATH, _ADMIN_ITER_KEY)
    if configured_user and salt_b64 and hash_b64 and iters:
        migrated = AdminCredential(
            username=configured_user,
            salt_b64=salt_b64,
            hash_b64=hash_b64,
            iterations=int(iters),
        )
        try:
            _credman_write(target=_CRED_TARGET, username=migrated.username, blob=_encode_admin_credential(migrated))
            reg_delete_value(winreg.HKEY_LOCAL_MACHINE, _ADMIN_REG_PATH, _ADMIN_USER_KEY)
            reg_delete_value(winreg.HKEY_LOCAL_MACHINE, _ADMIN_REG_PATH, _ADMIN_SALT_KEY)
            reg_delete_value(winreg.HKEY_LOCAL_MACHINE, _ADMIN_REG_PATH, _ADMIN_HASH_KEY)
            reg_delete_value(winreg.HKEY_LOCAL_MACHINE, _ADMIN_REG_PATH, _ADMIN_ITER_KEY)
        except Exception:
            logger.warning("_load_admin_credential: optional operation or cleanup failed; inspect application state")
        return migrated
    if uname:
        return None
    return None


_AUTH_REG_PATH = r"SOFTWARE\SentinelAudit\Auth"
_FAIL_COUNT_KEY = "FailCount"
_FIRST_FAIL_UNIX_KEY = "FirstFailUnix"
_LOCKOUT_UNTIL_UNIX_KEY = "LockoutUntilUnix"
_LOCKOUT_LEVEL_KEY = "LockoutLevel"


def _read_auth_dword(name: str) -> int | None:
    return reg_get_dword(winreg.HKEY_LOCAL_MACHINE, _AUTH_REG_PATH, name)


def _write_auth_dword(name: str, value: int) -> None:
    try:
        reg_set_dword(winreg.HKEY_LOCAL_MACHINE, _AUTH_REG_PATH, name, int(value))
    except OSError:
        logger.warning("_write_auth_dword: optional operation or cleanup failed; inspect application state")


def _reset_lockout_state(prefix: str = "") -> None:
    for k in (_FAIL_COUNT_KEY, _FIRST_FAIL_UNIX_KEY, _LOCKOUT_UNTIL_UNIX_KEY, _LOCKOUT_LEVEL_KEY):
        reg_delete_value(winreg.HKEY_LOCAL_MACHINE, _AUTH_REG_PATH, prefix + k)


def _get_lockout_remaining_seconds(now_unix: int, prefix: str = "") -> int:
    until = _read_auth_dword(prefix + _LOCKOUT_UNTIL_UNIX_KEY)
    if not until:
        return 0
    remaining = int(until) - int(now_unix)
    return remaining if remaining > 0 else 0


def _register_failed_login(now_unix: int, prefix: str = "") -> int:
    window_s = 600
    threshold = 5
    base_lock_s = 30
    max_lock_s = 3600

    until = _read_auth_dword(prefix + _LOCKOUT_UNTIL_UNIX_KEY) or 0
    if until and int(until) > int(now_unix):
        return int(until) - int(now_unix)

    count = _read_auth_dword(prefix + _FAIL_COUNT_KEY) or 0
    first = _read_auth_dword(prefix + _FIRST_FAIL_UNIX_KEY) or 0
    level = _read_auth_dword(prefix + _LOCKOUT_LEVEL_KEY) or 0

    if not first or int(now_unix) - int(first) > window_s:
        count = 0
        first = int(now_unix)

    count += 1
    _write_auth_dword(prefix + _FAIL_COUNT_KEY, count)
    _write_auth_dword(prefix + _FIRST_FAIL_UNIX_KEY, int(first))

    if count < threshold:
        return 0

    level = min(int(level) + 1, 10)
    lock_s = min(int(base_lock_s * (2 ** (level - 1))), max_lock_s)
    until = int(now_unix) + int(lock_s)
    _write_auth_dword(prefix + _LOCKOUT_LEVEL_KEY, level)
    _write_auth_dword(prefix + _LOCKOUT_UNTIL_UNIX_KEY, until)
    _write_auth_dword(prefix + _FAIL_COUNT_KEY, 0)
    _write_auth_dword(prefix + _FIRST_FAIL_UNIX_KEY, int(now_unix))
    return int(lock_s)


_PIN_LOCKOUT_PREFIX = "Pin"



def is_app_login_configured() -> bool:
    if not sys.platform.startswith("win"):
        return False
    _, blob = _credman_read(_CRED_TARGET)
    if blob and _decode_admin_credential(blob):
        return True
    configured_user = reg_get_str(winreg.HKEY_LOCAL_MACHINE, _ADMIN_REG_PATH, _ADMIN_USER_KEY)
    salt_b64 = reg_get_str(winreg.HKEY_LOCAL_MACHINE, _ADMIN_REG_PATH, _ADMIN_SALT_KEY)
    hash_b64 = reg_get_str(winreg.HKEY_LOCAL_MACHINE, _ADMIN_REG_PATH, _ADMIN_HASH_KEY)
    iters = reg_get_dword(winreg.HKEY_LOCAL_MACHINE, _ADMIN_REG_PATH, _ADMIN_ITER_KEY)
    return bool(configured_user and salt_b64 and hash_b64 and iters)


def set_initial_app_login(*, username: str, password: str) -> tuple[bool, str | None]:
    if not sys.platform.startswith("win"):
        return (False, "Unsupported platform.")
    if is_app_login_configured():
        return (False, "Login already configured.")

    u = (username or "").strip()
    p = password or ""
    if not u:
        return (False, "Username is required.")
    pw_err = _validate_password_strength(p)
    if pw_err:
        return (False, pw_err)

    salt = os.urandom(16)
    iterations = 200_000
    dk = _pbkdf2_sha256(p, salt, iterations)
    cred = AdminCredential(
        username=u,
        salt_b64=base64.b64encode(salt).decode("ascii"),
        hash_b64=base64.b64encode(dk).decode("ascii"),
        iterations=iterations,
    )
    ok = _credman_write(target=_CRED_TARGET, username=cred.username, blob=_encode_admin_credential(cred))
    if not ok:
        return (False, "Failed to write to Windows Credential Manager.")
    _reset_lockout_state()
    return (True, None)

def verify_app_login_detailed(username: str, password: str) -> tuple[bool, str | None, int]:
    if not sys.platform.startswith("win"):
        return (False, "Unsupported platform.", 0)

    now = int(time.time())
    remaining = _get_lockout_remaining_seconds(now)
    if remaining > 0:
        return (False, "Too many failed attempts. Try again later.", remaining)
    stored = _load_admin_credential()
    if not stored:
        return (False, "Setup required.", 0)

    u = (username or "").strip()
    p = password or ""
    if not u or not p:
        return (False, "Username and password are required.", 0)

    try:
        salt = base64.b64decode(stored.salt_b64.encode("ascii"), validate=True)
        expected = base64.b64decode(stored.hash_b64.encode("ascii"), validate=True)
    except Exception:
        return (False, "Login store unavailable.", 0)
    if stored.username.strip().lower() != u.lower():
        retry = _register_failed_login(now)
        return (False, "Invalid login.", retry)
    candidate = _pbkdf2_sha256(p, salt, stored.iterations)
    ok = bool(compare_digest(candidate, expected))
    if ok:
        _reset_lockout_state()
        return (True, None, 0)
    retry = _register_failed_login(now)
    return (False, "Invalid login.", retry)


def verify_app_login(username: str, password: str) -> bool:
    ok, _, _ = verify_app_login_detailed(username, password)
    return bool(ok)


def change_app_login(*, current_password: str, new_username: str, new_password: str) -> tuple[bool, str | None]:
    if not sys.platform.startswith("win"):
        return (False, "Unsupported platform.")

    stored = _load_admin_credential()
    if not stored:
        return (False, "Login not configured.")
    if not verify_app_login(stored.username, current_password):
        return (False, "Invalid current password.")

    u = (new_username or "").strip()
    p = new_password or ""
    if not u:
        return (False, "Username is required.")
    pw_err = _validate_password_strength(p)
    if pw_err:
        return (False, pw_err)

    salt = os.urandom(16)
    iterations = 200_000
    dk = _pbkdf2_sha256(p, salt, iterations)
    cred = AdminCredential(
        username=u,
        salt_b64=base64.b64encode(salt).decode("ascii"),
        hash_b64=base64.b64encode(dk).decode("ascii"),
        iterations=iterations,
    )
    ok = _credman_write(target=_CRED_TARGET, username=cred.username, blob=_encode_admin_credential(cred))
    if not ok:
        return (False, "Failed to write to Windows Credential Manager.")
    _reset_lockout_state()
    return (True, None)


def get_primary_screen_size() -> tuple[int, int]:
    if not sys.platform.startswith("win"):
        return (0, 0)
    try:
        width = int(ctypes.windll.user32.GetSystemMetrics(0))
        height = int(ctypes.windll.user32.GetSystemMetrics(1))
        return (width, height)
    except Exception:
        return (0, 0)


class TrayController:
    def __init__(
        self,
        *,
        title: str,
        on_open: callable,
        on_exit: callable,
    ) -> None:
        self._title = title
        self._on_open = on_open
        self._on_exit = on_exit
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._last_error: str | None = None

        self._hwnd: int | None = None
        self._hicon: int | None = None
        self._icon_path: str | None = None
        self._running = False

    def start(self, initial_score: int = 0) -> bool:
        if not sys.platform.startswith("win"):
            return False
        if self._thread and self._thread.is_alive():
            return True
        self._ready.clear()
        self._last_error = None
        self._thread = threading.Thread(target=self._run, args=(initial_score,), daemon=True)
        self._thread.start()
        self._ready.wait(timeout=2.0)
        if self._last_error:
            return False
        return self._hwnd is not None

    def stop(self) -> None:
        if not sys.platform.startswith("win"):
            return
        hwnd = self._hwnd
        if hwnd:
            try:
                ctypes.windll.user32.PostMessageW(hwnd, 0x0010, 0, 0)
            except Exception:
                logger.warning("stop: optional operation or cleanup failed; inspect application state")

    def set_score(self, score: int) -> None:
        if not sys.platform.startswith("win"):
            return
        hwnd = self._hwnd
        if not hwnd:
            return
        self._update_icon(hwnd, score)

    def _run(self, initial_score: int) -> None:
        if not sys.platform.startswith("win"):
            return

        try:
            user32 = ctypes.windll.user32
            shell32 = ctypes.windll.shell32

            WM_DESTROY = 0x0002
            WM_COMMAND = 0x0111
            WM_APP = 0x8000
            TRAY_CALLBACK = WM_APP + 1

            WM_LBUTTONUP = 0x0202
            WM_RBUTTONUP = 0x0205

            ID_OPEN = 1001
            ID_EXIT = 1002

            class WNDCLASSW(ctypes.Structure):
                _fields_ = [
                    ("style", ctypes.c_uint32),
                    ("lpfnWndProc", ctypes.c_void_p),
                    ("cbClsExtra", ctypes.c_int),
                    ("cbWndExtra", ctypes.c_int),
                    ("hInstance", ctypes.c_void_p),
                    ("hIcon", ctypes.c_void_p),
                    ("hCursor", ctypes.c_void_p),
                    ("hbrBackground", ctypes.c_void_p),
                    ("lpszMenuName", ctypes.c_wchar_p),
                    ("lpszClassName", ctypes.c_wchar_p),
                ]

            class POINT(ctypes.Structure):
                _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

            class GUID(ctypes.Structure):
                _fields_ = [
                    ("Data1", ctypes.c_uint32),
                    ("Data2", ctypes.c_uint16),
                    ("Data3", ctypes.c_uint16),
                    ("Data4", ctypes.c_ubyte * 8),
                ]

            class NOTIFYICONDATAW(ctypes.Structure):
                _fields_ = [
                    ("cbSize", ctypes.c_uint32),
                    ("hWnd", ctypes.c_void_p),
                    ("uID", ctypes.c_uint32),
                    ("uFlags", ctypes.c_uint32),
                    ("uCallbackMessage", ctypes.c_uint32),
                    ("hIcon", ctypes.c_void_p),
                    ("szTip", ctypes.c_wchar * 128),
                    ("dwState", ctypes.c_uint32),
                    ("dwStateMask", ctypes.c_uint32),
                    ("szInfo", ctypes.c_wchar * 256),
                    ("uTimeoutOrVersion", ctypes.c_uint32),
                    ("szInfoTitle", ctypes.c_wchar * 64),
                    ("dwInfoFlags", ctypes.c_uint32),
                    ("guidItem", GUID),
                    ("hBalloonIcon", ctypes.c_void_p),
                ]

            NIM_DELETE = 0x00000002

            TPM_RIGHTBUTTON = 0x0002
            TPM_BOTTOMALIGN = 0x0020
            TPM_LEFTALIGN = 0x0000

            self_ref = ctypes.py_object(self)

            @ctypes.WINFUNCTYPE(ctypes.c_longlong, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p)
            def wnd_proc(hwnd, msg, wparam, lparam):
                if msg == TRAY_CALLBACK:
                    lp = int(ctypes.c_void_p(lparam).value or 0)
                    if lp == WM_LBUTTONUP:
                        try:
                            self_ref.value._on_open()
                        except Exception:
                            logger.warning("_run: optional operation or cleanup failed; inspect application state")
                        return 0
                    if lp == WM_RBUTTONUP:
                        try:
                            menu = user32.CreatePopupMenu()
                            user32.InsertMenuW(menu, 0, 0x0000, ID_OPEN, "Open")
                            user32.InsertMenuW(menu, 1, 0x0000, ID_EXIT, "Exit")
                            pt = POINT()
                            user32.GetCursorPos(ctypes.byref(pt))
                            user32.SetForegroundWindow(hwnd)
                            user32.TrackPopupMenu(
                                menu,
                                TPM_RIGHTBUTTON | TPM_LEFTALIGN | TPM_BOTTOMALIGN,
                                pt.x,
                                pt.y,
                                0,
                                hwnd,
                                None,
                            )
                            user32.DestroyMenu(menu)
                        except Exception:
                            logger.warning("_run: optional operation or cleanup failed; inspect application state")
                        return 0
                    return 0

                if msg == WM_COMMAND:
                    cmd = int(ctypes.c_void_p(wparam).value or 0) & 0xFFFF
                    if cmd == ID_OPEN:
                        try:
                            self_ref.value._on_open()
                        except Exception:
                            logger.warning("_run: optional operation or cleanup failed; inspect application state")
                        return 0
                    if cmd == ID_EXIT:
                        try:
                            self_ref.value._on_exit()
                        except Exception:
                            logger.warning("_run: optional operation or cleanup failed; inspect application state")
                        return 0
                    return 0

                if msg == WM_DESTROY:
                    try:
                        user32.PostQuitMessage(0)
                    except Exception:
                        logger.warning("_run: optional operation or cleanup failed; inspect application state")
                    return 0

                return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

            hinstance = user32.GetModuleHandleW(None)
            class_name = f"SentinelAuditTray_{id(self)}"

            wc = WNDCLASSW()
            wc.style = 0
            wc.lpfnWndProc = ctypes.cast(wnd_proc, ctypes.c_void_p).value
            wc.cbClsExtra = 0
            wc.cbWndExtra = 0
            wc.hInstance = hinstance
            wc.hIcon = None
            wc.hCursor = None
            wc.hbrBackground = None
            wc.lpszMenuName = None
            wc.lpszClassName = class_name

            if not user32.RegisterClassW(ctypes.byref(wc)):
                self._ready.set()
                return

            hwnd = user32.CreateWindowExW(
                0,
                class_name,
                class_name,
                0,
                0,
                0,
                0,
                0,
                None,
                None,
                hinstance,
                None,
            )
            if not hwnd:
                self._ready.set()
                return

            self._hwnd = int(hwnd)
            self._running = True

            self._update_icon(int(hwnd), initial_score, add=True, callback_msg=TRAY_CALLBACK)
            self._ready.set()

            class MSG(ctypes.Structure):
                _fields_ = [
                    ("hwnd", ctypes.c_void_p),
                    ("message", ctypes.c_uint32),
                    ("wParam", ctypes.c_void_p),
                    ("lParam", ctypes.c_void_p),
                    ("time", ctypes.c_uint32),
                    ("pt", POINT),
                ]

            msg = MSG()
            while self._running and user32.GetMessageW(ctypes.byref(msg), None, 0, 0) != 0:
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))

            try:
                nid = NOTIFYICONDATAW()
                nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
                nid.hWnd = hwnd
                nid.uID = 1
                shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(nid))
            except Exception:
                logger.warning("_run: optional operation or cleanup failed; inspect application state")

            try:
                if self._hicon:
                    user32.DestroyIcon(ctypes.c_void_p(self._hicon))
            except Exception:
                logger.warning("_run: optional operation or cleanup failed; inspect application state")

            try:
                if self._icon_path:
                    Path = __import__("pathlib").Path
                    Path(self._icon_path).unlink(missing_ok=True)
            except Exception:
                logger.warning("_run: optional operation or cleanup failed; inspect application state")
        except Exception as exc:
            self._last_error = f"{type(exc).__name__}: {exc}"
            self._ready.set()
        finally:
            self._running = False
            self._hwnd = None

    def _update_icon(self, hwnd: int, score: int, *, add: bool = False, callback_msg: int | None = None) -> None:
        if not sys.platform.startswith("win"):
            return

        user32 = ctypes.windll.user32
        shell32 = ctypes.windll.shell32

        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", ctypes.c_uint32),
                ("Data2", ctypes.c_uint16),
                ("Data3", ctypes.c_uint16),
                ("Data4", ctypes.c_ubyte * 8),
            ]

        class NOTIFYICONDATAW(ctypes.Structure):
            _fields_ = [
                ("cbSize", ctypes.c_uint32),
                ("hWnd", ctypes.c_void_p),
                ("uID", ctypes.c_uint32),
                ("uFlags", ctypes.c_uint32),
                ("uCallbackMessage", ctypes.c_uint32),
                ("hIcon", ctypes.c_void_p),
                ("szTip", ctypes.c_wchar * 128),
                ("dwState", ctypes.c_uint32),
                ("dwStateMask", ctypes.c_uint32),
                ("szInfo", ctypes.c_wchar * 256),
                ("uTimeoutOrVersion", ctypes.c_uint32),
                ("szInfoTitle", ctypes.c_wchar * 64),
                ("dwInfoFlags", ctypes.c_uint32),
                ("guidItem", GUID),
                ("hBalloonIcon", ctypes.c_void_p),
            ]

        NIM_ADD = 0x00000000
        NIM_MODIFY = 0x00000001
        NIF_MESSAGE = 0x00000001
        NIF_ICON = 0x00000002
        NIF_TIP = 0x00000004

        LR_LOADFROMFILE = 0x00000010

        clamped = max(0, min(100, int(score)))
        icon_path = self._render_score_icon(clamped)

        hicon = int(
            user32.LoadImageW(
                None,
                icon_path,
                1,
                0,
                0,
                LR_LOADFROMFILE,
            )
            or 0
        )

        if not hicon:
            return

        try:
            tip = f"{self._title} — Score {clamped}"
            nid = NOTIFYICONDATAW()
            nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
            nid.hWnd = ctypes.c_void_p(hwnd)
            nid.uID = 1
            nid.uFlags = int(NIF_ICON | NIF_TIP | (NIF_MESSAGE if callback_msg else 0))
            nid.uCallbackMessage = int(callback_msg or 0)
            nid.hIcon = ctypes.c_void_p(hicon)
            nid.szTip = tip

            if add:
                shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid))
            else:
                shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))
        finally:
            try:
                if self._hicon:
                    user32.DestroyIcon(ctypes.c_void_p(self._hicon))
            except Exception:
                logger.warning("_update_icon: optional operation or cleanup failed; inspect application state")
            self._hicon = hicon

            try:
                if self._icon_path and self._icon_path != icon_path:
                    Path = __import__("pathlib").Path
                    Path(self._icon_path).unlink(missing_ok=True)
            except Exception:
                logger.warning("_update_icon: optional operation or cleanup failed; inspect application state")
            self._icon_path = icon_path

    def _render_score_icon(self, score: int) -> str:
        from PIL import Image, ImageDraw, ImageFont
        import os

        if score >= 80:
            bg = (0, 255, 170, 255)
        elif score >= 50:
            bg = (255, 180, 0, 255)
        else:
            bg = (255, 64, 64, 255)

        size = 64
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        draw.rounded_rectangle((0, 0, size - 1, size - 1), radius=14, fill=bg)

        txt = str(score)
        font = ImageFont.load_default()
        bbox = draw.textbbox((0, 0), txt, font=font)
        w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
        draw.text(((size - w) / 2, (size - h) / 2 - 2), txt, fill=(0, 0, 0, 255), font=font)

        fd, path = tempfile.mkstemp(prefix="sentinelaudit_tray_", suffix=".ico")
        try:
            os.close(fd)
            img.save(path, format="ICO", sizes=[(64, 64), (32, 32), (16, 16)])
        except Exception:
            try:
                os.close(fd)
            except Exception:
                logger.warning("_render_score_icon: optional operation or cleanup failed; inspect application state")
            raise
        return path
