"""Build the Windows desktop application from the checked-in spec."""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import sys


def main():
    if os.name != "nt":
        raise SystemExit("Windows executable builds must run on Windows.")
    root = Path(__file__).resolve().parent
    npm = shutil.which("npm.cmd")
    if not npm or importlib.util.find_spec("PyInstaller") is None:
        raise SystemExit("Install Node.js and pip install -r requirements.txt first.")
    subprocess.run([npm, "ci"], cwd=root / "frontend", check=True)
    subprocess.run([npm, "run", "build"], cwd=root / "frontend", check=True)
    if not (root / "frontend/dist/index.html").is_file():
        raise SystemExit("Frontend build did not produce index.html.")

    subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm",
                    "--clean", "SentinelAudit.spec"], cwd=root, check=True)
    output = root / "dist/SentinelAudit/SentinelAudit.exe"
    if not output.is_file():
        raise SystemExit(f"Expected build output is missing: {output}")
    print(f"Built: {output}")


if __name__ == "__main__":
    try:
        main()
    except (subprocess.CalledProcessError, OSError) as exc:
        raise SystemExit(f"Build failed: {exc}") from exc
