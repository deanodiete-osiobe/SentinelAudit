# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules

root = Path(SPECPATH)
a = Analysis(
    [str(root / "app/main.py")], pathex=[str(root)], binaries=[],
    datas=[(str(root / "frontend/dist"), "frontend/dist"),
           (str(root / "assets"), "assets")],
    hiddenimports=collect_submodules("sentinelaudit") + collect_submodules("pydantic"),
    hookspath=[], runtime_hooks=[], excludes=[], noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="SentinelAudit",
          debug=False, strip=False, upx=False, console=False,
          icon=str(root / "assets/sentinel_alt.ico"))
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="SentinelAudit")
