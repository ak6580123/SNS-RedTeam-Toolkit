# PyInstaller spec - onedir build. Run via packaging/build-app.ps1.
import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))
SRC = os.path.join(ROOT, "src")

hidden = collect_submodules("scripter") + collect_submodules("textual") + collect_submodules("rich")
datas = [(os.path.join(SRC, "scripter", "intel", "data"), os.path.join("scripter", "intel", "data"))]
datas += collect_data_files("textual")

a = Analysis(
    [os.path.join(SPECPATH, "entry.py")],
    pathex=[SRC],
    datas=datas,
    hiddenimports=hidden,
    excludes=["tkinter", "pytest", "coverage"],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="scripter",
    console=True,
    icon=os.path.join(SPECPATH, "assets", "icon.ico"),
    version=os.path.join(SPECPATH, "version_info.txt"),
)
coll = COLLECT(exe, a.binaries, a.datas, name="Scripter")
