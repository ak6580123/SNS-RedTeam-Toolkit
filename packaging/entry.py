"""Frozen-build entry point (used only by the PyInstaller bundle).

Responsibilities that the source tree does not need:
  * locate bundled files relative to the install directory (next to the exe)
  * give the app a writable per-user workspace (config/, data/, reports/) and
    seed it with the default config on first run
  * show a short, skippable splash screen for interactive TUI starts
"""
from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path

FROZEN = getattr(sys, "frozen", False)

ART = r"""
 ____            _       _
/ ___|  ___ _ __(_)_ __ | |_ ___ _ __
\___ \ / __| '__| | '_ \| __/ _ \ '__|
 ___) | (__| |  | | |_) | |_|  __/ |
|____/ \___|_|  |_| .__/ \__|\___|_|
                  |_|
""".strip("\n").splitlines()
TAGLINE = "authorized red-team automation  -  scope first, always"


def install_dir() -> Path:
    return Path(sys.executable).resolve().parent


def workspace_dir() -> Path:
    override = os.environ.get("SCRIPTER_HOME")
    base = Path(override) if override else Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "Scripter"
    return base / "workspace"


def prepare_workspace() -> None:
    """chdir into a writable workspace; the app resolves config/ and data/ relative to cwd."""
    ws = workspace_dir()
    (ws / "config").mkdir(parents=True, exist_ok=True)
    src = install_dir() / "config" / "config.example.toml"
    if src.is_file():
        shutil.copyfile(src, ws / "config" / "config.example.toml")  # always refresh the reference copy
        user_cfg = ws / "config" / "config.toml"
        if not user_cfg.exists():  # never overwrite the user's own config
            shutil.copyfile(src, user_cfg)
    os.chdir(ws)
    os.environ.setdefault("SCRIPTER_INSTALL_DIR", str(install_dir()))


def _enable_vt() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes

        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not k.GetConsoleMode(h, ctypes.byref(mode)):
            return False
        return bool(k.SetConsoleMode(h, mode.value | 0x0004))
    except Exception:
        return False


def _key_pressed() -> bool:
    if os.name == "nt":
        import msvcrt

        if msvcrt.kbhit():
            msvcrt.getwch()
            return True
    return False


def splash() -> None:
    """Brief animated splash. Any key skips; terminal state is always restored."""
    if os.environ.get("SCRIPTER_NO_SPLASH") or not (sys.stdout.isatty() and sys.stdin.isatty()):
        return
    if not _enable_vt():
        return
    cols, rows = shutil.get_terminal_size((100, 30))
    w = max(len(line) for line in ART)
    top = max((rows - (len(ART) + 3)) // 2, 0)
    left = max((cols - w) // 2, 0)
    out = sys.stdout
    out.write("\x1b[?1049h\x1b[?25l\x1b[2J")  # alt screen, hide cursor, clear
    out.flush()
    try:
        for step, line in enumerate(ART):
            out.write(f"\x1b[{top + 1 + step};{left + 1}H\x1b[38;5;{220 + (step % 3)}m{line}\x1b[0m")
            out.flush()
            for _ in range(4):
                time.sleep(0.04)
                if _key_pressed():
                    return
        tag_col = max((cols - len(TAGLINE)) // 2, 0)
        out.write(f"\x1b[{top + len(ART) + 2};{tag_col + 1}H\x1b[2m{TAGLINE}\x1b[0m")
        out.flush()
        for _ in range(12):
            time.sleep(0.06)
            if _key_pressed():
                return
    finally:
        out.write("\x1b[0m\x1b[?25h\x1b[?1049l")  # reset, show cursor, leave alt screen
        out.flush()


def main() -> None:
    args = sys.argv[1:]
    if "--no-splash" in args:
        args.remove("--no-splash")
        sys.argv = [sys.argv[0], *args]
        os.environ["SCRIPTER_NO_SPLASH"] = "1"
    if FROZEN:
        prepare_workspace()
    if not args or args == ["tui"]:
        splash()
    from scripter.cli import app

    app()


if __name__ == "__main__":
    main()
