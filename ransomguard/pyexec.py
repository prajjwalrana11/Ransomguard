"""Run Python snippets / modules in a child process, both from source and from a packaged (PyInstaller) .exe.

From source, a child is `python -m module` / `python -c code`. In a frozen build `sys.executable` is RansomGuard.exe itself,
which cannot understand -m / -c, so the exe is re-launched with --rg-module / --rg-code and `dispatch()` (called first thing
by the launcher) runs the request instead of opening the window."""
import os
import runpy
import sys

FROZEN = bool(getattr(sys, "frozen", False)) or os.environ.get("RG_FORCE_FROZEN") == "1"


def module_cmd(module, *args):
    return [sys.executable, "--rg-module", module, *map(str, args)] if FROZEN else [sys.executable, "-m", module, *map(str, args)]


def code_cmd(code):
    return [sys.executable, "--rg-code", code] if FROZEN else [sys.executable, "-c", code]


def base_dir():
    """Folder that holds queries.sql and the package: the source tree, or PyInstaller's bundle directory."""
    return getattr(sys, "_MEIPASS", None) or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def dispatch(argv):
    """Handle a child-process request. Returns True if argv was one (the caller must then exit)."""
    if len(argv) >= 2 and argv[0] == "--rg-module":
        sys.argv = [argv[1], *argv[2:]]
        runpy.run_module(argv[1], run_name="__main__", alter_sys=True)
        return True
    if len(argv) >= 2 and argv[0] == "--rg-code":
        exec(compile(argv[1], "<ransomguard-child>", "exec"), {"__name__": "__main__"})
        return True
    return False
