# Double-click launcher (Windows: runs without a console window). Opens the RansomGuard application.
# The same file is the entry point of the packaged .exe, which re-launches itself to run helper processes
# (the attack simulator, demo writers) because a frozen exe cannot be called with `python -m` / `python -c`.
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ransomguard.pyexec import dispatch
if not dispatch(sys.argv[1:]):
    from ransomguard.cli import main
    main([])
