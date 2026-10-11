"""Child operations used by test_audit_regressions.py."""
from pathlib import Path
import sys
import time

if sys.argv[1] == "hold":
    root = Path(sys.argv[2])
    (root / "ready").write_text("ready")
    deadline = time.monotonic() + 30
    while not (root / "release").exists():
        if time.monotonic() >= deadline:
            sys.exit(2)
        time.sleep(0.05)
else:
    raise ValueError("Unknown probe")
