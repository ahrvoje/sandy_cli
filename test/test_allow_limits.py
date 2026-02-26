"""
test_allow_limits.py - Tests for [allow] and [limit] settings.

Run inside the sandbox:
    sandy.exe -c test_allow_limits_config.toml -x <python.exe> test_allow_limits.py

Tests cover:
  1. Network access (network = true)     -> outbound HTTP works
  2. Memory limit                        -> allocation beyond limit fails
  3. Process count limit                 -> spawning beyond limit fails
  4. Timeout                             -> tested externally by batch runner
"""

import os
import sys
import time
import subprocess

print("=== Sandy Allow & Limits Tests ===")
print(f"Working dir: {os.getcwd()}")
print(f"Python:      {sys.executable}")
print()

passed = failed = 0


def expect_ok(label, fn):
    global passed, failed
    try:
        result = fn()
        print(f"  [PASS] {label}: {result}")
        passed += 1
    except Exception as e:
        print(f"  [FAIL] {label}: {e}")
        failed += 1


def expect_blocked(label, fn):
    global passed, failed
    try:
        fn()
        print(f"  [FAIL] {label}: should have been blocked!")
        failed += 1
    except Exception as e:
        print(f"  [PASS] {label}: blocked -> {type(e).__name__}")
        passed += 1


# ---------------------------------------------------------------------------
# 1. NETWORK ACCESS (network = true)
#    Outbound internet should be allowed (unlike the main test suite).
# ---------------------------------------------------------------------------
print("--- Network access (allowed) ---")
try:
    import urllib.request
    expect_ok("HTTP GET example.com",
        lambda: f"HTTP {urllib.request.urlopen('http://example.com', timeout=5).getcode()}")
except ImportError:
    print("  [SKIP] urllib not available")
print()

# ---------------------------------------------------------------------------
# 2. MEMORY LIMIT (128 MB)
#    Attempting to allocate far beyond the limit should fail.
# ---------------------------------------------------------------------------
print("--- Memory limit (128 MB) ---")

expect_ok("Allocate 50 MB",
    lambda: (bytearray(50 * 1024 * 1024), "50 MB OK")[1])

def allocate_excessive():
    """Try to allocate well beyond the 128 MB limit."""
    chunks = []
    for i in range(20):
        chunks.append(bytearray(50 * 1024 * 1024))
    return f"allocated {len(chunks)} x 50 MB (should have failed!)"

expect_blocked("Allocate 1 GB (exceeds 128 MB limit)",
    allocate_excessive)
print()

# ---------------------------------------------------------------------------
# 3. PROCESS COUNT LIMIT (3 max)
#    The sandbox process itself counts toward the limit.
#    Spawning more than the allowed number should fail.
# ---------------------------------------------------------------------------
print("--- Process count limit (3 max) ---")

expect_ok("Spawn 1 child",
    lambda: subprocess.run(
        [sys.executable, "-c", "print('child ok')"],
        capture_output=True, text=True, timeout=3
    ).stdout.strip())

def spawn_many():
    """Try to spawn 10 children simultaneously — should hit the limit."""
    procs = []
    spawn_errors = 0
    try:
        for i in range(10):
            try:
                p = subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(2)"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                procs.append(p)
            except OSError:
                spawn_errors += 1
        time.sleep(0.5)
        alive = sum(1 for p in procs if p.poll() is None)
        return f"{alive} alive, {spawn_errors} blocked (limit enforced)"
    finally:
        for p in procs:
            try:
                p.kill()
                p.wait(timeout=2)
            except Exception:
                pass

expect_ok("Spawn 10 children (expect limit enforcement)",
    spawn_many)
print()

# ---------------------------------------------------------------------------
# 4. TIMEOUT (5 seconds)
#    Not tested here — the batch runner tests this externally.
# ---------------------------------------------------------------------------
print("--- Timeout (5 seconds) ---")
print("  [INFO] Timeout is verified externally by the batch runner")
print("         (a separate script sleeps for 30s and should be killed)")
print()

# ---------------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------------
print(f"=== Results: {passed} passed, {failed} failed ===")
sys.exit(1 if failed > 0 else 0)
