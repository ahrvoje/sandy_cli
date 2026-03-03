# stress_probe.py — Child process for concurrent stress test.
# Runs inside a Sandy container. Verifies file access, sleeps, verifies again.
# Usage: stress_probe.py <instance_id> <sleep_seconds> <folder1> [folder2] ...
import os, sys, time, json

instance = sys.argv[1]
sleep_sec = float(sys.argv[2])
folders = sys.argv[3:]
results = {"instance": instance, "pid": os.getpid(), "sleep": sleep_sec,
           "start_ok": True, "end_ok": True, "errors": []}

def check_access(phase):
    """Verify read/write access to all granted folders."""
    ok = True
    for folder in folders:
        marker = os.path.join(folder, f"stress_{instance}.tmp")
        try:
            # Write
            with open(marker, "w") as f:
                f.write(f"{instance}:{phase}:{time.time()}")
            # Read back
            with open(marker, "r") as f:
                content = f.read()
            if instance not in content:
                results["errors"].append(f"{phase}: read-back mismatch in {folder}")
                ok = False
            # List
            items = os.listdir(folder)
            if not items:
                results["errors"].append(f"{phase}: empty listing in {folder}")
                ok = False
        except Exception as e:
            results["errors"].append(f"{phase}: {type(e).__name__} in {folder}: {e}")
            ok = False
    return ok

def cleanup_markers():
    """Remove our marker files (best-effort)."""
    for folder in folders:
        marker = os.path.join(folder, f"stress_{instance}.tmp")
        try:
            os.remove(marker)
        except:
            pass

# Phase 1: verify access at start
results["start_ok"] = check_access("START")
print(f"[{instance}] START pid={os.getpid()} sleep={sleep_sec}s folders={len(folders)} ok={results['start_ok']}")
sys.stdout.flush()

# Sleep for the configured random duration
time.sleep(sleep_sec)

# Phase 2: verify access still works at end (ACLs should still be granted)
results["end_ok"] = check_access("END")
print(f"[{instance}] END ok={results['end_ok']} errors={len(results['errors'])}")
sys.stdout.flush()

# Clean markers
cleanup_markers()

# Write structured results to the granted folder (not %TEMP% — AppContainer can't write there)
result_path = os.path.join(folders[0], f"sandy_stress_{instance}.json")
with open(result_path, "w") as f:
    json.dump(results, f)

# Exit 0 if both phases passed, 1 otherwise
sys.exit(0 if (results["start_ok"] and results["end_ok"]) else 1)
