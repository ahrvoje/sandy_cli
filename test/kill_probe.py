# kill_probe.py — Child process for kill-resilience tests.
# Creates a signal file when ready, verifies file access continuously,
# and writes periodic heartbeats. Designed to be killed mid-execution.
#
# Usage: kill_probe.py <instance_id> <duration_secs> <folder1> [folder2] ...
#
# Creates:
#   <folder1>/kill_probe_<id>_ready.signal  — on startup (signals orchestrator)
#   <folder1>/kill_probe_<id>_result.json   — on clean exit (never written if killed)
import os, sys, time, json

instance = sys.argv[1]
duration = float(sys.argv[2])
folders = sys.argv[3:]
start_time = time.time()
errors = []

def verify_access(phase):
    """Test read+write+delete on all folders. Returns True if all OK."""
    ok = True
    for folder in folders:
        tag = f"kp_{instance}_{phase}"
        marker = os.path.join(folder, f"{tag}.tmp")
        try:
            with open(marker, "w") as f:
                f.write(f"{instance}:{phase}:{time.time()}")
            with open(marker, "r") as f:
                data = f.read()
            if instance not in data:
                errors.append(f"{phase}: readback mismatch in {folder}")
                ok = False
            os.remove(marker)
        except Exception as e:
            errors.append(f"{phase}: {type(e).__name__} in {folder}: {e}")
            ok = False
    return ok

# --- Phase 1: Initial access check ---
start_ok = verify_access("START")
print(f"[{instance}] START pid={os.getpid()} ok={start_ok}")
sys.stdout.flush()

# --- Signal ready (touch file so orchestrator knows we're running) ---
signal_path = os.path.join(folders[0], f"kill_probe_{instance}_ready.signal")
with open(signal_path, "w") as f:
    f.write(str(os.getpid()))

# --- Phase 2: Heartbeat loop with periodic access checks ---
heartbeat = 0
while time.time() - start_time < duration:
    time.sleep(0.5)
    heartbeat += 1
    if heartbeat % 4 == 0:  # Check access every 2 seconds
        mid_ok = verify_access(f"MID_{heartbeat}")
        if not mid_ok:
            print(f"[{instance}] MID_CHECK FAILED at heartbeat {heartbeat}")
            sys.stdout.flush()

# --- Phase 3: Final access check ---
end_ok = verify_access("END")
print(f"[{instance}] END ok={end_ok} errors={len(errors)} elapsed={time.time()-start_time:.1f}s")
sys.stdout.flush()

# --- Write result (only reached on clean exit, not if killed) ---
result = {
    "instance": instance,
    "pid": os.getpid(),
    "start_ok": start_ok,
    "end_ok": end_ok,
    "errors": errors,
    "duration": time.time() - start_time,
    "clean_exit": True
}
result_path = os.path.join(folders[0], f"kill_probe_{instance}_result.json")
with open(result_path, "w") as f:
    json.dump(result, f)

# Clean signal file
try:
    os.remove(signal_path)
except:
    pass

sys.exit(0 if (start_ok and end_ok) else 1)
