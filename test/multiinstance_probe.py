"""Multi-instance probe: tests file access and writes a marker."""
import sys, os, time

mode = sys.argv[1]       # 'a' or 'b'
wait = int(sys.argv[2])  # seconds to wait
shared = sys.argv[3]     # path to shared folder

marker = os.path.join(shared, f"marker_{mode}.txt")
readback = os.path.join(shared, "seed.txt")

print(f"[{mode}] START — pid={os.getpid()}")

# 1. Write our marker file
try:
    with open(marker, "w") as f:
        f.write(f"instance {mode} pid={os.getpid()}\n")
    print(f"[{mode}] WRITE marker -> OK")
except Exception as e:
    print(f"[{mode}] WRITE marker -> FAIL: {e}")
    sys.exit(1)

# 2. Read seed file
try:
    with open(readback) as f:
        content = f.read().strip()
    print(f"[{mode}] READ seed -> OK ({content})")
except Exception as e:
    print(f"[{mode}] READ seed -> FAIL: {e}")
    sys.exit(1)

# 3. Wait — other instance may exit during this time
print(f"[{mode}] Waiting {wait}s...")
time.sleep(wait)

# 4. Verify we still have access (critical: other instance's exit must not break us)
try:
    with open(readback) as f:
        content = f.read().strip()
    print(f"[{mode}] POST-WAIT READ seed -> OK ({content})")
except Exception as e:
    print(f"[{mode}] POST-WAIT READ seed -> FAIL: {e}")
    sys.exit(1)

try:
    with open(marker, "a") as f:
        f.write(f"post-wait check ok\n")
    print(f"[{mode}] POST-WAIT WRITE marker -> OK")
except Exception as e:
    print(f"[{mode}] POST-WAIT WRITE marker -> FAIL: {e}")
    sys.exit(1)

# 5. Check if other instance's marker exists (it should)
other = "b" if mode == "a" else "a"
other_marker = os.path.join(shared, f"marker_{other}.txt")
if os.path.exists(other_marker):
    print(f"[{mode}] Other marker (marker_{other}.txt) -> EXISTS")
else:
    print(f"[{mode}] Other marker (marker_{other}.txt) -> NOT YET (OK if we started first)")

print(f"[{mode}] DONE")
sys.exit(0)
