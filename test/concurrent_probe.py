# Probe script for concurrent Sandy container test.
# Receives a ROLE argument (read/write/all) and tests access to the data folder.
# Stays alive for a configurable duration so --status can observe all 3 running.
import os, sys, time

role = sys.argv[1] if len(sys.argv) > 1 else "unknown"
folder = os.path.join(os.environ.get("USERPROFILE", "C:\\Users\\H"), "test_concurrent", "data")
marker = os.path.join(folder, f"probe_{role}.txt")
wait = int(sys.argv[2]) if len(sys.argv) > 2 else 15

results = []

# Test: list directory (requires read)
try:
    items = os.listdir(folder)
    results.append(f"  LIST:  OK ({len(items)} items)")
except Exception as e:
    results.append(f"  LIST:  BLOCKED ({type(e).__name__})")

# Test: read a file (requires read)
try:
    seed = os.path.join(folder, "seed.txt")
    content = open(seed).read().strip()
    results.append(f"  READ:  OK ({content[:30]})")
except Exception as e:
    results.append(f"  READ:  BLOCKED ({type(e).__name__})")

# Test: write a file (requires write)
try:
    open(marker, "w").write(f"written by {role}")
    results.append(f"  WRITE: OK ({marker})")
except Exception as e:
    results.append(f"  WRITE: BLOCKED ({type(e).__name__})")

# Test: delete (requires delete/all)
try:
    os.remove(marker)
    results.append(f"  DEL:   OK")
except Exception as e:
    results.append(f"  DEL:   BLOCKED ({type(e).__name__})")

print(f"[{role.upper()}] container results:")
for r in results:
    print(r)
sys.stdout.flush()

# Stay alive so --status can see us
print(f"[{role.upper()}] waiting {wait}s for status check...")
sys.stdout.flush()
time.sleep(wait)
print(f"[{role.upper()}] done.")
