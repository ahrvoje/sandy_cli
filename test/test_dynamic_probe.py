# test_dynamic_probe.py — Probe for dynamic sandbox test
# Periodically tries to read from folder A and write to folder B.
# Writes results to a marker file so the orchestrator can verify.

import os, sys, time

folder_a = sys.argv[1]  # read-test folder
folder_b = sys.argv[2]  # write-test folder
marker   = sys.argv[3]  # output marker file

results = []

for cycle in range(8):
    time.sleep(1.5)
    
    # Test read on folder A
    try:
        files = os.listdir(folder_a)
        results.append(f"C{cycle}: read_A=OK")
    except PermissionError:
        results.append(f"C{cycle}: read_A=DENIED")
    except Exception as e:
        results.append(f"C{cycle}: read_A=ERR({e})")
    
    # Test write on folder B
    test_file = os.path.join(folder_b, f"probe_{cycle}.txt")
    try:
        with open(test_file, 'w') as f:
            f.write(f"cycle {cycle}")
        results.append(f"C{cycle}: write_B=OK")
    except PermissionError:
        results.append(f"C{cycle}: write_B=DENIED")
    except Exception as e:
        results.append(f"C{cycle}: write_B=ERR({e})")

# Write results
with open(marker, 'w') as f:
    f.write('\n'.join(results) + '\n')
