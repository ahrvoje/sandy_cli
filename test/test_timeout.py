"""
test_timeout.py - Sleeps for 30 seconds.
Used to verify Sandy's timeout limit kills the process.
If timeout=5 is configured, this should be killed after ~5 seconds.
"""
import time
print("Sleeping for 30 seconds (should be killed by timeout)...")
time.sleep(30)
print("ERROR: timeout did not trigger!")
