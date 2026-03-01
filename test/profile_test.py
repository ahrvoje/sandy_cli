"""Profile test: parent spawns child doing sandbox-relevant actions."""
import subprocess, sys, os, tempfile

# Spawn a child that does various sandbox-configurable things
child_code = r'''
import os, sys, tempfile, socket, urllib.request

# 1. Read from user profile
home = os.path.expanduser("~")
files = os.listdir(home)
print(f"[child] Listed home dir: {len(files)} items")

# 2. Write to temp
tmp = os.path.join(tempfile.gettempdir(), "sandy_profile_test.txt")
with open(tmp, "w") as f:
    f.write("profile test data")
print(f"[child] Wrote temp file: {tmp}")
os.remove(tmp)

# 3. Read from app dir
app_dir = os.path.dirname(sys.executable)
app_files = os.listdir(app_dir)
print(f"[child] Listed app dir: {len(app_files)} items")

# 4. DNS lookup (network)
try:
    addr = socket.getaddrinfo("localhost", 80)
    print(f"[child] DNS lookup OK: {len(addr)} results")
except Exception as e:
    print(f"[child] DNS lookup: {e}")

# 5. Read some system DLLs info
sys32 = os.path.join(os.environ["WINDIR"], "System32")
dlls = [f for f in os.listdir(sys32) if f.endswith(".dll")][:5]
print(f"[child] System32 DLLs sample: {dlls}")

print("[child] Done")
'''

print("[parent] Launching child process...")
result = subprocess.run([sys.executable, "-c", child_code], capture_output=True, text=True)
print(result.stdout, end="")
if result.stderr:
    print(result.stderr, end="")
print(f"[parent] Child exited with code {result.returncode}")
