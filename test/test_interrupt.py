"""Interrupt test driver.  Runs OUTSIDE the sandbox and interrupts Sandy at the worst moments.

  build <root>        create the large tree (100 folders x 100 files) and the small tree
  killgrant <root>    end Sandy (TerminateProcess on its exact PID) while the grant on the large
                      tree is in progress; then `sandy --cleanup` must remove every ACE of the run
  ctrlc <root>        send a real console Ctrl+C while the sandboxed child runs; Sandy must clean
                      up by itself and exit with STATUS_CONTROL_C_EXIT
  desktop <root>      end three restricted-token runs; `sandy --cleanup` must remove their ACEs
                      from the window station and the desktop
  _sendctrlc <pid>    internal helper: attach to the console of <pid> and raise Ctrl+C there

Every process that this driver ends is a process that it started itself.
"""
import ctypes, os, re, subprocess, sys, time, winreg
from ctypes import wintypes

SANDY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "x64", "Release", "sandy.exe")
CONFIG_DIR = os.path.dirname(os.path.abspath(__file__))
CMD = os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe")
STATUS_CONTROL_C_EXIT = 0xC000013A

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)

SE_FILE_OBJECT, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION = 1, 7, 4
advapi32.GetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p,
                                           ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                           ctypes.POINTER(ctypes.c_void_p)]
advapi32.GetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p,
                                     ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                     ctypes.POINTER(ctypes.c_void_p)]
advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
    ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR), ctypes.c_void_p]
kernel32.LocalFree.argtypes = [ctypes.c_void_p]
user32.GetProcessWindowStation.restype = wintypes.HANDLE
user32.OpenDesktopW.restype = wintypes.HANDLE
user32.OpenDesktopW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
user32.CloseDesktop.argtypes = [wintypes.HANDLE]

pass_count = 0
fail_count = 0


def test(name, condition, detail=""):
    global pass_count, fail_count
    if condition:
        print(f"  [PASS] {name}")
        pass_count += 1
    else:
        print(f"  [FAIL] {name}" + (f" -- {detail}" if detail else ""))
        fail_count += 1


def sddl_of(sd):
    text = wintypes.LPWSTR()
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, DACL_SECURITY_INFORMATION,
                                                                  ctypes.byref(text), None)
    value = text.value or ""
    kernel32.LocalFree(text)
    kernel32.LocalFree(sd)
    return value


def file_dacl(path):
    sd = ctypes.c_void_p()
    if advapi32.GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, None, None, None, None,
                                      ctypes.byref(sd)):
        return ""
    return sddl_of(sd)


def count_sid(tree, sid):
    """(objects under <tree>, root included, whose DACL names the SID; does the root name it)."""
    count = 0
    for base, _dirs, files in os.walk(tree):
        count += sid in file_dacl(base)
        count += sum(sid in file_dacl(os.path.join(base, f)) for f in files)
    return count, sid in file_dacl(tree)


def window_object_sids(handle):
    sd = ctypes.c_void_p()
    err = advapi32.GetSecurityInfo(handle, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, None, None, None, None,
                                   ctypes.byref(sd))
    assert err == 0, f"GetSecurityInfo failed: {err}"
    return set(re.findall(r"S-1-9-[0-9-]+", sddl_of(sd)))


def desktop_sids():
    """Restricted-token instance SIDs in the DACL of the window station and of the Default desktop."""
    station = window_object_sids(user32.GetProcessWindowStation())
    desktop_handle = user32.OpenDesktopW("Default", 0, False, 0x00020000)  # READ_CONTROL
    desktop = window_object_sids(desktop_handle)
    user32.CloseDesktop(desktop_handle)
    return station | desktop


def ledgers():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Sandy\Grants") as key:
            return {winreg.EnumKey(key, i) for i in range(winreg.QueryInfoKey(key)[0])}
    except OSError:
        return set()


def read_log(log):
    try:
        with open(log, encoding="utf-8-sig", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def wait_for(log, needle, timeout=60):
    start = time.time()
    while time.time() - start < timeout:
        if needle in read_log(log):
            return True
        time.sleep(0.005)
    return False


def fresh_log(root, tag):
    log = os.path.join(root, tag + ".log")
    for name in os.listdir(root):
        if name.startswith(tag + ".log"):
            os.remove(os.path.join(root, name))
    return log


def run_sid(log):
    match = re.search(r"RT_SID: (S-[0-9-]+)", read_log(log))
    return match.group(1) if match else None


def instance_id(log):
    match = re.search(r"SandyCleanup_([0-9a-fA-F-]{36})", read_log(log))
    return match.group(1) if match else None


def cleanup():
    return subprocess.run([SANDY, "--cleanup"], capture_output=True, text=True, errors="replace")


# ---------------------------------------------------------------------
def build(root):
    big, small = os.path.join(root, "big"), os.path.join(root, "small")
    for d in range(100):
        folder = os.path.join(big, f"d{d:03}")
        os.makedirs(folder, exist_ok=True)
        for f in range(100):
            with open(os.path.join(folder, f"f{f:03}.txt"), "w") as handle:
                handle.write("x")
    os.makedirs(small, exist_ok=True)
    with open(os.path.join(small, "f.txt"), "w") as handle:
        handle.write("x")
    print(f"  [OK] large tree: {sum(len(files) for _, _, files in os.walk(big))} files in 100 folders")
    return 0


def killgrant(root):
    big = os.path.join(root, "big")
    config = os.path.join(CONFIG_DIR, "test_interrupt_big_config.toml")
    child = [CMD, "/c", "exit 0"]

    # A complete run tells how long the grant takes; the kill goes to the middle of that time.
    log = fresh_log(root, "time")
    result = subprocess.run([SANDY, "-c", config, "-q", "-l", log, "-x"] + child, capture_output=True)
    match = re.search(r"TIMING: grants applied in (\d+)ms", read_log(log))
    test("reference run on the large tree ends clean", result.returncode == 0 and match is not None,
         f"exit {result.returncode}")
    if not match:
        return
    grant_seconds = int(match.group(1)) / 1000.0
    print(f"  [OK] grant on the large tree takes {grant_seconds:.2f}s")
    test("reference run leaves no ACE of its SID", count_sid(big, run_sid(log))[0] == 0)

    # The root folder gets its ACE last.  "Some objects hold the SID, the root does not" is the proof
    # that the kill came in the middle of the grant.  Timing is not exact, so try other moments too.
    hit = False
    for attempt, fraction in enumerate((0.5, 0.3, 0.7), start=1):
        log = fresh_log(root, f"kill{attempt}")
        known = ledgers()
        proc = subprocess.Popen([SANDY, "-c", config, "-q", "-l", log, "-x"] + child,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not wait_for(log, "PIPELINE: sorted"):
            proc.kill()
            proc.wait()
            test("grant phase reached", False, "no PIPELINE line in the log")
            return
        time.sleep(grant_seconds * fraction)
        proc.kill()  # TerminateProcess on the exact PID of the process started above
        proc.wait()
        sid = run_sid(log)
        marked, root_marked = count_sid(big, sid)
        own_ledger = ledgers() - known
        print(f"  [OK] attempt {attempt}: killed PID {proc.pid} at {fraction:.0%} of the grant; "
              f"{marked} objects hold the SID, root: {root_marked}, ledger written: {bool(own_ledger)}")
        mid_grant = marked > 0 and not root_marked
        if mid_grant:
            hit = True
            test("ledger of the killed run exists although the grant was not complete", bool(own_ledger))
        result = cleanup()
        left, _ = count_sid(big, sid)
        test(f"attempt {attempt}: --cleanup removed every ACE of the killed run", left == 0,
             f"{left} objects still hold {sid}")
        test(f"attempt {attempt}: --cleanup removed the ledger of the killed run", not (ledgers() - known),
             result.stdout.strip()[-200:])
        if hit:
            break
    test("the kill came in the middle of a grant in at least one attempt", hit)


def send_ctrl_c(pid):
    """Raise Ctrl+C on the console of <pid>, as a user at the keyboard does.  A helper process does
    it: the caller keeps its own console."""
    helper = subprocess.run([sys.executable, os.path.abspath(__file__), "_sendctrlc", str(pid)],
                            capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    return helper.returncode == 0, (helper.stdout + helper.stderr).strip()


def _sendctrlc(pid):
    kernel32.FreeConsole()
    if not kernel32.AttachConsole(pid):
        print(f"AttachConsole failed: {ctypes.get_last_error()}")
        return 1
    kernel32.SetConsoleCtrlHandler(None, True)  # this helper ignores the Ctrl+C that it raises
    if not kernel32.GenerateConsoleCtrlEvent(0, 0):  # CTRL_C_EVENT, every process on that console
        print(f"GenerateConsoleCtrlEvent failed: {ctypes.get_last_error()}")
        return 1
    time.sleep(0.5)
    kernel32.FreeConsole()
    return 0


def ctrlc(root):
    for label, tree, config in (("small tree", "small", "test_interrupt_small_config.toml"),
                                ("large tree", "big", "test_interrupt_big_config.toml")):
        tree = os.path.join(root, tree)
        log = fresh_log(root, "ctrlc")
        known = ledgers()
        startup = subprocess.STARTUPINFO()
        startup.dwFlags = subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow = 0  # hidden console, shared by Sandy and the sandboxed child
        # A parent that ignores Ctrl+C gives that state to its children.  Sandy must start with
        # Ctrl+C enabled, as it does from an interactive prompt.
        kernel32.SetConsoleCtrlHandler(None, False)
        proc = subprocess.Popen([SANDY, "-c", os.path.join(CONFIG_DIR, config), "-q", "-l", log, "-x",
                                 sys.executable, "-c", "import time; time.sleep(120)"],
                                creationflags=subprocess.CREATE_NEW_CONSOLE, startupinfo=startup)
        if not wait_for(log, "CHILD: resumed"):
            proc.kill()
            proc.wait()
            cleanup()
            test(f"{label}: sandboxed child started", False)
            continue
        time.sleep(1.0)
        sent, detail = send_ctrl_c(proc.pid)
        test(f"{label}: Ctrl+C raised on Sandy's console", sent, detail)
        try:
            code = proc.wait(60)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            code = None
        test(f"{label}: Sandy ended by itself after Ctrl+C", code is not None)
        test(f"{label}: exit code is STATUS_CONTROL_C_EXIT (0xC000013A)",
             code is not None and (code & 0xFFFFFFFF) == STATUS_CONTROL_C_EXIT,
             f"exit code {code if code is None else hex(code & 0xFFFFFFFF)}")
        sid = run_sid(log)
        left, _ = count_sid(tree, sid)
        test(f"{label}: no ACE of the run left, without --cleanup", left == 0, f"{left} objects hold {sid}")
        test(f"{label}: no ledger of the run left, without --cleanup", not (ledgers() - known))
        test(f"{label}: desktop access of the run revoked", sid not in desktop_sids())
        task = subprocess.run(["schtasks", "/Query", "/TN", f"SandyCleanup_{instance_id(log)}"], capture_output=True)
        test(f"{label}: cleanup task of the run deleted", task.returncode != 0)
        cleanup()


def desktop(root):
    config = os.path.join(CONFIG_DIR, "test_interrupt_small_config.toml")
    before = desktop_sids()
    killed = []
    for i in range(3):
        log = fresh_log(root, f"desk{i}")
        proc = subprocess.Popen([SANDY, "-c", config, "-q", "-l", log, "-x",
                                 sys.executable, "-c", "import time; time.sleep(60)"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        started = wait_for(log, "CHILD: resumed")
        proc.kill()  # TerminateProcess on the exact PID of the process started above
        proc.wait()
        if started and run_sid(log):
            killed.append(run_sid(log))
    test("three restricted-token runs started and were ended", len(set(killed)) == 3, f"{len(killed)} runs")
    if len(set(killed)) != 3:
        cleanup()
        return
    time.sleep(1)
    leaked = desktop_sids() & set(killed)
    test("the last ended run left its ACE on the window station / desktop (the state to repair)",
         killed[-1] in leaked)
    test("the start of the next run repaired the desktop ACEs of the earlier ended runs",
         leaked <= {killed[-1]}, f"{len(leaked)} of 3 SIDs present")
    cleanup()
    after = desktop_sids()
    test("--cleanup removed the desktop ACEs of the ended runs", not (after & set(killed)),
         f"{len(after & set(killed))} SID(s) left")
    test("--cleanup did not touch other desktop ACEs", before - set(killed) <= after)


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "_sendctrlc":
        sys.exit(_sendctrlc(int(sys.argv[2])))
    if mode == "build":
        sys.exit(build(sys.argv[2]))
    {"killgrant": killgrant, "ctrlc": ctrlc, "desktop": desktop}[mode](sys.argv[2])
    print(f"\n  {mode.upper()}: {pass_count} pass, {fail_count} fail")
    sys.exit(1 if fail_count else 0)
