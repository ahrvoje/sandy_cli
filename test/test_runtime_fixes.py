"""Runtime behaviour probe.  Runs INSIDE the sandbox.  One mode per check; each prints one
result line that the batch script looks for.

  spawn <marker> <seconds>   start a descendant that writes <marker> after <seconds>; the root exits at once
  desktop                    can this process see and use the windows of other processes?
  loghandle <log name>       did this process inherit a handle to Sandy's session log?
  child                      can this process start a child process and read its output?
"""
import ctypes, os, subprocess, sys
from ctypes import wintypes

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


def spawn(marker, seconds):
    code = f"import time; time.sleep({int(seconds)}); open(r'{marker}', 'w').write('alive')"
    subprocess.Popen([sys.executable, "-c", code])
    print("SPAWN: root exits, descendant keeps running", flush=True)


def desktop():
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.FindWindowW.restype = wintypes.HWND
    user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
    user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    # A handle value can still be found under the job UI limits; what counts is that it cannot be used.
    taskbar = user32.FindWindowW("Shell_TrayWnd", None)
    if not taskbar:
        reach = "ABSENT"
    elif user32.PostMessageW(taskbar, 0, 0, 0):  # WM_NULL: no effect on the receiver
        reach = "REACHABLE"
    else:
        reach = f"BLOCKED (error {ctypes.get_last_error()})"
    count = [0]

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def each(_hwnd, _lparam):
        count[0] += 1
        return True

    user32.EnumWindows(each, 0)
    print(f"TASKBAR: {reach}")
    print(f"WINDOWS: {count[0]}")


def loghandle(log_name):
    """Look at every file handle of this process.  None may point at the session log."""
    kernel32.GetFileType.argtypes = [wintypes.HANDLE]
    kernel32.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    kernel32.WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_char_p, wintypes.DWORD,
                                   ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    buffer = ctypes.create_unicode_buffer(1024)
    for handle in range(4, 8192, 4):
        if kernel32.GetFileType(handle) != 1:  # FILE_TYPE_DISK
            continue
        if not kernel32.GetFinalPathNameByHandleW(handle, buffer, 1024, 0):
            continue
        if buffer.value.lower().endswith(log_name.lower()):
            written = wintypes.DWORD(0)
            text = b"\r\nFORGED-BY-CHILD\r\n"
            ok = kernel32.WriteFile(handle, text, len(text), ctypes.byref(written), None)
            print(f"LOGHANDLE: INHERITED (handle {handle}, write {'worked' if ok else 'failed'})")
            return
    print("LOGHANDLE: NONE")


def child():
    try:
        result = subprocess.run([sys.executable, "-c", "print(6 * 7)"], capture_output=True, text=True, timeout=30)
        print(f"CHILD: {result.stdout.strip() or 'NO-OUTPUT'} (exit {result.returncode})")
    except OSError as error:
        print(f"CHILD: FAILED ({error})")


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "spawn":
        spawn(sys.argv[2], sys.argv[3])
    elif mode == "desktop":
        desktop()
    elif mode == "loghandle":
        loghandle(sys.argv[2])
    elif mode == "child":
        child()
