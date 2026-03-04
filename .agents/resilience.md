# Sandy Resilience — Findings & Lessons Learned

This document captures hard-won insights from developing and testing Sandy's resilience mechanisms.
It serves as a reference for future debugging, auditing, and extending the system.

---

## Architecture Overview

Sandy persists grants in `HKCU\Software\Sandy\Grants\<UUID>` with per-instance subkeys containing:
- `_pid` (DWORD): the sandy.exe process ID
- `_ctime` (QWORD): process creation time (FILETIME)
- `_container` (REG_SZ): AppContainer profile moniker
- Numbered values: `access|path|original_sddl` for each granted folder

On clean exit, the instance deletes its own subkey and restores folder ACLs.
On crash/kill, the subkey persists as a stale entry for `--cleanup` to handle.

---

## Critical Bug: Zombie Process Detection

### Problem
`IsProcessAlive(pid, ctime)` used `OpenProcess` + creation time comparison to decide if a stored PID is alive. After `TerminateProcess` (e.g., `taskkill /f`), the process object remains in kernel memory until all handles are closed. During this zombie state:
- `OpenProcess` succeeds
- `GetProcessTimes` returns the **original** creation time
- `IsProcessAlive` returns `true` for a dead process

This caused `--cleanup` to classify killed instances as ALIVE, skipping their stale entries entirely.

### Fix
Added `WaitForSingleObject(h, 0)` check after `OpenProcess`. A signaled process handle means the process has terminated, regardless of whether handles remain open:

```cpp
HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
if (!h) return false;

// Signaled = terminated (zombie awaiting handle cleanup)
if (WaitForSingleObject(h, 0) != WAIT_TIMEOUT) {
    CloseHandle(h);
    return false;
}
```

### Lesson
Never trust `OpenProcess` success alone to determine liveness. Process objects outlive their execution. Always check the signaled state.

---

## Kill Scenarios Tested

| Scenario | What it tests | Key risk |
|---|---|---|
| Kill during active run | Grants persist in registry | ACL left modified |
| Kill with overlapping instance | Surviving instance retains access | Killed instance's cleanup wipes shared ACEs |
| Kill then restart same folder | New instance coexists with stale state | Stale entries interfere with new grants |
| Rapid-fire 3 kills | Multiple stale entries accumulate | `--cleanup` fails to handle all of them |
| Kill BOTH overlapping instances | Double-kill recovery | ACLs for shared folders not fully restored |
| Clean instance with stale state | Normal operation alongside stale entries | Warning emitted, no corruption |

---

## Cleanup Chain

`--cleanup` calls in this order:
1. `ForceDisableLoopback()` — removes loopback exemptions
2. `RestoreStaleGrants()` — enumerates grant subkeys, detects dead PIDs, restores original DACLs, deletes stale AppContainer profiles, removes subkeys
3. `RestoreStaleWER()` — removes stale WER exception keys
4. `DeleteCleanupTask()` — removes scheduled task only if no grant subkeys remain
5. `EnumSandyProfiles()` — deletes orphaned AppContainer profiles from Windows Mappings

### Key design constraint
`DeleteCleanupTask` checks for remaining grant subkeys before deleting the scheduled task. If `RestoreStaleGrants` fails to clean even one subkey, the scheduled task persists — this is intentional as a safety net.

---

## Concurrent Instance Safety

- Each instance writes to its own UUID-keyed subkey (no shared state mutation)
- ACL restoration skips paths still needed by other live instances (`livePaths` set)
- `RegDeleteTreeW` used instead of `RegDeleteKeyW` for robustness with unexpected subkeys
- Grant persistence uses `KEY_READ | KEY_WRITE` with deny ACE for Restricted SID (`S-1-5-12`) to prevent sandboxed child from tampering

---

## POSIX CLI Conventions

- Isolated flags (`--status`, `--cleanup`, `--print-*`, `-v`, `-h`) must appear alone
- Informational output → stdout (pipeable, redirectable)
- Errors/warnings → stderr
- Exit code 0 = success, 1 = error

---

## Test Infrastructure

| File | Purpose |
|---|---|
| `test_kill_resilience.bat` | 6-scenario kill battery (no mid-test manual cleanup) |
| `test_resilience.bat` | Basic resilience: cleanup, stale detection, idempotency |
| `test_stress.bat` | Multi-instance stress with overlapping grants |
| `test_concurrent.bat` | Concurrent read/write instance isolation |
| `kill_probe.py` | Child process: signals readiness, heartbeats, writes result on clean exit only |
| `kill_config.toml` | Grants ALL access to test_kill_A and test_kill_B folders |

### Test philosophy
Only ONE manual `reg delete` at the very start for pristine baseline. After that, Sandy's `--cleanup` is the ONLY mechanism for recovery. Stale state carries forward between scenarios. If Sandy can't clean itself, that's a real bug.
