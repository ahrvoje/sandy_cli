# Sandy Resilience — Findings & Lessons Learned

This document captures hard-won insights from developing and testing Sandy's resilience mechanisms.
It serves as a reference for future debugging, auditing, and extending the system.

---

## Architecture Overview

Sandy persists grants in `HKCU\Software\Sandy\Grants\<UUID>` with per-instance subkeys containing:
- `_pid` (DWORD): the sandy.exe process ID
- `_ctime` (QWORD): process creation time (FILETIME)
- `_container` (REG_SZ): AppContainer profile moniker
- `_nextIdx` (DWORD): next grant index counter
- Numbered values: `TYPE|PATH|SID[|DENY:1][|TRAPPED:sid1;sid2]` for each granted/denied path

On clean exit, the instance removes its own ACEs via `RemoveSidFromDacl()`, deletes its subkey, and removes its per-instance scheduled task.
On crash/kill, the subkey persists as a stale entry for `--cleanup` to handle.

---

## Grant Record Parsing — Validation Rigor

`ParseGrantRecord()` (`SandboxGrants.h`) parses persisted registry values with strict validation:

| Field | Validation |
|-------|------------|
| TYPE | Must be `FILE` or `REG` |
| PATH | Non-empty, must be absolute (drive letter, UNC, or `HKEY`), no embedded `\|` |
| SID | Must match `S-<digit>-<digit>-...` via `ValidateSidPrefix()` |
| TRAPPED SIDs | Each semicolon-separated SID validated individually |
| Flags | Only `DENY:1` and `TRAPPED:` recognized; unknown flags reject the record |
| Trailing data | Any content after known flags rejects the record |

- Returns `false` + sets a diagnostic `reason` string (e.g. `"SID does not match S-<rev>-<auth> format"`)
- Caller logs rejection with the specific reason: `GRANT_PARSE: malformed record (reason), skipping: data`
- **Never** silently accept malformed records — all rejections are logged

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
2. `RestoreStaleGrants()` — enumerates grant subkeys, detects dead PIDs, removes stale ACEs via `RemoveSidFromDacl()`, deletes stale AppContainer profiles, removes subkeys
3. `RestoreStaleWER()` — removes stale WER exception keys
4. `DeleteStaleCleanupTasks()` — finds and deletes scheduled tasks for dead instances

### Per-Instance Cleanup Tasks
Each instance creates its own scheduled task: `SandyCleanup_<uuid>`. On clean exit, the instance deletes its task via `DeleteCleanupTask()`. Stale tasks from crashed instances are cleaned by `DeleteStaleCleanupTasks()`, which enumerates all `SandyCleanup_*` tasks and deletes those whose PIDs are no longer alive.

### Key design constraint
`RestoreStaleGrants` skips paths used by other live instances (the `livePaths` set). If any live instance still needs a path, its ACEs are preserved.

### Parent Registry Key Policy
Parent registry keys (`Software\Sandy`, `Grants`, `Profiles`, `WER`) are **permanent** — they are
never deleted, even when empty. `--cleanup` removes only:
- Individual instance subkeys under `Grants\<UUID>`
- Individual PID values under `WER`
- The entire `Software\Sandy\Test` subtree (test-only)

**`--cleanup` MUST NEVER delete:**
- `HKCU\Software\Sandy`
- `HKCU\Software\Sandy\Grants`
- `HKCU\Software\Sandy\Profiles`
- `HKCU\Software\Sandy\WER`

**Test validation:** Tests checking for stale grants must count **subkeys only** using
`findstr /c:"Grants\\"` — not `findstr /c:"HKEY_"` which also matches the parent key header.
An empty parent key with zero subkeys is the expected clean state.
---

## Logger Diagnostics

`SandyLogger::LogFmt()` formats messages using a stack buffer (1024 chars) for common
cases and dynamically-allocated heap buffer for larger messages. Truncation counter
and `LOG_DIAG` summary emitted at session close via `Stop()`.

**Never** revert to fixed-size-only formatting — large paths and SIDs can exceed 1024 chars.

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
- Exit codes (POSIX high-code convention, defined in `SandyExit` namespace in `SandboxTypes.h`):

| Code | Meaning |
|:----:|---------|
| 0 | Success (child exited 0, or info command succeeded) |
| 1-124 | Child exit code (passed through unchanged) |
| 125 | Sandy internal / general error |
| 126 | Cannot execute (CreateProcess failed) |
| 127 | Command not found (exe doesn't exist) |
| 128 | Configuration error (invalid TOML, file not found) |
| 129 | Sandbox setup failed (token, SID, ACL, pipes) |
| 130 | Timeout (child killed by watchdog) |
| 131 | Child crashed (NTSTATUS crash code) |

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
