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
| PATH | Non-empty, must be absolute (drive letter, UNC, `HKEY`, `CURRENT_USER\`, or `MACHINE\`), no embedded `\|` |
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
1. `ForceDisableLoopback()` — removes loopback exemptions (skips live and saved-profile containers)
2. `RestoreStaleGrants()` — enumerates grant subkeys, detects dead PIDs, removes stale ACEs via `RemoveSidFromDacl()`, deletes stale AppContainer profiles (**skips** profile-mode entries and saved-profile containers via `_profile_mode` flag + `GetSavedProfileContainerNames()`), removes subkeys. Deferred grants (tree-skip due to child-deny conflict) keep their registry state for later cleanup.
3. `CleanStagingProfiles()` — scans `Profiles\*` for keys with `_staging=1` (crash mid-create-profile), revokes their ACLs, deletes AC profiles, and removes the incomplete registry key
4. `RestoreStaleWER()` — removes stale WER exception keys (ref-counted: only deletes HKLM key when last owner)
5. `DeleteStaleCleanupTasks()` — finds and deletes scheduled tasks for dead instances

### Per-Instance Cleanup Tasks
Each instance (including profile-mode runs) creates its own scheduled task: `SandyCleanup_<uuid>`. On clean exit, the instance deletes its task via `DeleteCleanupTask()`. Stale tasks from crashed instances are cleaned by `DeleteStaleCleanupTasks()`, which enumerates all `SandyCleanup_*` tasks and deletes those whose PIDs are no longer alive.

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

### Saved-Profile Protection
Containers created by `--create-profile` are permanent. Cleanup (both `--cleanup` and startup `CleanupStaleStartupState`) excludes them by checking `GetSavedProfileContainerNames()` which reads `_container` values from `Software\Sandy\Profiles\*`. These containers are never deleted by stale cleanup — only by explicit `--delete-profile`.

### WER Reference Counting
The `HKLM\...\LocalDumps\<exeName>` key is globally shared. When multiple Sandy instances monitor the same executable:
- `CountLiveWERReferences(exeName)` counts how many live PIDs track the same exe name
- On exit, a Sandy instance clears its own `HKCU\Sandy\WER\<PID>` entry first, then only deletes the HKLM key if no other live instances remain
- `RestoreStaleWER()` applies the same ref-counting logic for stale entries
- `CleanupStaleStartupState()` applies the same ref-counting logic (never calls `DisableCrashDumps` while live owners exist)
- All early-return paths in `RunPipeline()` (stdin failure, launch failure, job failure) call `ClearWERExeName()` + ref-counted `DisableCrashDumps()` if crash dumps were enabled
- **Crash-safe ordering:** `SetupCrashDumps()` writes the HKCU ownership record (`PersistWERExeName`) **before** creating the HKLM `LocalDumps` key (`EnableCrashDumps`). If power is lost between the two, cleanup sees a dangling HKCU entry and harmlessly removes it. If HKLM setup fails, the HKCU entry is cleared immediately.

### Profile-Mode Live-State
Profile-mode runs (`-p`) now create a lightweight live-state record under `Grants\<instanceId>` containing only `_pid`, `_ctime`, `_container`, and `_profile_mode=1` (no grant values). This allows `GetLiveContainerNames()` to detect live profile-mode runs. On clean exit, `ClearLiveState()` deletes the record. Profile-mode runs also create per-instance cleanup tasks for crash recovery. Early-return failures in `RunWithProfile()` (SID reconstruction, token creation) now call `DeleteCleanupTask()` to prevent leaked tasks.

### Create-Profile Transaction Safety
`HandleCreateProfile()` uses a staging-marker protocol:
1. Creates the `Profiles\<name>` registry key
2. Writes `_staging=1` marker + SID/container for crash recovery
3. Applies filesystem ACL grants
4. Commits remaining metadata and grant records to the open key
5. Removes the `_staging` marker (`RegDeleteValueW`)

If Sandy crashes during steps 2–4, the `_staging=1` marker survives. `CleanStagingProfiles()` (called by `--cleanup`) detects this, revokes applied ACLs via `RestoreGrantsFromKey()`, deletes the AppContainer profile if present, and removes the incomplete registry key.

---

## Round 4 Fixes (2026-03-13)

### Emergency Cleanup — Child Termination First
`CleanupSandbox()` (Ctrl+C / SEH path) now terminates the child process via `TerminateProcess` + `WaitForSingleObject(5s)` **before** revoking any grants or deleting the AppContainer. A global `g_childProcess` handle (set after successful launch, cleared in Phase 5) provides the child reference. If the child does not terminate within 5s, cleanup is deferred to stale-state recovery on next run.

### Same-Path Allow Rules — Additive ACE Masks
`GrantObjectAccess()` now uses `GRANT_ACCESS` instead of `SET_ACCESS`. This makes multiple allows on the same path additive (OR'd permission masks) rather than last-write-wins. Critical for configs that grant both `read` and `execute` on the same path.

### Procmon Session Ownership
`LaunchProcmon()` checks `IsProcmonRunning()` before starting a new instance. If Procmon is already running, audit/trace mode refuses to proceed (preventing disruption of unrelated debugging sessions). The old unconditional `/Terminate` is removed.

### Procmon Filter Backup/Restore
`BackupProcmonFilter()` snapshots `HKCU\Sysinternals\Process Monitor\FilterRules` before trace mode overwrites it. `RestoreProcmonFilter()` restores the original value (or deletes the value if none existed) on all exit paths from `RunTrace()`.

### Stale Cleanup — Path+SID Precision
`RestoreStaleGrants()` now uses `path|SID` compound keys for skip-protection instead of path-only keys. When two instances share a path but use different SIDs, the dead instance's ACEs are cleaned while the live instance's are preserved.

---

## Round 5 Fixes (2026-03-13)

### WER Crash-Safe Ownership Ordering
`SetupCrashDumps()` now writes the HKCU ownership record **before** creating the HKLM `LocalDumps` key, and clears the HKCU record if HKLM setup fails. This eliminates orphaned WER policy after power loss between the two writes.

### Descendant ACE Deferral
`RevokeAllGrants()` no longer clears registry state when tree-set cleanup is skipped due to a conflicting child deny from another instance. Instead, the grant record is kept in the stale-recovery ledger (`ClearPersistedGrants` is skipped when deferred > 0). `RestoreStaleGrants` will finish the cleanup when the conflicting deny is gone.

### Saved-Profile Staging Marker
`HandleCreateProfile()` sets `_staging=1` before ACL application and removes it after successful commit. `CleanStagingProfiles()` (called by `--cleanup`) detects and rolls back incomplete profiles.

### Procmon Filter Restoration
`RunTrace()` now calls `RestoreProcmonFilter()` when the target process fails to launch, preventing filter state leaks on this previously-missing exit path.

### PID-Specific Crash Dump Matching
`ReportCrashDump()` accepts an optional `childPid` parameter and prefers dump files matching `<exeName>.<PID>.dmp` over newest-file fallback. This prevents misattribution in concurrent same-exe runs.

### Dynamic Reload — Granular Same-Path Revoke
`DynamicWatcherThread` Phase 1 (revoke) now re-applies surviving same-path allows from the new config after revoking a removed allow entry. This prevents over-revocation when two allow rules share a path and only one is removed.

---

## Round 6 Fixes (2026-03-13)

### Crash-Safe Staging Grants
`HandleCreateProfile()` now writes grant records **incrementally** to the staging profile key during `ApplyAccessPipeline()` (via `g_stagingProfileKey`). Previously, grant records were batch-copied from the in-memory list after all grants succeeded — if Sandy crashed mid-pipeline, the staging profile had no grant records for `CleanStagingProfiles()` to roll back.

### Live Profile Deletion Guard
`HandleDeleteProfile()` now checks `GetLiveContainerNames()` before deletion. If any running Sandy instance (`-p` mode) uses the target profile's container, deletion is refused with a descriptive error.

### Post-Success Grant Recording
`GrantObjectAccess()` and `DenyObjectAccess()` now call `RecordGrant` **after** the DACL application succeeds, not before. Previously, a failed `SetNamedSecurityInfoW` or `TreeSetNamedSecurityInfoW` would leave phantom grant records in memory and registry, causing stale-recovery to attempt removal of ACEs that were never applied.

### Stdin Sentinel ("INHERIT")
`WriteConfigToRegistry()` stores `"INHERIT"` (instead of empty string) when `stdinMode` is empty (meaning "inherit parent stdin"). `ReadConfigFromRegistry()` decodes `"INHERIT"` back to empty, and treats truly-empty registry values as "unspecified" (→ `NUL` default). This prevents saved profiles from silently losing inherited stdin.

### Deny Cleanup Inheritance Restoration
`RemoveSidFromDacl()` in the `skipTreeSet=true` path (peek cleanup) now passes `siFlags` to `SetKernelObjectSecurity()` instead of hard-coded `DACL_SECURITY_INFORMATION`. When `wasDenied=true`, `siFlags` includes `UNPROTECTED_DACL_SECURITY_INFORMATION`, which re-enables host inheritance after deny ACE removal.

### Startup Staging Recovery
`CleanStagingProfiles()` is now called during normal startup in both `RunSandboxed()` and `RunWithProfile()`, not just by `--cleanup`. Incomplete staging profiles from crashes are auto-recovered without requiring manual `--cleanup`.

---

## Round 9 Fixes (2026-03-13)

### Registry Grants for Restricted Profiles
`HandleCreateProfile()` now calls `GrantRegistryAccess()` for restricted profiles. Previously, only `ApplyAccessPipeline()` (filesystem ACLs) was applied — registry `read`/`write` entries were serialized but never materialized on the host, causing profile-mode runs to silently lack configured registry access.

### Stale-Grant Metadata Preservation
`RestoreStaleGrants()` now honors the `RestoreGrantsFromKey()` return value. When ACL rollback is incomplete (path still exists but ACEs could not be removed), the stale grants subkey is preserved for retry instead of being unconditionally deleted. This matches the contract already used by `CleanStagingProfiles()` and `HandleDeleteProfile()`.

### Automatic Deferred Cleanup Retry
`RestoreStaleGrants()` is now called during normal startup in both `RunSandboxed()` and `RunWithProfile()`. Previously, deferred overlap cleanup (tree-skip due to child-deny conflict) would only be retried via manual `--cleanup` or emergency paths. Now any subsequent Sandy launch automatically retries deferred stale cleanup.

### Dynamic Reload Failure-Aware State
`DynamicWatcherThread` now only updates its tracked state (`currentKeys`, `currentRegKeys`, config) when all grant/revoke operations in a reload succeed. If any operation fails, the previous baseline is retained so failed changes remain pending for the next reload cycle. Since grant operations are idempotent (`GRANT_ACCESS` is additive, `RemoveSidFromDacl` is a no-op when SID is absent), re-applying successful changes is harmless.

### Procmon Startup Leak Prevention
`LaunchProcmon()` now terminates any Procmon instance it started if capture readiness (`WaitForFile`) fails. Previously, a Procmon session could be left running in the background after a startup failure, blocking subsequent audit/trace runs.

### Profile Creation Transaction Safety
`HandleCreateProfile()` now fails with `SetupError` when `ApplyAccessPipeline()` or `GrantRegistryAccess()` returns failure. The staging marker (`_staging=1`) is preserved so `CleanStagingProfiles()` can roll back partial grants on next startup. Previously, a partial profile was committed as canonical with only a warning.

## Round 10 Fixes (2026-03-13)

### Registry Grant Record Round-Trip
`ParseGrantRecord()` now accepts Win32 registry object paths (`CURRENT_USER\...`, `MACHINE\...`) in addition to `HKEY` prefixes. Previously, `GrantRegistryAccess()` persisted paths via `RegistryToWin32Path()` (which converts `HKCU\` → `CURRENT_USER\`), but the parser rejected those paths as non-absolute — making persisted registry grants unparseable during crash recovery, staging rollback, and profile deletion.

### Profile Creation Self-Rollback
`HandleCreateProfile()` now immediately rolls back already-applied ACLs when grant application fails, instead of deferring to a future `CleanStagingProfiles()` pass. The staging key and AppContainer profile (if created) are deleted before returning the error, so no partial persistent state is left behind.

### Fail-Closed Audit Mode
`SetupAudit()` now returns `false` when Procmon is missing or capture startup fails. `RunPipeline()` aborts with `SetupError` instead of silently continuing without the requested audit capture.

### Symmetric Registry Cleanup Failure Detection
`RestoreGrantsFromKey()` now checks whether registry keys still exist when `RemoveSidFromDacl()` returns 0 ACEs removed — the same failure-detection contract previously applied only to file paths. This prevents cleanup from silently discarding retry metadata for failed registry ACL removals.

### Fail-Closed Dynamic Watcher
`RunPipeline()` now checks `CreateEventW()` and `CreateThread()` results for the dynamic config watcher. If either fails, the child process is terminated and the run aborts with `SetupError` and a clear error message, instead of silently running without live-reload capability.

## Round 11 Fixes (2026-03-13)

### Create-Profile Rollback Metadata Preservation
`HandleCreateProfile()` now checks `RestoreGrantsFromKey()` return value during self-rollback. If ACL revert was incomplete, the staging key (with `_staging=1` marker) is preserved for `CleanStagingProfiles()` or `--cleanup` to retry later, instead of being unconditionally deleted.

### Deferred Overlap Cleanup Reason Persistence
`RevokeAllGrants()` now persists a `DEFERRED:1` flag on registry grant records when tree-set cleanup is skipped due to live child deny from another instance. `RestoreGrantsFromKey()` re-checks the child-deny overlap condition (via `GetOtherInstanceDenyPaths()`) before allowing recursive cleanup on deferred records. If the condition is still present, metadata is preserved for the next retry instead of escalating to full recursive cleanup.

### Centralized Post-Setup Abort Teardown
`TeardownAuditAndDumps()` is a new helper that stops Procmon capture and cleans WER state. All 7 post-feature-setup abort paths (stdin, token validation, launch, job, watchdog, dynamic event, dynamic thread failures) now call this single routine instead of hand-coding partial WER-only cleanup. Previously, none of these abort paths terminated Procmon.

### Procmon Discovery Path Safety
`FindProcmon()` no longer uses `SearchPathW(nullptr, ...)` which consults the current directory and full PATH (search-order hijacking risk). It now builds an explicit search path (System32 + known Sysinternals locations + PATH) and validates results are absolute paths before returning.

### Profile-Mode Live-State Key Hardening
`PersistLiveState()` now calls `HardenRegistryKeyAgainstRestricted()` (extracted from `RecordGrant()`) to deny Restricted SID (`S-1-5-12`) write access on the live-state registry key. This matches the protection already applied to normal live grant keys, preventing restricted-token sandboxed children from tampering with liveness metadata.

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
