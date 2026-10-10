# Sandy Resilience — Current Rules and Failure Model

This document captures the current resilience model for Sandy after the removal
of Procmon-based audit/trace and the move to a profile-first ownership design.
It should guide future work on crash recovery, stale cleanup, and power-loss safety.

---

## Core Ownership Model

Sandy has two durable concepts:

| Scope | Registry roots / artifacts | Owner |
|---|---|---|
| **Profile** | `HKCU\Software\Sandy\Profiles\<name>` plus durable AppContainer / durable ACLs | Persistent sandbox identity |
| **Run** | `HKCU\Software\Sandy\Grants\<instanceId>`, cleanup task, live-state | One execution session |

Key rule: **cleanup must operate on the owner's state, not on whichever code path noticed the problem.**

Transient runs own both identity and run metadata. Profile-backed runs own only
run metadata; the profile continues to own the durable identity.

---

## Registry and Recovery Ledgers

`HKCU\Software\Sandy\Grants\<instanceId>` is the run recovery ledger. It stores:
- `_pid`
- `_ctime`
- `_container`
- `_profile_mode` for profile-backed runs
- `_desktop_sid` when the run granted its SID access to the window station / desktop
- numbered grant records for cleanup / rollback:
  `TYPE|PATH|SID[|DENY:1][|THIS:1][|OWNER:I|OWNER:O]`

A grant record is written **before** its DACL change (write-ahead). At every
instruction boundary the ledger names every ACE that can exist.

`HKCU\Software\Sandy\Profiles\<name>` is durable profile state. It stores:
- saved config
- durable identity metadata (`_sid`, `_container`)
- staging markers during creation / rollback
- durable grant inventory for delete-profile and crash rollback

Saved capability configuration uses `_capability_count`, indexed
`_capability_<i>` names, and `_allow_loopback`. Missing or invalid metadata
must fail profile loading rather than silently omit access settings. There is no
legacy migration; old profiles must be recreated for execution. Profile teardown
must remain usable without loading their saved configuration.

Capability SIDs exist only in the child token and Sandy's temporary allocations.
They require no host ACL rollback. Loopback exemptions are separate host state:
transient runs own their exemptions; saved profiles own durable exemptions.
Keep the existing container-based recovery and deletion paths for both.

**Parent registry keys are permanent.** Cleanup removes subkeys and values, not the parent roots.

---

## Liveness Detection

PID existence is not enough. A killed process can remain as a zombie kernel object
while handles are still open.

When checking whether a recorded Sandy instance is alive:
1. open the process
2. compare creation time
3. require `WaitForSingleObject(handle, 0) == WAIT_TIMEOUT`

If any of those fail, treat the instance as dead for stale recovery.

---

## Startup Recovery and Manual Cleanup

Both normal startup and `--cleanup` must cover the same failure classes:
- incomplete staging profiles
- stale grant ledgers (file, registry and desktop ACEs)
- stale cleanup tasks

Recovery output of a normal run goes to the session log, not to the console
(`RecoveryPrintf`): from `BeginRunSession` on, stdout belongs to the child.
`--cleanup` prints the same messages on the console.

The exact ordering may differ for implementation reasons, but the design intent is:
1. repair interrupted durable transactions
2. retry deferred stale cleanup
3. clear stale host-global best-effort state

A product that only heals itself when the user discovers `--cleanup` is not resilient enough.

---

## Durable-Change Transaction Rules

Any change that outlives the current process must follow these rules:

1. **Record intent before mutating host state** when the host mutation is harder to discover later.
2. **Do not drop rollback metadata until rollback actually succeeds.**
3. **Fail closed** if Sandy cannot persist the recovery metadata needed to undo what it just changed.
4. **Make rollback retryable** after crash, kill, or power loss.

This applies to:
- durable ACL grants
- saved-profile creation and deletion
- AppContainer profile lifecycle
- live-state coordination metadata when other paths depend on it for safety

---

## Overlapping ACL Cleanup

Both AppContainer and Restricted Token SIDs are unique per instance. Cleanup
removes ACEs by owning SID only, so one instance's cleanup **cannot remove**
another's ACEs.  However, individual ACE removal uses `SetNamedSecurityInfoW`
which triggers Windows auto-inheritance propagation on directories.  When two
instances clean up concurrently on overlapping paths, the interleaved
propagation can re-stamp ACEs that the other instance just removed.

**Solution:** `RevokeAllGrants()` and `RestoreGrantsFromKey()` acquire the
global named mutex (`Local\Sandy_ACL`) for the entire cleanup sequence, not
just per-operation.  Windows named mutexes are recursive, so the inner
per-path `RemoveSidFromDaclDetailed` calls re-acquire without deadlock.
This ensures one instance's full cleanup completes before another starts.

This means:
- No need to query other instances' deny paths before cleanup
- No need to defer cleanup because another instance has a child deny
- No need to mark records as DEFERRED or retry later

Grants and cleanup use `SetNamedSecurityInfoW` (not `TreeSet`). Windows
auto-inheritance propagation naturally handles multi-level grant structures.

Windows propagates to the descendants first and writes the rule's root last.
A kill in the middle of a grant leaves descendants with an inherited ACE and a
root without it; a kill in the middle of a revoke leaves the opposite. Stale
recovery covers both: it removes the SID from the root and, when the root
holds no ACE of the SID, rewrites the root's unchanged DACL to force a new
propagation (`ACL_REPROPAGATE`). A failed re-propagation is logged and does not
keep the ledger alive.

Profile-owned ACLs follow the same rule: their SID is unique to the profile,
so cleanup by that SID is always safe regardless of concurrent runs.

---

## Profile-First Safety Rules

Profiles are a first-class feature, not a bolt-on exception path.

This means:
- profile creation must be transaction-like
- profile runs must publish enough live metadata for safe delete / cleanup decisions
- profile deletion must refuse to run while any live run is still using that profile identity
- normal run cleanup must never dismantle profile-owned state

When a profile-backed run exits, only run-owned state should disappear.

---

## Power Loss and Violent Termination

Assume Sandy can die at any instruction boundary.

The design must tolerate:
- `taskkill /f`
- power loss
- machine restart
- Sandy crash after partially applying ACLs
- Sandy crash after creating a durable AppContainer but before commit completion
- root-process exit while descendants still exist (the run, its timeout
  watchdog and its cleanup all follow the job tree, not the root process)

For each durable mutation, ask:
- what exact metadata proves ownership?
- what exact metadata allows rollback?
- what happens if power dies after step N but before step N+1?
- can a later startup finish or safely retry the operation?

If the answer depends on the user running a special command or manually cleaning state, the design is not yet robust.

---

## Removed Host-Tool Surface

Procmon-backed audit/trace was removed because it introduced host-global state,
external tool orchestration, and repeated cleanup regressions unrelated to core sandboxing.

Do not reintroduce host tooling that:
- mutates unrelated user configuration
- owns host-global state Sandy cannot reliably namespace
- requires extra teardown branches across every launch-failure path

The current resilience focus is on grants, profiles, loopback, live-state,
and cleanup tasks.

---

## Cleanup Metadata Integrity

If applying or revoking an ACL fails, Sandy must not pretend the state is clean.

Rules:
- record a grant **before** the ACL change (write-ahead). A record without an
  ACE is harmless: cleanup finds nothing to remove. An ACE without a record is
  a permanent leak.
- if the record cannot be written, do not change the ACL (`ERROR_WRITE_FAULT`)
- preserve retry metadata when cleanup was partial or ambiguous
- treat persistence failures as setup failures when they would otherwise leave untracked durable state behind
- a test must never delete a ledger that it did not create: an ACE whose
  ledger is gone stays on the object forever

Incorrect bookkeeping is a resilience bug even if the immediate filesystem change looked harmless.

---

## Test Expectations for Resilience Work

Any change touching recovery or durable ownership should be reasoned about under:
- concurrent runs
- profile-backed runs plus transient runs
- overlapping filesystem trees
- interrupted create-profile / delete-profile
- stale cleanup after crash
- startup recovery after previous partial failure

If the change only works for the happy path, it is not finished.

---

## Console Handler Cleanup Strategy

Windows console close, logoff, and shutdown handlers are deadline-limited
(~5 seconds before the OS terminates the process). Sandy's full cleanup
(child termination wait + ACL revocation + loopback removal + container
teardown) can exceed this window.

Additionally, once `user32.dll` or `gdi32.dll` is loaded, Windows does
**not** call `SetConsoleCtrlHandler` for `CTRL_LOGOFF_EVENT` or
`CTRL_SHUTDOWN_EVENT`.  Sandy loads `user32` implicitly via desktop ACL
APIs (`GetProcessWindowStation`, `OpenDesktopW`) during restricted-token
runs.

| Signal | Cleanup | Rationale |
|--------|---------|-----------|
| `CTRL_C_EVENT` | Handler ends the child tree; the main thread runs the normal cleanup | No OS deadline |
| `CTRL_BREAK_EVENT` | Same as `CTRL_C_EVENT` | No OS deadline |
| `CTRL_CLOSE_EVENT` | Terminate child only | Deadline-limited; defer rest to recovery |
| `CTRL_LOGOFF_EVENT` | Log only | Handler may not fire; deadline applies if it does |
| `CTRL_SHUTDOWN_EVENT` | Log only | Same as logoff |

Stale-state recovery on the next Sandy invocation (`BeginRunSession`)
handles everything that was deferred: stale grants, orphaned containers,
leftover cleanup tasks, and incomplete staging profiles.

The per-instance ONLOGON cleanup task (`SandyCleanup_<uuid>`) is
**intentionally retained** for deadline-limited and unreliable signals.
It fires on next logon and runs `sandy.exe --cleanup`, ensuring deferred
state is cleaned even if the user never manually runs Sandy again.

**Do not** add full synchronous cleanup to deadline-limited signal paths.

### One cleanup owner

The handler thread never runs cleanup. For Ctrl+C / Ctrl+Break it sets
`g_shutdownRequested`, ends the child tree (`TerminateRunningChild`) and
returns `TRUE`. The main thread then leaves its wait, or stops the grant
pipeline between two paths (`ShutdownRequested()`), runs the one normal
cleanup path, and `wmain` returns `STATUS_CONTROL_C_EXIT` (0xC000013A).

If the handler returned `FALSE`, or ran cleanup itself, the default handler
would end the process while the main thread is in the middle of a revoke.
A second Ctrl+C is the user's way out: the handler then returns `FALSE` and
recovery finishes the work later.

---

## Cleanup Task

`SandyCleanup_<uuid>` is registered through the Task Scheduler API
(`ITaskService`) as a logon-trigger task for the current user. This needs no
elevation. `schtasks.exe /SC ONLOGON` needs an administrator, so a task made
that way does not exist for a normal user; Sandy does not start `schtasks.exe`.
