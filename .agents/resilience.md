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
- numbered grant records for cleanup / rollback

`HKCU\Software\Sandy\Profiles\<name>` is durable profile state. It stores:
- saved config
- durable identity metadata (`_sid`, `_container`)
- staging markers during creation / rollback
- durable grant inventory for delete-profile and crash rollback

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
- stale grant ledgers
- stale cleanup tasks

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
removes ACEs by owning SID only, so one instance's cleanup **cannot** interfere
with another's — no cross-instance coordination is needed.

This means:
- No need to query other instances' deny paths before cleanup
- No need to defer cleanup because another instance has a child deny
- No need to mark records as DEFERRED or retry later

Grants and cleanup use `SetNamedSecurityInfoW` (not `TreeSet`). Windows
auto-inheritance propagation naturally handles multi-level grant structures.

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
- root-process exit while descendants still exist

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
- record grants only after the ACL change succeeded
- preserve retry metadata when cleanup was partial or ambiguous


- treat persistence failures as setup failures when they would otherwise leave untracked durable state behind

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
