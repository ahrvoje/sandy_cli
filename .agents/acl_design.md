---
description: Critical ACL design facts to avoid regressions in Sandy sandbox
---

# Per-Instance Isolation — Unique SIDs

Every Sandy instance generates a UUID-based container name (`Sandy_<uuid>`).
`CreateAppContainerProfile` derives a unique SID from this name, so **every
concurrent Sandy process has its own AppContainer SID**. This means:

- ACL grants are per-instance — one instance's grants never leak to another.
- Cleanup is per-instance — revoking one instance's grants doesn't affect others.
- The registry tracks grants per instance under `HKCU\Software\Sandy\Grants\<uuid>`.

**Never** revert to a fixed container name (e.g. `SandySandbox`). A deterministic
name causes all instances to share one SID, making concurrent different-grant
scenarios impossible and causing stale ACE accumulation.

# Per-Instance Grants and Behavior

Each Sandy instance applies its own config independently. Three concurrent
instances can grant `read`, `write`, and `all` to the **same folder** and each
will enforce different permissions. This is verified by `test_concurrent.bat`.

During cleanup, each instance removes only **its own ACEs** using `RemoveSidFromDacl`,
which walks the DACL and removes ACEs matching the instance's SID. For shared SIDs
(Restricted Token mode), `GetOtherInstancePaths()` skips paths still needed by
other live instances.

# ACL Propagation — TreeSetNamedSecurityInfoW

Directory grants use `TreeSetNamedSecurityInfoW` (not `SetNamedSecurityInfoW`) to
synchronously propagate OICI ACEs to all child files. `SetNamedSecurityInfoW` does
NOT reliably propagate to existing children, causing `0xC0000022` failures in
large directory trees (e.g. Python's 36K files).

This applies to all three DACL modification paths in `SandboxACL.h`:
- `GrantObjectAccess` — grant (adds ACE)
- `DenyObjectAccess` — deny (adds/modifies ACE)
- `RemoveSidFromDacl` — cleanup (removes ACEs for a specific SID)

**Never** replace `TreeSetNamedSecurityInfoW` with `SetNamedSecurityInfoW` for
directories. File-only grants still use `SetNamedSecurityInfoW` (no children).

# Access Level Permissions — Read vs Execute

**`read` does NOT grant `FILE_EXECUTE`.** This is intentional and critical.

Any directory containing executables or DLLs that need to be **loaded** (Python,
Node, compilers) must use `execute`, not `read`, in the config:

```toml
[allow]
execute = ['C:\path\to\python']   # correct — OS loader needs FILE_EXECUTE
read    = ['C:\path\to\data']     # correct — data-only, no code loading
```

**Never** add `FILE_EXECUTE` to the Read mask to "fix" loading — that silently
escalates every read grant into execute permission, breaking the security model.

# Permission Flags by Access Level

| Level | Config key | Mask | Windows flags |
|-------|-----------|------|---------------|
| Read | `read` | `FILE_GENERIC_READ` | `FILE_READ_DATA`, `FILE_READ_EA`, `FILE_READ_ATTRIBUTES`, `READ_CONTROL`, `SYNCHRONIZE` |
| Write | `write` | `FILE_GENERIC_WRITE \| FILE_READ_ATTRIBUTES \| SYNCHRONIZE` | `FILE_WRITE_DATA`, `FILE_APPEND_DATA`, `FILE_WRITE_EA`, `FILE_WRITE_ATTRIBUTES`, `READ_CONTROL`, `SYNCHRONIZE`, `FILE_READ_ATTRIBUTES` |
| Execute | `execute` | `FILE_GENERIC_READ \| FILE_GENERIC_EXECUTE` | All Read flags + `FILE_EXECUTE` |
| Append | `append` | `FILE_APPEND_DATA \| FILE_READ_ATTRIBUTES \| SYNCHRONIZE` | Append-only, no read/overwrite |
| Delete | `delete` | `DELETE \| FILE_READ_ATTRIBUTES \| SYNCHRONIZE` | Delete only, no read/write |
| All | `all` | `FILE_ALL_ACCESS & ~(FILE_DELETE_CHILD \| WRITE_DAC \| WRITE_OWNER)` | Full data control, no ACL modification |

Key points:
- **Read** cannot load DLLs/EXEs (no `FILE_EXECUTE`)
- **Write** cannot list or read directory contents (no `FILE_READ_DATA`)
- **Execute** is the standard `(RX)` — minimum for running programs
- **Append** cannot overwrite existing data (no `FILE_WRITE_DATA`)
- **Delete** cannot read or write file contents

# DENY ACEs — Hybrid Approach (AppContainer vs Restricted)

**DENY ACEs (`DENY_ACCESS`) are silently ignored by the Windows kernel for
AppContainer SIDs.** A DENY ACE placed before an ALLOW ACE in the DACL has
no effect — AppContainer access checks bypass deny-before-allow evaluation.
Restricted Token mode honors DENY ACEs normally.

Sandy uses a **mode-aware hybrid** in `DenyObjectAccess()`:

### Restricted Token Mode
Uses real `DENY_ACCESS` ACEs with the denied permission mask. The kernel
evaluates DENY before ALLOW, so these work as expected.

### AppContainer Mode
DENY ACEs are useless. Instead, Sandy manually constructs a new DACL:
1. Reads the existing DACL from the deny target path
2. Enumerates all ACEs — copies non-SID ACEs to a new ACL
3. Skips ALL ACEs for the AppContainer SID (both explicit and inherited)
4. Adds a single new ALLOW ACE with `(existingMask & ~denyOnlyBits)`
5. Applies with `PROTECTED_DACL_SECURITY_INFORMATION` to break inheritance

Step 5 is critical: the parent grant's `TreeSetNamedSecurityInfoW` propagates
an inheritable `(I)(OI)(CI)(F)` ACE to all children. Without breaking
inheritance, Windows re-applies this inherited full-access ACE even after
we replace the DACL, making the deny ineffective.

For directories, `TreeSetNamedSecurityInfoW` with `TREE_SEC_INFO_RESET`
propagates the protected DACL to all descendant files and folders.

### Mask Math — denyOnlyBits

```
sharedBits = SYNCHRONIZE | FILE_READ_ATTRIBUTES | READ_CONTROL
           | STANDARD_RIGHTS_READ | STANDARD_RIGHTS_WRITE
           | STANDARD_RIGHTS_EXECUTE
denyOnlyBits = denyMask & ~sharedBits
reducedMask  = existingMask & ~denyOnlyBits
```

This is critical because deny masks (e.g. `FILE_GENERIC_WRITE`) share bits
with read/execute (`SYNCHRONIZE`, `READ_CONTROL`, `FILE_READ_ATTRIBUTES`).
Raw subtraction (`existing & ~denyMask`) destroys read access.

### Tested Behavior (7 zones, 31 test cases, `test_acl_grants.bat`)

| Zone | Grant | Deny | list | read | write | create | delete |
|------|-------|------|------|------|-------|--------|--------|
| workspace/src | all | — | ✅ | ✅ | ✅ | ✅ | ✅ |
| workspace/build | all | write | ✅ | ✅ | ❌ | ❌ | ✅ |
| workspace/secrets | all | all | ❌ | ❌ | ❌ | ❌ | ❌ |
| data/public | read | — | ✅ | ✅ | ❌ | ❌ | ❌ |
| data/private | read | read | ❌ | ❌ | ❌ | — | — |
| logs | append | — | ❌ | ❌ | ❌ | — | — |
| tools | execute | — | ✅ | ✅ | ❌ | ❌ | ❌ |

### Deep Test (4 levels, 12 zones, 46+4 checks, `test_deep_acl.bat`)

Tests deny inheritance from L3→L4, heterogeneous grant overlap, and post-exit cleanup.

| Zone | Depth | Grant | Deny | list | read | write | create | delete |
|------|-------|-------|------|------|------|-------|--------|--------|
| app/src | L2 | all | — | ✅ | ✅ | ✅ | ✅ | ✅ |
| app/src/core | L3 | all | write | ✅ | ✅ | ❌ | ❌ | ✅ |
| app/src/core/engine | L4 | all | write *(inh)* | ✅ | ✅ | ❌ | ❌ | ✅ |
| app/src/contrib | L3 | all | all | ❌ | ❌ | ❌ | — | ❌ |
| app/src/contrib/plugins | L4 | all | all *(inh)* | ❌ | ❌ | ❌ | — | ❌ |
| app/docs/public/guides | L4 | all | — | ✅ | ✅ | ✅ | — | ✅ |
| app/docs/classified | L3 | all | read | ❌ | ❌ | ✅ | ✅ | ✅ |
| app/docs/classified/memos | L4 | all | read *(inh)* | ❌ | ❌ | ✅ | — | ✅ |
| library/stable/v1 | L3 | read | — | ✅ | ✅ | ❌ | — | — |
| library/experimental/beta | L3 | read | read | ❌ | ❌ | — | — | — |
| scripts/common/utils | L3 | exec | — | ✅ | ✅ | ❌ | — | — |
| scripts/restricted/admin | L3 | exec | execute | ❌ | ❌ | — | — | — |

Post-exit cleanup: ✅ No AppContainer SIDs on any tree, ✅ No registry grants.

**Important:** `deny.write` does NOT block deletes. `DELETE` is a separate
permission bit. Use `deny.delete` or `deny.all` to block deletion.

### Regression Guards

- **Never** use raw `DENY_ACCESS` for AppContainer — the kernel ignores it.
- **Never** use `REVOKE_ACCESS` for deny — it can't remove inherited ACEs.
- **Never** do `existingMask & ~denyMask` — destroys shared bits needed by reads.
- **Always** use `PROTECTED_DACL_SECURITY_INFORMATION` on denied paths to break 
  inheritance from parent grants.
- **Always** use `TREE_SEC_INFO_RESET` (not `SET`) for deny's `TreeSet` to fully
  replace DACLs including inherited entries.
- **Always** manually construct the DACL (enumerate+copy+add) to handle both
  explicit and inherited ACEs.

# ACL Design — Sandy Grant Bit System

## AccessMask Overview

Each `AccessLevel` maps to a Windows permission bitmask:

| Level | Mask | Key bits |
|-------|------|----------|
| Read | `FILE_GENERIC_READ` | `FILE_READ_DATA`, `FILE_READ_EA`, `READ_CONTROL`, `SYNCHRONIZE` |
| Write | `FILE_GENERIC_WRITE + FILE_READ_ATTRIBUTES` | `FILE_WRITE_DATA`, `FILE_APPEND_DATA`, `FILE_WRITE_EA`, `FILE_WRITE_ATTRIBUTES` |
| Execute | `FILE_GENERIC_READ + FILE_GENERIC_EXECUTE` | Read + `FILE_EXECUTE` |
| Append | `FILE_APPEND_DATA + FILE_READ_ATTRIBUTES + SYNCHRONIZE` | Append only, no overwrite |
| Delete | `DELETE + FILE_READ_ATTRIBUTES + SYNCHRONIZE` | Delete only |
| All | `FILE_ALL_ACCESS & ~(FILE_DELETE_CHILD \| WRITE_DAC \| WRITE_OWNER)` | All data ops, no ACL modification |

## Stripped Bits in `All` Mask

Three bits are intentionally excluded from `AccessLevel::All`:

| Bit | Why stripped |
|-----|-------------|
| `FILE_DELETE_CHILD` | Parent's delete-child lets sandbox delete denied children and recreate them without deny. Children inherit their own `DELETE` via ACL inheritance, so non-denied children can still be deleted. |
| `WRITE_DAC` | Sandbox could re-add `FILE_DELETE_CHILD` to its own ACE, undoing the protection above. No legitimate sandbox use for DACL modification. |
| `WRITE_OWNER` | No legitimate sandbox use. `SE_RESTORE_PRIVILEGE` (required for ownership changes) is stripped from AppContainers, but defense-in-depth. |

This is elegant because it requires zero special-case logic — the grant math handles everything.

**Never** add `FILE_DELETE_CHILD`, `WRITE_DAC`, or `WRITE_OWNER` back to the `All` mask.

## Deny Subtraction (AppContainer Mode)

AppContainer SIDs ignore `DENY_ACCESS` ACEs. Sandy implements deny by subtracting bits from the existing ALLOW ACE:

```
reducedMask = existingMask & ~(denyMask & ~sharedBits)
```

**Shared bits** are always preserved: `SYNCHRONIZE`, `FILE_READ_ATTRIBUTES`, `READ_CONTROL`. These support basic file operations (`stat()`, handle synchronization, DACL inspection).

# Multi-Instance ACL Safety — ACE-Level Removal

## The Problem with DACL Snapshot Restoration

The original design saved the full DACL as SDDL before granting, then replaced
the entire DACL on cleanup. This races when multiple instances modify the same
folder:

```
Instance A: saves DACL = S0
Instance B: saves DACL = S0 + A's ACE = S1
Instance A exits: replaces DACL with S0 → B's child loses access
Instance B exits: replaces DACL with S1 → A's zombie ACE is back
```

## The Fix: ACE-Level Addition and Removal

**Grant** adds an ACE for the instance's SID to the existing DACL.
**Revoke** walks the DACL, removes only ACEs matching the instance's SID,
leaves everything else untouched.

This is implemented in `RemoveSidFromDacl()` (`SandboxACL.h`):
1. Convert SID string → binary SID
2. Read current DACL via `GetNamedSecurityInfoW`
3. Walk ACE list with `GetAce()`, match via `EqualSid()`
4. Build new DACL from non-matching ACEs
5. Apply via `SetNamedSecurityInfoW` / `TreeSetNamedSecurityInfoW`

## Registry Format Change

| Field | Before | After |
|-------|--------|-------|
| Grant record | `TYPE\|PATH\|SDDL` | `TYPE\|PATH\|SID` |
| `ACLGrant` struct | `originalSDDL` + `objectId[16]` | `sidString` |
| `RecordGrant` param | `PSECURITY_DESCRIPTOR` | `const std::wstring& sidString` |

## Mode-Specific Safety

| Mode | SID per instance | Cleanup |
|------|------------------|---------|
| AppContainer | Unique (per-profile) | Remove ACEs for our SID — zero interference |
| Restricted Token | Shared (`S-1-5-12`) | Skip paths used by other live instances |

## Removed Components

- `RestoreDacl()` — replaced by `RemoveSidFromDacl()`
- `StampObjectId()` / `ResolveByObjectId()` — OID tracking not needed for ACE removal
- SDDL snapshot in `RecordGrant()` — only SID string is stored

**Never** revert to snapshot-based DACL restoration. ACE-level removal is the
only approach that is safe for concurrent multi-instance operation.

Verified by `test_multiinstance.bat` — overlapping grants, instance exit,
DACL restoration, and kill+cleanup scenarios.
