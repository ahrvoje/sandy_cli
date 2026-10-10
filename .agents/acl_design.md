---
description: Critical ACL design facts to avoid regressions in Sandy sandbox
---

# Ownership and SID Model

Sandy now treats **profiles as first-class durable identities** and **runs as
execution sessions** that may be either transient or profile-backed.

## AppContainer

- **Transient run:** container name is `Sandy_<uuid>` and the SID is unique to that run.
- **Saved profile:** container name is `Sandy_<name>` and the SID is durable for that profile.

## Restricted Token

- Always uses a unique run SID under `SECURITY_RESOURCE_MANAGER_AUTHORITY` (`S-1-9-*`).
- `S-1-5-12` remains a restricting SID for system-object behavior only; it is not a grant owner SID.
- By default, the user's own SID is included in the restricting list so existing
  file access passes the dual check. When `strict = true`, the user SID is
  excluded — forcing explicit grants for user-owned resources and making
  `.this`/`.deep` scope enforcement fully meaningful on the restricting side.

**Never** collapse these back into a shared SID model. Cleanup and overlap safety
rely on removing ACEs by the exact owning SID.

# What “Per-Instance” Means Now

- **Transient AppContainer:** grants are per run.
- **Saved-profile AppContainer:** grants are per profile.
- **Restricted Token:** grants are per run.

Do not write logic that assumes all AppContainer grants are transient. Profile-owned
ACL state is durable and must survive normal run exit.

# LPAC Loader Access Is More Than File Access

A DLL read/execute grant does not guarantee that Windows can activate its
manifest. Before widening file or registry permissions for a load failure,
read [LPAC loader debugging](lpac_loader_debugging.md). The pipe hook avoids
its own SxS requirement by having no manifest; it must work with zero
capabilities.

For applications that need them, `registry_read` and `com` add capability SIDs
to the LPAC token. They do not edit host ACLs and do not create ACL grants to
revoke. Their access scope comes from existing resource ACLs and the token;
`registry_read` is not a one-key grant. Keep these application requirements
separate from the hook's build invariant.

# ACL Propagation — Inheritance-Based Model

## One write path: `AddAcesToObject`

Every filesystem and registry rule goes through `AddAcesToObject()` in
`SandboxACL.h`. For one object and one SID it does, in this order:

1. read the DACL;
2. write the ledger record (`RecordGrantFn`) — **before** the DACL changes;
3. build the new DACL: the SID's new ACEs go in at their canonical position,
   every other ACE keeps its place (`RebuildDacl`);
4. write the DACL once (`WriteDaclToObject`).

If step 2 fails, nothing is written (`ERROR_WRITE_FAULT`): no record, no ACE.

Recursive rules on a directory use `SetNamedSecurityInfoW`; the ACEs carry
inheritance flags and Windows auto-inheritance propagates them to existing
descendants. Rules on a single object (`.this`, files) use one
`SetKernelObjectSecurity` write with no propagation.

Windows writes the descendants first and the rule's root last. A kill during
propagation therefore leaves descendants with an inherited ACE that the root
does not hold. `RemoveSidFromDaclDetailed` handles this: when the root holds no
ACE of the SID, it rewrites the root's unchanged DACL to force a new
propagation (`ACL_REPROPAGATE`).

## DACL Protection Invariant — `WriteDaclToObject`

Sandy **never** changes the protection of a DACL. `WriteDaclToObject()` reads
`SE_DACL_PROTECTED` and `SE_DACL_AUTO_INHERITED` from the existing security
descriptor and writes both back unchanged. It has **no parameter** to choose
another value, so no caller can set or clear protection by mistake.

After cleanup a DACL is identical to the one before the run: same ACEs, same
order, same flags. `test_dacl_fidelity.bat` holds this as a test.

> [!CAUTION]
> **Never** add a bare `SetNamedSecurityInfoW` or `SetKernelObjectSecurity` call
> for filesystem objects.  Always use `WriteDaclToObject`.  A bare call drops
> the protection or auto-inherit flag of a DACL that the user set.

## Rules

- **Never** use `TreeSetNamedSecurityInfoW` for grants, cleanup, or deny.
- **Never** use `TREE_SEC_INFO_SET` anywhere — it stamps one DACL onto all
  descendants and destroys per-child DACLs.
- **Never** use `SetEntriesInAclW` to apply an `[allow.*]` / `[deny.*]` /
  `[registry]` rule. It keeps at most one ACE per trustee, so a deny and an
  allow of the same SID cannot both stay. `RebuildDacl` is the DACL builder
  for rules. (Sandy's own objects — token default DACL, desktop, its registry
  keys — hold one ACE per SID and still use it.)
- **Never** strip, move or rewrite an ACE of another identity.

# Access Levels — Read vs Execute

**`read` does NOT grant `FILE_EXECUTE`.** Any directory containing code that must
be loaded by the OS loader requires `execute`, not `read`.

```toml
[allow.deep]
execute = ['C:\path\to\python']
read    = ['C:\path\to\data']
```

Do not “fix” loader failures by adding execute to the read mask.

# Permission Flags by Access Level

| Level | Config key | Mask | Windows flags |
|-------|-----------|------|---------------|
| Read | `read` | `FILE_GENERIC_READ` | `FILE_READ_DATA`, `FILE_READ_EA`, `FILE_READ_ATTRIBUTES`, `READ_CONTROL`, `SYNCHRONIZE` |
| Write | `write` | `FILE_GENERIC_WRITE \| FILE_READ_ATTRIBUTES \| SYNCHRONIZE` | `FILE_WRITE_DATA`, `FILE_APPEND_DATA`, `FILE_WRITE_EA`, `FILE_WRITE_ATTRIBUTES`, `READ_CONTROL`, `SYNCHRONIZE`, `FILE_READ_ATTRIBUTES` |
| Execute | `execute` | `FILE_GENERIC_READ \| FILE_GENERIC_EXECUTE` | All Read flags + `FILE_EXECUTE` |
| Append | `append` | `FILE_APPEND_DATA \| FILE_READ_ATTRIBUTES \| SYNCHRONIZE` | Append-only, no read/overwrite |
| Delete | `delete` | `DELETE \| FILE_READ_ATTRIBUTES \| SYNCHRONIZE` | Delete only, no read/write |
| All | `all` | `FILE_ALL_ACCESS & ~(FILE_DELETE_CHILD \| WRITE_DAC \| WRITE_OWNER)` | Full data control, no ACL modification |
| Run | `run` | `FILE_EXECUTE \| FILE_READ_ATTRIBUTES \| SYNCHRONIZE` | Execute only, no read (can't copy binary) |
| Stat | `stat` | `FILE_READ_ATTRIBUTES \| SYNCHRONIZE` | Attributes only (NON-recursive, like ) |
| Touch | `touch` | `FILE_WRITE_ATTRIBUTES \| FILE_READ_ATTRIBUTES \| SYNCHRONIZE` | Modify attributes only (NON-recursive, like ) |
| Create | `create` | `FILE_ADD_FILE \| FILE_ADD_SUBDIRECTORY \| FILE_READ_ATTRIBUTES \| SYNCHRONIZE` | Create new files/subdirs, no overwrite |

# DENY ACEs — Restricted Token Only

## Restricted Token Mode

Uses real `ACCESS_DENIED_ACE` entries for the run SID.

## AppContainer Mode

Deny is **not supported**. The kernel ignores deny ACEs for AppContainer
SIDs (`S-1-15-2-*`). Config validation rejects `[deny.*]` for AC mode.

## Deny masks are not allow masks — `DenyMask()`

An allow mask carries the rights that every open needs (`SYNCHRONIZE`,
`READ_CONTROL`, `FILE_READ_ATTRIBUTES`). A deny on those rights blocks every
open, whatever the level. `DenyMask()` therefore holds only the rights that
define the level:

| Level | Deny mask |
|-------|-----------|
| `read` | `FILE_READ_DATA \| FILE_READ_EA` |
| `write` | `FILE_WRITE_DATA \| FILE_APPEND_DATA \| FILE_WRITE_EA \| FILE_WRITE_ATTRIBUTES` |
| `execute`, `run` | `FILE_EXECUTE` |
| `append` | `FILE_APPEND_DATA` |
| `delete` | `DELETE \| FILE_DELETE_CHILD` |
| `all` | `FILE_ALL_ACCESS` |
| `stat` | `FILE_READ_ATTRIBUTES` (holds only where listing the parent is denied too) |
| `touch` | `FILE_WRITE_ATTRIBUTES` |
| `create` | `FILE_ADD_FILE \| FILE_ADD_SUBDIRECTORY` |

Every deny mask also holds `kDenyTamperMask = WRITE_DAC | WRITE_OWNER`: the
denied process must not be able to edit the rule away.

> [!CAUTION]
> **Never** build a deny mask from `AccessMask()`. `SYNCHRONIZE`,
> `READ_CONTROL` or `FILE_READ_ATTRIBUTES` in a deny mask makes every deny
> level block read and list.

## Owner neutralization — `OwnerAce`

With `strict = false` the user SID is a restricting SID, so the sandboxed
process is an owner of the user's objects. Windows gives an owner
`READ_CONTROL | WRITE_DAC` before it reads the DACL; a deny ACE cannot remove
that. An `OWNER RIGHTS` (S-1-3-4) ACE switches the implicit grant off.

`AddAcesToObject(neutralizeOwner = true)` adds one `OWNER RIGHTS` allow ACE
(`kOwnerAceMask = READ_CONTROL | WRITE_DAC`) next to a deny, unless the object
already holds an `OWNER RIGHTS` ACE. The real user keeps the same rights. The
ledger record says which companion exists (`OWNER:I` inherited form,
`OWNER:O` object-only form), and cleanup removes exactly that one ACE.

## Delete guard — `kDeleteGuardMask`

Windows lets a process delete or rename an object when it holds
`FILE_DELETE_CHILD` on the parent, whatever the DACL of the object says. For
each `deny.delete` / `deny.all` path `BuildPathPlan` adds one object-only deny
ACE (`FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER`) on the parent directory,
when the user can delete children there. The guard is recorded and removed
like any other rule.

## `create` inherits to directories only — `DeepInheritFlags()`

`FILE_ADD_FILE` / `FILE_ADD_SUBDIRECTORY` have the same bit values as
`FILE_WRITE_DATA` / `FILE_APPEND_DATA`. A `create` ACE that files inherit is an
overwrite rule. `create` rules use `CONTAINER_INHERIT_ACE` only.

# Allow/Deny Precedence — the ACE Order Decides

Sandy does not strip denies and does not protect DACLs to make a carve-out.
The canonical ACE order of Windows does the work: explicit deny, explicit
allow, then inherited ACEs, nearest parent first. An explicit ACE on a nearer
object is evaluated before a deny inherited from further up.

| Rules | Result |
|---|---|
| allow on a **descendant** of a deny | the allow gives back exactly the rights it names, at its scope |
| deny on a **descendant** of an allow | the deny removes exactly the rights it names |
| allow and deny, **same path, same scope** | deny wins (deny ACE comes first) |
| `allow.this` and `deny.deep` on the **same directory** | the `allow.this` wins on the directory itself for the rights it names; descendants keep the full deny |

The last row is the only place where Sandy shapes ACEs: `CompilePathAces`
makes the recursive deny inherit-only and adds an object deny for
`denyMask & ~allowThisMask`. Same-object precedence is decided there, once.

> [!CAUTION]
> A carve-out is right by right. `allow.deep write` under `deny.deep all`
> gives write, not read. Do not "help" by widening the allow or by removing
> the inherited deny: the user asked for exactly these rights.

# Regression Guards

- **Never** write a deny ACE for an AppContainer SID (kernel ignores them).
- **Never** use `REVOKE_ACCESS` as a substitute for deny.
- **Never** set or clear `PROTECTED_DACL`, for any purpose. It changes the
  access of every other identity on the object and cannot be undone exactly.
- **Never** write a DACL before its ledger record exists (write-ahead).
- **Never** put `SYNCHRONIZE`, `READ_CONTROL` or `FILE_READ_ATTRIBUTES` into a
  deny mask (the `all` level is the one exception: it denies everything).
- **Never** remove an `OWNER RIGHTS` ACE that the ledger does not name.

# Multi-Owner ACL Safety — ACE-Level Removal

Snapshot-based DACL restoration is unsafe for overlapping runs or profiles.
Sandy must add and remove ACEs by **owning SID**, never by restoring an old SDDL blob.

## Safe model

- **Grant:** add ACE(s) for the owning SID.
- **Revoke:** walk the current DACL and remove ACEs for that SID only.
- **Persist:** store enough metadata to retry cleanup later if the process dies.

This is why `RecordGrant()` stores owner/SID-oriented data rather than whole-DACL snapshots.

# Overlap Precision

When multiple owners touch the same tree, cleanup decisions must be keyed by
**path + SID**, not by path alone.

Examples:
- Two transient restricted runs on the same folder: same path, different SIDs.
- A saved profile and a transient restricted run overlapping the same subtree.
- A saved AppContainer profile and a transient AppContainer run touching related items.

If cleanup skips by path only, stale ACEs survive forever.

# Durable vs Transient Cleanup Rules

- **Transient run ACL state** is removed at normal run exit or stale recovery.
- **Profile-owned ACL state** is removed only by explicit profile deletion or profile rollback.
- **Run metadata** may point at a profile-owned SID/container, but that does not transfer ownership.

Do not let normal run cleanup delete profile-owned ACLs or containers.

# Desktop and Window Station ACLs

Restricted Token mode with `desktop = true` grants the SID access to the
current window station and desktop.

- **Persistent profiles:** Desktop ACEs are granted at profile creation and
  revoked at profile deletion.  Profile runs do no per-run desktop management.
- **Transient runs:** Desktop ACEs are granted per-run and revoked on run exit
  (including emergency cleanup). The intent is written to the ledger first
  (`_desktop_sid`, `PersistDesktopGrantIntent`), so stale recovery removes the
  ACEs of a killed run too.

This cleanup must stay ACE-level and owner-specific.

`desktop = false` cannot be enforced through the token: the window station
and desktop DACLs grant full access to `RESTRICTED` (S-1-5-12). It is enforced
through job-object UI limits (`JOB_OBJECT_UILIMIT_HANDLES` and related flags):
the sandbox cannot list or use windows of other processes.

**Never** revert to snapshot-based desktop DACL restoration.

