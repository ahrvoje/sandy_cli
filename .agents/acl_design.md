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

# ACL Propagation — Inheritance-Based Model

## Grants and Cleanup: `SetNamedSecurityInfoW`

Directory grants and ACE removal use `SetNamedSecurityInfoW` (not `TreeSet`).
The ACE has `OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE` flags, so Windows
auto-inheritance propagates it to existing descendants.

Key property: auto-inheritance **skips** children with `PROTECTED_DACL` (e.g.
deny paths from other instances). This makes multi-instance operations fully
independent — each SID's grants and cleanup never disturb another SID's DACLs.

## Deny: `SetNamedSecurityInfoW` (Restricted Token Only)

Deny rules use standard `DENY_ACCESS` ACEs via `SetNamedSecurityInfoW` with
auto-inheritance. This is only supported in **Restricted Token** mode.

> [!CAUTION]
> The Windows kernel **ignores** DENY ACEs for AppContainer SIDs (`S-1-15-2-*`).
> Sandy rejects `[deny.*]` for AppContainer mode at config validation time.

## Rules

- **Never** use `TreeSetNamedSecurityInfoW` for grants, cleanup, or deny.
- **Never** use `TREE_SEC_INFO_SET` anywhere — it stamps one DACL onto all
  descendants and destroys per-child DACLs.

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

Uses real `DENY_ACCESS` ACEs. The kernel evaluates deny-before-allow normally.
Deny ACEs are applied via `SetNamedSecurityInfoW` with `DACL_SECURITY_INFORMATION`
and auto-inheritance propagation.

## AppContainer Mode

Deny is **not supported**. The kernel ignores `DENY_ACCESS` ACEs for AppContainer
SIDs (`S-1-15-2-*`). Config validation rejects `[deny.*]` for AC mode.

# Regression Guards

- **Never** write a `DENY_ACCESS` ACE for an AppContainer SID (kernel ignores them).
- **Never** use `REVOKE_ACCESS` as a substitute for deny.
- **Never** use `PROTECTED_DACL` for deny enforcement (causes SID-agnostic side effects).

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

Restricted Token mode requires granting the SID access to the current window
station and desktop.

- **Persistent profiles:** Desktop ACEs are granted at profile creation and
  revoked at profile deletion.  Profile runs do no per-run desktop management.
- **Transient runs:** Desktop ACEs are granted per-run and revoked on run exit
  (including emergency cleanup).

This cleanup must stay ACE-level and owner-specific.

**Never** revert to snapshot-based desktop DACL restoration.

