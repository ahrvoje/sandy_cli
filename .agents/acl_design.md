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

During cleanup, each instance only revokes its own grants. The registry stores
the original SDDL for each modified path, and `GetOtherInstancePaths()` ensures
paths still needed by other live instances are not revoked prematurely.

# ACL Propagation — TreeSetNamedSecurityInfoW

Directory grants use `TreeSetNamedSecurityInfoW` (not `SetNamedSecurityInfoW`) to
synchronously propagate OICI ACEs to all child files. `SetNamedSecurityInfoW` does
NOT reliably propagate to existing children, causing `0xC0000022` failures in
large directory trees (e.g. Python's 36K files).

This applies to all three DACL modification paths in `SandboxACL.h`:
- `GrantObjectAccess` — grant
- `RestoreGrantsFromKey` — crash recovery restore
- `RevokeAllGrants` — in-process cleanup

**Never** replace `TreeSetNamedSecurityInfoW` with `SetNamedSecurityInfoW` for
directories. File-only grants still use `SetNamedSecurityInfoW` (no children).

# Access Level Permissions — Read vs Execute

**`read` does NOT grant `FILE_EXECUTE`.** This is intentional and critical.

Any directory containing executables or DLLs that need to be **loaded** (Python,
Node, compilers) must use `execute`, not `read`, in the config:

```toml
[access]
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
| All | `all` | `FILE_ALL_ACCESS` | Full control |

Key points:
- **Read** cannot load DLLs/EXEs (no `FILE_EXECUTE`)
- **Write** cannot list or read directory contents (no `FILE_READ_DATA`)
- **Execute** is the standard `(RX)` — minimum for running programs
- **Append** cannot overwrite existing data (no `FILE_WRITE_DATA`)
- **Delete** cannot read or write file contents
