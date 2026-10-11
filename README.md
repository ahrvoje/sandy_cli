<p align="center">
  <img src="resources/sandy_logo.png" alt="Sandy Logo" width="400"/>
</p>

<p align="center">
  <strong>A lightweight Windows sandbox runner</strong><br/>
  Run any executable in an isolated sandbox with fine-grained file, folder, and network access control.<br/>
  Features first-class persistent profiles and transient one-shot sandboxes.
</p>

<p align="center">
  <a href="https://ahrvoje.github.io/sandy_cli/"><strong>📖 View Documentation</strong></a>
</p>

---

## What is Sandy?

Sandy launches executables inside a kernel-enforced Windows sandbox. Normal launches need no elevation; changing ACLs on protected host paths requires permission to those paths. Adding loopback exemptions requires an administrator. Three isolation modes are supported: [AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation) (App. Packages — the same technology used by UWP apps and Edge), **LPAC** (Restricted App. Packages — stricter AppContainer that opts out of ALL APPLICATION PACKAGES), and **Restricted Token** (restricting SIDs with configurable integrity level). The sandbox uses an explicit TOML model with safe, locked-down defaults for any omitted settings.

No VMs, Docker, WSL, or Hyper-V — just a single native executable. Sandy is lean, unprivileged sandboxing for agentic AI workflows, automation scripts, and tool-use pipelines: you define exactly which folders, files, and network access the process gets.

When ACL cleanup fails, Sandy keeps the recovery ledger and logon task and
reports incomplete cleanup. If the child returned zero, Sandy returns 125;
otherwise the child's error or timeout result is preserved. Startup and
`--cleanup` retry the recorded removals. Ledger creation and inspection share
a lock, so abandoned incomplete records can be recovered without touching a live writer.

### Key Features

- 🔒 **Three sandbox modes** — AppContainer, LPAC, or Restricted Token with configurable integrity
- 📁 **Granular access control** — read, write, execute, append, delete, or full access per file or folder
- 🌐 **Network control** — internet/LAN capabilities and a loopback switch (AppContainer / LPAC)
- 🏢 **Multi-instance safe** — true isolation with independent instance-specific grants
- 💾 **Profile-first design** — persistent sandbox identities with reusable grants and config
- 🛡️ **Explicit configuration** — uses a TOML model with strictly safe, locked-down defaults for omissions
- ⏱️ **Resource limits** — timeout, memory cap, and process count limits
- 📝 **Operational logging** — session logs and cleanup diagnostics
- ⚡ **Zero dependencies** — single native executable, no runtime needed

---

## Usage

```
sandy.exe -c <config.toml> [-l <logfile>] [-L] [-q] -x <executable> [args...]
sandy.exe -s "<toml>"      [-l <logfile>] [-L] [-q] -x <executable> [args...]
sandy.exe -p <profile>     [-l <logfile>] [-q] -x <executable> [args...]
sandy.exe --create-profile <name> -c <config.toml>  (create persistent sandbox profile)
sandy.exe --delete-profile <name>                   (delete profile + revoke ACLs)
sandy.exe --profile-info <name>                     (show profile details)
sandy.exe --print-container-toml          (print default appcontainer config)
sandy.exe --print-restricted-toml         (print default restricted config)
sandy.exe --cleanup                       (restore stale state from crashed runs)
sandy.exe --status [--json]                (show instances, retry containers, cleanup tasks, and summary counts)
sandy.exe --explain <code>                 (decode exit code: Sandy, NTSTATUS, Win32)
sandy.exe --dry-run -c <config.toml> [-x <exec>]              (validate + show plan, no changes)
sandy.exe --dry-run --create-profile <name> -c <config.toml>  (preview profile creation, no changes)
sandy.exe --print-config -c <config.toml>  (print resolved config)
```

| Flag | Description |
|-------------------------------------|-------------|
| `-c <path>`, `--config <path>` | Path to TOML config file |
| `-s <toml>`, `--string <toml>` | Inline TOML config string (alternative to `-c`) |
| `-l <path>`, `--log <path>` | Session log (operational events, config, exit code) |
| `-L`, `--log-stamp` | Prepend `YYYYMMDD_HHMMSS_uid_` to log filenames |
| `-p <name>`, `--profile <name>` | Run with a persistent saved profile (mutually exclusive with `-c`/`-s`) |
| `--create-profile <name>` | Create a persistent sandbox profile with SID + ACLs from TOML config |
| `--delete-profile <name>` | Delete a saved profile and revoke its persistent ACLs |
| `--profile-info <name>` | Show saved profile details (type, SID, config, grants) |
| `-x <path>`, `--exec <path>` | Executable to run sandboxed (consumes remaining args) |
| `-q`, `--quiet` | Suppress the config banner on stderr. The banner is also off when `-l` is active (it goes to the log) |
| `-v`, `--version` | Print version |
| `-h`, `--help` | Print full help text with config reference |
| `--print-container-toml` | Print default AppContainer config to stdout |
| `--print-restricted-toml` | Print default Restricted Token config to stdout |
| `--cleanup` | Restore stale state from crashed runs (liveness-gated: preserves live instances) |
| `--status [--json]` | Show instances, retry containers, cleanup tasks, saved profiles, and summary counts |
| `--json` | JSON output (with `--status`, includes summary counts) |
| `--explain <code>` | Decode exit code (Sandy 125-131, NTSTATUS, Win32) |
| `--dry-run`, `--check` | Validate config + show planned changes (no system modifications). Also supported with `--create-profile` to preview what would be created. |
| `--print-config` | Print resolved config to stdout (requires `-c`/`-s`) |


All sandy flags must come **before** `-x`. Everything after `-x <executable>` is forwarded to it, also tokens such as `-l` or `-q`.

### Exit codes

Sandy follows the POSIX high-code convention used by `bash`, `env`, `timeout`, and `git bisect`. Child exit codes 0-124 pass through with zero ambiguity.

| Code | Meaning |
|:----:|---------|
| `0` | Success — child exited cleanly, or info command succeeded |
| `1`-`124` | Child's exit code (passed through unchanged) |
| `125` | Sandy internal / general error, or a command-line usage error (unknown option, missing argument) |
| `126` | Cannot execute — `CreateProcess` failed (permission denied, bad format) |
| `127` | Command not found — executable does not exist on disk |
| `128` | Configuration error — invalid TOML, wrong-mode keys, config file not found |
| `129` | Sandbox setup failed — token/SID creation, ACL grants, or stdin setup |
| `130` | Timeout — the sandboxed process tree was ended by Sandy's timeout watchdog |
| `131` | Child crashed — NTSTATUS crash code detected (e.g. `0xC0000005`) |

> [!TIP]
> In automation scripts, check for `exit code >= 125` to detect Sandy-level errors. Codes 130 and 131 indicate the child ran but terminated abnormally.

> [!NOTE]
> **Ctrl+C / Ctrl+Break.** Sandy ends the child process tree, runs its complete cleanup, and then exits with `0xC000013A` (`STATUS_CONTROL_C_EXIT`, shown by `cmd` as `-1073741510`). This is the code that Windows gives to any console program ended by Ctrl+C.

---

## Config File

All sandbox behavior is controlled by a TOML config. Every config **must** include a `[sandbox]` section declaring the token mode. Use `-c` or `-s` (mutually exclusive). Mode-specific settings are validated — using a flag meant for the other mode is an error. All paths must be absolute and must exist on disk (non-existent paths are rejected as config errors).

**Environment variables in paths:** a path can hold variables in `%NAME%` form, for example `'%USERPROFILE%\project'` or `'%LOCALAPPDATA%\Programs\Python\Python314'`. Sandy replaces them with the values from its own environment when it loads the config, so a config does not have to hold a user name. A variable that is not set is a config error. `--print-config` shows the resolved paths.

**Config limits (defense-in-depth):**
- Config file size: max **1 MB**
- Path length: max **32,768 characters** per path (Win32 extended limit)
- Rules per section: max **256** entries in `[allow.*]`, `[deny.*]`, or `[registry]`

See [`sandy_config.toml`](sandy_config.toml) for the default template, [`sandy_config_appcontainer.toml`](sandy_config_appcontainer.toml) and [`sandy_config_restricted.toml`](sandy_config_restricted.toml) for mode-specific templates.

### `[sandbox]` — Mode selection

```toml
[sandbox]
token = 'appcontainer'    # or 'lpac' or 'restricted'
integrity = 'low'         # restricted only: 'low' or 'medium' (required)
strict = false            # restricted only: exclude user SID from restricting list (default: false)
workdir = 'C:\projects'   # absolute child working directory (default: inherit Sandy's current working directory)
```

| Key | Values | Modes | Description |
|-----|--------|-------|-------------|
| `token` | `'appcontainer'`, `'lpac'`, `'restricted'` | all | Sandbox isolation model *(required)* |
| `integrity` | `'low'`, `'medium'` | restricted | Integrity level *(required)* · `'low'` = strongest isolation, `'medium'` = wider app compatibility |
| `strict` | `true`, `false` | restricted | Exclude user SID from restricting list · Default: `false`. When `true`, user-owned resources require explicit `[allow.*]` grants |
| `workdir` | absolute path | both | Child process working directory (default: `'inherit'` — Sandy's current working directory) |

The `-s` option converts a literal `\n` outside strings and comments to a line break. File input (`-c`) uses standard TOML semantics. Unknown sections and wrong-mode items are rejected even when empty or false.

### `[allow.deep]` / `[allow.this]` — File and folder grants

Grant the sandboxed process access to specific files or folders. Sandy modifies folder ACLs at launch and restores them on exit. Requires `WRITE_DAC` on each path (user-owned folders work without admin).

Two scopes control inheritance:
- **`[allow.deep]`** — grants apply recursively to the path and **all descendants** (OI|CI inheritance)
- **`[allow.this]`** — grants apply **only to the named object** itself (uses `SetKernelObjectSecurity` — instant, no child walk)

```toml
[allow.deep]
read    = ['C:\data\config.json', 'C:\Python314']
write   = ['C:\logs\agent.log', 'C:\temp\output']
execute = ['C:\tools\bin']
append  = ['C:\logs\audit.log']
delete  = ['C:\temp\scratch']
all     = ['C:\workspace']

[allow.this]
read    = ['C:\', 'C:\Users', '%USERPROFILE%']    # directory listing only
stat    = ['C:\important_file.dat']             # attributes only
```

| Key | Permission granted |
|-----|--------------------|
| `read` | Read files, list directories |
| `write` | Create and modify files, no read |
| `execute` | Read + execute files, list directories |
| `append` | Append only, no overwrite, no read |
| `delete` | Delete only |
| `all` | Full access: read + write + execute + delete |
| `run` | Execute only, no read (can't copy binary) |
| `stat` | Read attributes only |
| `touch` | Modify attributes only |
| `create` | Create new files/subdirs, no overwrite |

> [!IMPORTANT]
> **Scope controls inheritance.** In `[allow.deep]`, all access levels apply recursively. In `[allow.this]`, all access levels apply to the single object only. The access level determines *what* permissions are granted; the scope determines *where* they propagate.

> [!IMPORTANT]
> Permissions are independent — `write` does **not** grant `read`, and `read` does **not** grant `execute`. Grant each permission explicitly, or use `all` for full access.

> [!NOTE]
> **Two limits that come from the Windows permission bits.** A `create` rule in `[allow.deep]` / `[deny.deep]` inherits to sub-folders only: "add file" on a folder and "write data" on a file are the same bit, so a `create` rule on files would be an overwrite rule. For the same reason `append` on a folder also allows the creation of sub-folders.

### `[deny.deep]` / `[deny.this]` — Deny access to specific paths *(restricted token only)*

Block specific permissions on paths that would otherwise be accessible. Same access keys and scope semantics as allow. All keys optional (default `[]`).

> [!CAUTION]
> `[deny.*]` is **not available in AppContainer mode**. The Windows kernel ignores DENY ACEs for AppContainer SIDs. Use Restricted Token mode for deny rules.

```toml
[deny.deep]
write   = ['C:\workspace\src\core']         # block writes in core/ and all descendants
all     = ['C:\workspace\secrets']           # fully block secrets/ recursively

[deny.this]
write   = ['C:\workspace\config.lock']      # block writes to this single file only
```

**Key behaviors:**

- **`[deny.deep]` is recursive.** A deny on a directory blocks the denied permissions on that directory **and all descendants** — subdirectories and files at every depth.
- **`[deny.this]` is non-recursive.** Applies only to the named object itself.
- **Deny is surgical.** Only the specific permission type is blocked. For example, `deny.write` blocks writing and creating files, but `read`, `execute`, and `delete` remain allowed.
- **`deny.write` does NOT block delete.** `DELETE` is a separate Windows permission from `WRITE`. To block deletion, use `deny.delete` or `deny.all`.
- **`deny.read` blocks listing.** Denying read also blocks `os.listdir()` / `dir` because directory listing requires read-data permission.
- **`deny.delete` and `deny.all` also block rename.** Windows lets a process delete or rename an object through the "delete child" right of the parent folder, whatever the object's own DACL says. For these two levels Sandy therefore puts one extra deny ACE (the *delete guard*: delete child, this folder only) on the parent folder of the denied path. The denied object, and the denied folder itself, cannot be deleted or renamed. Other children of that parent are not affected.
- **A deny cannot be edited away.** Every deny also blocks "change permissions" and "take ownership" on the denied object. With `strict = false` the sandboxed process counts as owner of the user's files, and Windows gives an owner the right to change permissions before it reads the DACL. Sandy switches that implicit right off with one `OWNER RIGHTS` ACE next to the deny. The real user keeps the same rights as before.
- **`deny.stat` has a limit.** Windows also gives "read attributes" through the list right of the parent folder. `deny.stat` holds only where listing the parent folder is denied too.

| Deny level | Rights denied |
|------------|---------------|
| `read` | Read data / list folder, read extended attributes |
| `write` | Write data, append data, write extended attributes, write attributes |
| `execute`, `run` | Execute / traverse |
| `append` | Append data |
| `delete` | Delete, delete child |
| `all` | All file rights |
| `stat` | Read attributes |
| `touch` | Write attributes |
| `create` | Add file, add sub-folder (folders only) |

All levels also deny "change permissions" and "take ownership".

#### Allow-inside-deny (the nearest rule wins)

Sandy supports carving out allowed subtrees from within denied areas. The standard Windows ACE order decides: the ACEs on an object are evaluated before the ACEs it inherits from further up. So the rule on the **nearest** folder wins, right by right:

- An allow under a deny gives back exactly the rights that the allow names, at its own scope (`allow.deep` = the subtree, `allow.this` = that one object). `allow.deep write` under `deny.deep all` gives write access; read stays denied.
- A deny under an allow removes exactly the rights that the deny names.
- On the same path and scope, the deny wins.
- `allow.this` on a folder that also has a `deny.deep` wins on the folder itself for the rights it names. Descendants keep the full deny.

Sandy never changes the protection of a DACL ("disable inheritance") and never removes or rewrites ACEs of other identities. It adds ACEs for the sandbox SID and removes exactly those on exit.

```toml
[deny.deep]
all = ['C:\repos']                 # deny all access to repos

[allow.deep]
all  = ['C:\repos\snipps']         # but allow full access to snipps

[allow.this]
stat = ['C:\repos']                # and allow stat on the repos dir itself
```

The pipeline execution is logged:
```
PIPELINE: sorted 3 entries by path depth:
    DENY  [ALL    ] C:\repos
    ALLOW [STAT   ] C:\repos  (this object only)
    ALLOW [ALL    ] C:\repos\snipps
```

> [!TIP]
> **Common pattern:** Deny `all` on a broad directory, then allow specific subdirectories. The rule on the nearest folder wins.

### `[pipes]` — Container-local pipe names *(AppContainer / LPAC only)*

Map an app's fixed Win32 pipe name to a `LOCAL` name without changing its executable:

```toml
[sandbox]
token = 'lpac'

[pipes]
'\\.\pipe\my-app' = '\\.\pipe\LOCAL\my-app'
```

The mapping is optional and empty by default. Both names must be pipe paths
(`\\.\pipe\` or `\\?\pipe\`); the destination must contain `LOCAL\` and a
non-empty name. Matching ignores case but otherwise requires the exact name.
Names have a 256-character limit and cannot contain control characters. At most
256 pairs are allowed, within a 32,766-character serialized environment value.
Wildcards and environment expansion in pipe names are not supported.

Sandy embeds the hook DLL in `sandy.exe`, extracts a separate copy for each run,
and loads it before the root app's entry point. It rewrites normal imports of
`CreateNamedPipeW`, `CreateFileW`, `WaitNamedPipeW`, and `CallNamedPipeW` in modules
loaded at that time. The app and Sandy must have the same architecture.
ANSI APIs, `GetProcAddress`, delay imports, later DLL loads, calls from initial
DLL initialization, direct NT calls, and spawned child processes are not covered.
This is a compatibility feature; the Windows token and pipe access checks still apply.
It does not grant access to an existing host pipe or create a host-side alias.

Saved profiles retain the map. Each run owns its extracted DLL, and cleanup
removes it without changing the profile's grants. Startup recovery retries file
removal after a killed run. Loading or hook installation failure aborts launch
with exit code 129. No extra capabilities are added to LPAC.

### `[capabilities]` — Windows capability names

AppContainer and LPAC use the same list. The default is empty; Sandy adds only the
requested capability SIDs to the child token. Restricted Token mode rejects this section.

```toml
[capabilities]
names = ['registryRead', 'lpacCom']
```

Sandy uses Windows `DeriveCapabilitySidsFromName`. The list is not limited to a
built-in catalog: Windows and custom capability names use the same interface.
A name can derive a SID even if no resource accepts it. Listing a capability does
not guarantee that an API, service, or application will work under LPAC.

| Name | Purpose, subject to Windows policy and resource permissions |
|------|------------------------------------------------------------|
| `internetClient` | Outbound internet |
| `internetClientServer` | Internet client and server access |
| `privateNetworkClientServer` | Private network access; also required for Sandy's loopback option |
| `registryRead` | Registry access where existing ACLs grant rights to this capability |
| `lpacCom` | LPAC COM/OLE access where the server permits it |
| `lpacCryptoServices` | Access to participating cryptographic services |
| `lpacIdentityServices` | Access to participating identity services |

Names must be nonempty strings, at most 256 characters each, without spaces or
control characters. The input list accepts at most 256 entries. Duplicate names
are removed without regard to case; the first spelling and order are retained.
Names persist in saved profiles and appear in logs, dry runs, and config output.

Capabilities add token identities; they do not edit host ACLs. Access rights,
including read versus write, come from the resource ACL and other Windows checks.
`registryRead` is neither a grant to every registry key nor a global read-only
restriction. A write can succeed if the complete access check permits it.
Sandy's per-key `[registry]` grants remain Restricted Token only.

### `[privileges]` — Other process controls

These controls use mechanisms other than capability SIDs. All keys are optional.
Wrong-mode keys are rejected.

| Key | Available in | Default | Description |
|-----|-------------|---------|-------------|
| `loopback` | appcontainer / lpac | `false` | Add a sandbox loopback exemption; requires an administrator and `privateNetworkClientServer` in `names` |
| `desktop` | restricted | `true` | Grant WinSta0 + Desktop access; `false` applies job UI limits to other processes' windows |
| `stdin` | all | `false` | `true` = inherit, `false` = NUL, or an absolute input file path |
| `clipboard_read` | all | `false` | Remove Sandy's clipboard-read job restriction |
| `clipboard_write` | all | `false` | Remove Sandy's clipboard-write job restriction |
| `child_processes` | all | `true` | Allow child processes (kernel-enforced) |

Clipboard switches control job restrictions independently of capabilities such as
`lpacClipboard`. Other Windows access checks still apply.

The [LibreOffice LPAC guide](docs/libreoffice.html) shows how to provide
LibreOffice jobs to AI agents using an existing Sandy executable, an unpacked
LibreOffice runtime, and a dedicated scratch folder. The unrestricted Python
launcher initializes the profile once, generates an explicit `[pipes]` mapping,
and runs the document job inside LPAC. Profile, home, AppData, documents,
temporary data, configuration, and logs are directed into scratch. Sandy cleans
up the sandbox; the launcher removes per-run temporary files and retains the
profile, documents, and logs. The guide includes a complete generated TOML example.

Save the linked launcher and template together, then run from their folder:

```powershell
py -3 .\libreoffice-demo.py --sandy "C:\AgentTools\sandy.exe" --libreoffice "C:\AgentTools\LibreOffice" --scratch "C:\AgentWork\office-job"
```

Private network access with loopback:

```toml
[capabilities]
names = ['privateNetworkClientServer']

[privileges]
loopback = true
```

Omit `loopback` (or set it to `false`) for private network access without
Sandy's loopback exemption. Sandy does not add an implied capability. Its loopback
option requires private-network access; it is not a localhost-only configuration.
Sandy removes run-owned exemptions at exit. Saved-profile exemptions last until
the profile is deleted.

#### AppContainer vs LPAC — App. Packages access

Both modes use the same AppContainer pipeline. The difference is membership in the `ALL APPLICATION PACKAGES` (App. Packages) group:

- **AppContainer** (`token = 'appcontainer'`): includes `ALL APPLICATION PACKAGES` SID, granting read access to system directories (`C:\Windows`, `C:\Program Files`) and other resources whose DACLs allow App. Packages.
- **LPAC** (`token = 'lpac'`): opts out of `ALL APPLICATION PACKAGES`. Access is limited to resources whose DACLs explicitly grant `ALL RESTRICTED APPLICATION PACKAGES` (Restricted App. Packages) — everything else requires explicit `[allow.*]` grants.

> [!TIP]
> Python's Windows installer sets `ALL APPLICATION PACKAGES` on its install directory. With `token = 'appcontainer'`, the Python folder is readable without an explicit `[allow.deep]` entry. With `token = 'lpac'`, you must add it to `[allow.deep]`.

### `[registry]` — Registry key grants *(restricted only)*

Grant read or write access to specific registry keys. Most keys under `HKLM\Software` and `HKCU` are already readable by default via `BUILTIN\Users`.

Each registry path must start with `HKCU\` or `HKLM\`.

```toml
[registry]
read  = ['HKCU\Software\MyApp']
write = ['HKCU\Software\MyApp\Settings']
```

> [!NOTE]
> `[registry]` is not available in AppContainer mode — AppContainer provides a fixed private registry hive automatically.

### `[environment]` — Environment variables

All keys are optional. Default: `inherit = false`, `pass = []` (clean environment with essential Windows variables).

```toml
[environment]
inherit = true            # pass full parent environment
# or:
inherit = false           # clean env + pass list (default)
pass = ['PATH', 'PYTHONPATH', 'HOME']
```

When `inherit = false`, the following essential Windows vars are always passed:

| Category | Variables |
|----------|-----------|
| System | `SYSTEMROOT`, `SYSTEMDRIVE`, `WINDIR`, `OS` |
| Temp | `TEMP`, `TMP` |
| Shell | `COMSPEC`, `PATHEXT` |
| User dirs | `LOCALAPPDATA`, `APPDATA`, `USERPROFILE`, `HOMEDRIVE`, `HOMEPATH` |
| Hardware | `PROCESSOR_ARCHITECTURE`, `NUMBER_OF_PROCESSORS` |

### `[limit]` — Resource constraints

Values must be non-negative integers. Maximums: `timeout` = 86400 seconds,
`memory` = 65536 MB, `processes` = 1024. Zero means no limit.

```toml
[limit]
timeout = 300       # end the whole process tree after N seconds (default: 0)
memory = 4096       # job-wide memory cap in MB (default: 0)
processes = 10      # max total active processes (default: 0)
```

> [!NOTE]
> **The timeout covers the whole process tree.** Sandy waits for the root process and then for every descendant in the job. The watchdog stays active until the tree is gone. On timeout the whole tree is ended and Sandy exits with 130, also when the root process had already exited.

> [!IMPORTANT]
> **Resource limits are strictly enforced (fail-closed).** If a resource limit (memory, process count, or clipboard restriction) is configured but cannot be applied to the job object, Sandy will terminate the child and exit with code 129 (setup error). This includes scenarios where `SetInformationJobObject` fails as well as cases where the job cannot be assigned to the child process. The sandbox never runs with unenforced limits.

> [!NOTE]
> **Effective enforcement visibility.** `--status` reports instance state, transient retry-container metadata, scheduled tasks, AppContainer profiles, and saved profiles, but it is not yet a full structured "requested policy vs effective policy" report. Cleanup parsing errors and best-effort cleanup limitations are logged when encountered.

### Config availability summary

AppContainer and LPAC share the configuration availability and defaults below. Restricted Low and Restricted Medium also share them; `integrity` selects Low or Medium. These groups describe configuration rules, not identical access rights; see [Sandbox Modes](#sandbox-modes).

🟢 Required (choose a listed value) · 🔵 Optional (safe default shown) · 🔴 Unavailable (omit; unsupported values or rules cause a parse error).

| Section / Key | AppContainer / LPAC | Restricted Low / Medium |
|---------------|:--------------------|:------------------------|
| **`[sandbox]`** — setup | 🟢 Required | 🟢 Required |
| &ensp; `token` | 🟢 `'appcontainer'`/`'lpac'` | 🟢 `'restricted'` |
| &ensp; `integrity` | 🔴 Fixed: Low | 🟢 `'low'`/`'medium'` |
| &ensp; `strict` | 🔴 Unavailable | 🔵 Default: `false` |
| &ensp; `workdir` — directory | 🔵 Default: `'inherit'` | 🔵 Default: `'inherit'` |
| **`[allow.deep]`** — recursive | 🔵 Default: `[]` | 🔵 Default: `[]` |
| **`[allow.this]`** — object only | 🔵 Default: `[]` | 🔵 Default: `[]` |
| **`[deny.deep]`** — recursive | 🔴 Unavailable | 🔵 Default: `[]` |
| **`[deny.this]`** — object only | 🔴 Unavailable | 🔵 Default: `[]` |
| **`[pipes]`** — name mapping | 🔵 Default: empty map | 🔴 Unavailable |
| **`[capabilities]`** — SIDs | 🔵 Optional | 🔴 Unavailable |
| &ensp; `names` | 🔵 Default: `[]` | 🔴 Unavailable |
| **`[privileges]`** — controls | 🔵 Optional | 🔵 Optional |
| &ensp; `loopback` | 🔵 Default: `false` | 🔴 Unavailable |
| &ensp; `desktop` | 🔴 Inherited access | 🔵 Default: `true` |
| &ensp; `stdin` | 🔵 Default: `false` (NUL) | 🔵 Default: `false` (NUL) |
| &ensp; `clipboard_read` | 🔵 Default: `false` | 🔵 Default: `false` |
| &ensp; `clipboard_write` | 🔵 Default: `false` | 🔵 Default: `false` |
| &ensp; `child_processes` | 🔵 Default: `true` | 🔵 Default: `true` |
| **`[registry]`** — per-key R/W | 🔴 Unavailable | 🔵 Default: `[]` |
| **`[environment]`** — parent env | 🔵 Optional | 🔵 Optional |
| &ensp; `inherit` — full parent env | 🔵 Default: `false` | 🔵 Default: `false` |
| &ensp; `pass` — extra variables | 🔵 Default: `[]` | 🔵 Default: `[]` |
| **`[limit]`** — resources | 🔵 Default: `0` (unlimited) | 🔵 Default: `0` (unlimited) |

Allow/deny rules grant or deny access to files and folders; “object only” means the named object without recursion. Capability names identify Windows SIDs. R/W means read/write grants. Resource limits cover time, memory and process count.

---

## Sandbox Modes

**AppContainer (AC)** · **LPAC** (Less Privileged AppContainer) · **Restricted Low / Medium** (Restricted Token, RT).

🔒 Fixed for the row · ❌ Blocked · ✅ Allowed · ⚙️ Configurable · ⚠️ May break apps · — Not applicable.

| Aspect | AppContainer | LPAC | Restricted Low | Restricted Medium |
|--------|:------------:|:----:|:--------------:|:-----------------:|
| **Integrity level** 🔒 | Low | Low | Low | Medium |
| **Object namespace** 🔒 | Isolated | Isolated | Shared | Shared |
| **Process identity** 🔒 | AC SID | AC SID | Instance SID&nbsp;⁴ | Instance SID&nbsp;⁴ |
| **Privilege stripping** 🔒 | All | All | All but one&nbsp;⁵ | All but one&nbsp;⁵ |
| **Isolation layers** 🔒 | 2: SID + NS | 2: SID + NS | 2: SIDs + IL | 1: SIDs only |
| **Elevation** | ❌ | ❌ | ❌ | ❌ |
| **Named pipes** | `LOCAL`&nbsp;⁶ | `LOCAL`&nbsp;⁶ | ✅ | ✅ |
| **Desktop access** | Inherited | Inherited | ⚙️ | ⚙️ |
| **Network** | ⚙️&nbsp;⁷ | ⚙️&nbsp;⁷ | ✅ | ✅ |
| **App. Packages access** | Included | Excluded&nbsp;¹ | — | — |
| **System dir reads** | Via APP&nbsp;¹ | Via ARAP&nbsp;¹ | ✅ | ✅ |
| **System dir writes** | ❌ | ❌ | ❌ | ❌ |
| **User profile reads** | ⚙️ | ⚙️ | ✅ | ✅ |
| **User profile writes** | ⚙️ | ⚙️ | ⚙️&nbsp;² | ✅ |
| **Registry reads** | ACL‑limited&nbsp;⁷ | ACL‑limited&nbsp;⁷ | ✅ | ✅ |
| **Registry HKCU writes** | ACL-based&nbsp;⁷ | ACL-based&nbsp;⁷ | ❌ | ✅ |
| **Registry HKLM writes** | ❌ | ❌ | ❌ | ❌ |
| **DLL/API set resolution** | ✅ | ⚠️&nbsp;³ | ⚠️ | ✅ |
| **COM/RPC servers** | Per server&nbsp;⁷ | ⚙️ Opt‑in&nbsp;⁷ | ✅ | ✅ |
| **Scheduled tasks** | ❌ | ❌ | ❌ | ✅ |
| **Window messages (UIPI)** | ❌ | ❌ | ❌ | ✅ |
| **Clipboard R/W** | ⚙️ | ⚙️ | ⚙️ | ⚙️ |
| **Child processes** | ⚙️ | ⚙️ | ⚙️ | ⚙️ |
| **Stdin** | ⚙️ | ⚙️ | ⚙️ | ⚙️ |
| **Environment** | ⚙️ | ⚙️ | ⚙️ | ⚙️ |
| **File/folder grants** | ⚙️ | ⚙️ | ⚙️ | ⚙️ |
| **Resource limits** | ⚙️ | ⚙️ | ⚙️ | ⚙️ |

**Controls:** Desktop, clipboard read/write, child processes and stdin use `[privileges]` keys `desktop`, `clipboard_read` / `clipboard_write`, `child_processes` and `stdin`. Environment uses `[environment] inherit`; file/folder and user-profile grants use `[allow.*]`; resource limits use `[limit]`. **NS** = object namespace; **IL** = integrity level.

¹ **APP** = `ALL APPLICATION PACKAGES` (`S-1-15-2-1`); **ARAP** = `ALL RESTRICTED APPLICATION PACKAGES` (`S-1-15-2-2`). LPAC opts out of APP. Windows system directories (`C:\Windows`, `System32`, `Program Files`) carry ARAP ACEs on Win10+ and are readable by LPAC. However, user-installed application directories (e.g. Python under `AppData\Local\Programs`) typically carry only the APP ACE without ARAP, making them invisible to LPAC unless explicitly granted via `[allow.*]`.

² Restricted Low writes to medium-integrity folders (most of `C:\Users`) are blocked by mandatory integrity even with `[allow.*]` grants. Use `AppData\LocalLow` or Restricted Medium for user profile writes.

³ LPAC DLLs from system directories resolve normally (ARAP ACEs present). DLLs loaded from user-installed application paths may fail because those paths lack ARAP ACEs — the app needs explicit `[allow.*]` execute grants for those directories.

⁴ RT uses a per-instance SID in the token’s restricting list.

⁵ Restricted Token retains `SeChangeNotify`; all other privileges are stripped.

⁶ AppContainer and LPAC use `LOCAL` pipe names. Optional `[pipes]` mappings adapt an app's fixed names within the [documented interception limits](docs/config.html#pipes).

⁷ **Network:** AC/LPAC use `[capabilities] names` plus `[privileges] loopback`. **Registry:** `registryRead` is opt-in; reads remain ACL-limited, HKCU writes depend on ACLs, and Sandy provides no per-key grants in AC/LPAC. **COM:** AppContainer can access permitted COM objects by default; LPAC needs `lpacCom` in `[capabilities] names`. Server permissions still apply in all modes. See [Microsoft's AppContainer overview](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer#appcontainer-overview).

**Use AppContainer** when you need network isolation with broad system-directory access. COM access remains subject to server permissions; fixed pipe names can use `[pipes]` within the limits above.

**Use LPAC** when you want AppContainer isolation with minimum default access — only explicitly granted resources are reachable.

**Use Restricted Token** when the app needs general named-pipe compatibility (Flutter, Chromium, Mojo), broader COM/RPC compatibility, or Medium integrity.

### Examples

AppContainer with network access:

```toml
[sandbox]
token = 'appcontainer'

[allow.deep]
read = ['C:\Python314', 'C:\projects\my_agent']
all = ['C:\workspace']

[capabilities]
names = ['internetClient']

[privileges]
loopback = false
stdin = false
clipboard_read = false
clipboard_write = false
child_processes = true

[environment]
inherit = false
pass = ['PATH']

[limit]
timeout = 300
memory = 2048
processes = 0
```

```
sandy.exe -c agent_config.toml -x C:\Python314\python.exe agent.py
```

Restricted Token with medium integrity (named pipes are always available in this mode):

```toml
[sandbox]
token = 'restricted'
integrity = 'medium'

[allow.deep]
read = ['C:\Python314', 'C:\projects\my_agent']
all = ['C:\workspace']

[privileges]
desktop = true
stdin = false
clipboard_read = false
clipboard_write = false
child_processes = true

[environment]
inherit = true

[registry]
write = ['HKCU\Software\MyApp\Settings']

[limit]
timeout = 300
memory = 0
processes = 0
```

---

## Logging

Session logs (`-l`) write to the path you specify — relative paths resolve against the current working directory (standard POSIX behavior).

**Early logger initialization:** The logger starts immediately after CLI argument parsing — before config loading — so config parser warnings (e.g. duplicate paths) are captured in the log file.

**Console passthrough:** The child process inherits the parent's console handles directly (real TTY). Sandy does **not** interpose on stdout/stderr. This means interactive CLI tools (REPLs, Claude Code, etc.) work correctly with TTY detection, colors, and terminal features. To capture child output to a file, use standard shell redirection: `sandy ... -x myapp > output.log 2>&1`.

**Log content:** The session log holds Sandy's own events only: config, grants, timing, exit code, cleanup. It never holds child output. The child does not inherit the log handle and cannot write to the log.

**Log rotation:** The path you give always holds the **newest** session. If the file already exists and `--log-stamp` is *not* used, Sandy first moves the old file to the next free numbered name:

```
session.log      newest session
session.log.1    oldest session
session.log.2    next oldest, ...
```

**Timestamped logs:** Use `-L` / `--log-stamp` to prepend a unique `YYYYMMDD_HHMMSS_uid_` prefix to log filenames. The 4-hex UID prevents collisions when multiple runs start in the same second:

```
sandy.exe -c config.toml -L -l session.log -x myapp.exe
→ 20260305_105426_a3f1_session.log
```

All log timestamps use **local time with ISO 8601 UTC offset** (e.g. `2026-03-05T10:54:26.123+01:00`).

**Error diagnostics:** When ACL operations fail, Sandy logs the exact Win32 error code and its human-readable description — e.g. `FAILED (0x00000005: Access is denied)`. This applies to file grants, deny rules, and registry grants.

**Pre-launch token validation (Restricted Token mode):** Before launching the child process, Sandy verifies the restricted token's integrity level matches the configured value (`low` = `0x1000`, `medium` = `0x2000`). If the check fails, Sandy aborts with exit code 129 and logs `TOKEN_VALIDATE: FAILED`.

---

## Profiles

Sandy treats **persistent named profiles** as a first-class execution model. A profile is a durable sandbox identity with its own SID, AppContainer or restricted-token metadata, and persistent grants. Transient `-c` / `-s` runs are the lightweight one-shot variant over the same pipeline.

### Lifecycle

1. **Create** a profile from a TOML config:
   ```
   sandy.exe --create-profile myapp -c myapp_config.toml
   ```
   Sandy generates a SID, applies all ACLs (file grants, deny rules, and registry grants for restricted profiles), and persists everything to `HKCU\Software\Sandy\Profiles\myapp`. ACLs remain on disk permanently. If any grant fails, creation is aborted and partial state is rolled back on next startup.

2. **Run** with the profile (no config needed):
   ```
   sandy.exe -p myapp -x python.exe script.py
   ```
   Sandy reuses the stored identity and config — no ACL setup, no ACL teardown on exit. The `-p` flag is mutually exclusive with `-c`/`-s`.

3. **Inspect** a profile:
   ```
   sandy.exe --profile-info myapp
   ```

4. **Delete** when no longer needed:
   ```
   sandy.exe --delete-profile myapp
   ```
   Revokes all persistent ACLs and removes the SID.

> [!NOTE]
> `--cleanup` does **not** delete saved profiles or their ACLs. It only repairs incomplete staging and stale transient state. Only `--delete-profile` removes a profile. `--status` lists all saved profiles.

---

## Notes

> [!WARNING]
> **AppContainer vs LPAC isolation.** AppContainer mode includes the `ALL APPLICATION PACKAGES` SID, giving read access to system directories and resources whose DACLs allow App. Packages. LPAC mode opts out — access is limited to `ALL RESTRICTED APPLICATION PACKAGES` resources and explicit `[allow.*]` grants. Most executables need system DLLs, so use `token = 'appcontainer'` unless you need strict isolation. In Restricted Token mode, system directories are always readable.

> [!NOTE]
> **Localhost access** (AppContainer / LPAC) requires an administrator to add the exemption, plus `names = ['privateNetworkClientServer']` in `[capabilities]` and `loopback = true` in `[privileges]`. Sandy uses `CheckNetIsolation.exe` (resolved from `System32` to prevent search-order hijacking) to manage a per-instance loopback exemption (matching the AppContainer's unique `Sandy_<UUID>` profile name). Loopback always implies LAN access — there is no localhost-only capability in the Windows AppContainer model.

> [!NOTE]
> **Sandy stderr banner.** Sandy prints a config summary to stderr before running. Use `-q` to suppress it in automation pipelines where stderr is captured.

> [!NOTE]
> **Sandy runs without elevation in most cases.** It modifies folder ACLs to grant the sandbox access, which requires `WRITE_DAC` permission on each configured folder. Users have this permission on folders they own (e.g. under `%USERPROFILE%`). For folders owned by `SYSTEM`, `TrustedInstaller`, or other users, Sandy must be run as Administrator.

---

## Cleanup &amp; Crash Resilience

Sandy never leaves system state dirty. Five run-scoped resources are tracked and cleaned regardless of how the process exits:

| Resource | Created by | Persistence |
|----------|-----------|-------------|
| **ACL grants** | `[allow.*]` / `[deny.*]` folder/file grants, desktop access | `HKCU\Software\Sandy\Grants\<UUID>` (TYPE\|PATH\|SID per grant, written before the DACL changes) |
| **Registry persistence** | Grant write-ahead log | Same key (cleared with ACLs) |
| **Loopback exemption** | `loopback = true` | In-memory flag + `CheckNetIsolation.exe` |
| **AppContainer profile** | Container creation | OS-managed (`Sandy_<UUID>`) — unique per instance |
| **Scheduled task** | Crash safety net | Task Scheduler (`SandyCleanup_<UUID>`) — one per instance |

### Exit scenarios

| Scenario | ACLs | Loopback | AppContainer | Sched. Task | Registry | Mechanism |
|----------|:----:|:--------:|:------------:|:-----------:|:--------:|-----------|
| **Clean exit** | ✅ | ✅ | ✅ | ✅ | ✅ | Normal cleanup at the end of `RunSandboxed` |
| **Child crash** | ✅ | ✅ | ✅ | ✅ | ✅ | Same — child exit doesn't affect Sandy |
| **Timeout** | ✅ | ✅ | ✅ | ✅ | ✅ | Watchdog ends the whole process tree → normal cleanup → exit 130 |
| **Ctrl+C / Ctrl+Break** | ✅ | ✅ | ✅ | ✅ | ✅ | Signal handler ends the child tree → the main thread runs the normal cleanup → exit `0xC000013A` |
| **Sandy crash (SEH)** | ✅ | ✅ | ✅ | ✅ | ✅ | `__except` handler → terminates child first → `CleanupSandbox()` |
| **Console close** | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | Windows allows about 5 seconds: Sandy ends the child tree; recovery (see below) does the rest |
| **Power loss / taskkill** | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | Recovery: the next Sandy start, `sandy.exe --cleanup`, or the scheduled task at logon |

✅ cleaned before Sandy exits · ⏳ cleaned by recovery

### How it works

1. **Write-ahead logging:** Before modifying any ACL, Sandy persists each grant as `TYPE|PATH|SID[|DENY:1][|THIS:1][|OWNER:I|OWNER:O]` to `HKCU\Software\Sandy\Grants\<UUID>`. The subkey also stores `_pid` (for liveness checks), `_container` (AppContainer profile name) and `_desktop_sid` (desktop access of a restricted-token run). The recovery ledger is written *before* the system state is modified: a kill at any moment leaves a record for every ACE that exists. If a kill cut a recursive grant short, recovery re-propagates inheritance from the root of the rule, so no descendant keeps an ACE of the dead run.

2. **Scheduled task safety net:** A per-instance `SandyCleanup_<UUID>` scheduled task is created to run `sandy.exe --cleanup` at next logon — for both normal and profile-mode (`-p`) runs. It only fires if Sandy didn't clean up normally (crash/power loss). Deleted on clean exit. Sandy registers the task for the current user through the Task Scheduler API; no elevation is needed.

3. **Multi-instance safety:** Transient runs use unique SIDs; saved profiles reuse their durable SID. Runs have separate UUIDs and liveness records. Cleanup removes only the owning identity's ACEs via `RemoveSidFromDaclDetailed`. A profile's grants remain until profile deletion, which is refused while a run still uses that profile.

   > **For agents and automation:** Multiple Sandy instances can safely run concurrently with overlapping folder grants. Each instance's sandbox is fully isolated. Use `--status` to inspect active instances and `--cleanup` to clear any stale state.

4. **Start-up recovery:** Each Sandy start first cleans the state of dead instances (grants, desktop ACEs, containers, tasks). Sandy writes what it recovered to the session log, not to the console: the child's output stream stays clean. If state remains that Sandy could not recover, it warns on stderr (when no session log is active):
   ```
   [Sandy] WARNING: Stale or incomplete recovery metadata detected.
           Grants: 1 stale, 0 incomplete (0 active) under HKCU\Software\Sandy\Grants
           Containers: 0 stale, 0 incomplete (0 active) under HKCU\Software\Sandy\TransientContainers
           Run 'sandy.exe --cleanup' to restore original state.
   ```

5. **Liveness-gated cleanup:** `--cleanup` and startup cleanup correlate every transient AppContainer profile with the owning Sandy instance's PID and creation time before taking destructive action. Only resources belonging to dead instances are cleaned. Live instances retain their loopback exemptions and AppContainer profiles. Stale cleanup is **path+SID-precise**: when two instances share a path but use different SIDs, only the dead instance's ACEs are cleaned while the live instance's are preserved. Saved profiles (created via `--create-profile`) are permanently protected and never cleaned as stale. The system helper process `CheckNetIsolation.exe` is launched from its fully-qualified `System32` path to prevent search-order hijacking.

### Cleanup guarantees

| Guarantee | Mechanism |
|-----------|-----------|
| **ACL grants restored** on clean exit | `RemoveSidFromDaclDetailed` per path and SID |
| **ACE-level cleanup** | Sandy preserves other identities' explicit ACEs and DACL protection. Windows recomputes inherited ACEs on DACL writes: a moved file can lose ACEs inherited from its former parent. Windows can also set the auto-inherited flag |
| **Registry grants cleared** on clean exit | `RegDeleteTreeW` on instance subkey |
| **Loopback exemption removed** on clean exit | `CheckNetIsolation.exe LoopbackExempt -d` |
| **Scheduled task deleted** on clean exit | Task Scheduler API |
| **Stale ACLs restored** after crash | `--cleanup` parses persisted `TYPE|PATH|SID` records, removes SID's ACEs |
| **Parent registry keys permanent** | `Software\Sandy`, `Grants`, and `Profiles` are never deleted — preserved for visual tracking |

**Best-effort behaviors** (not guaranteed):
- **Desktop/window-station ACL cleanup** depends on `GetProcessWindowStation()` and `OpenDesktopW()` succeeding — these may fail in service or headless contexts. Failures are logged with error codes. The desktop access of a run is recorded in its ledger, so recovery also removes these ACEs after a kill.
- **Loopback cleanup** depends on `CheckNetIsolation.exe` being available and the process running with sufficient privileges.
- **Persisted grant records** that are malformed (invalid TYPE, empty PATH, non-SID strings, or unknown flags) are skipped and logged — they will not cause cleanup to fail or corrupt system state.

### Validation notes

- Desktop/window-station ACL cleanup is now SID-targeted rather than snapshot-based, which is much safer for multi-instance use.
- This area remains operationally sensitive because it rebuilds ACLs on real host window objects; targeted repeated-grant, overlapping-instance, and crash-cleanup validation remains recommended.

### Status output notes

- `--status` prints instance state, transient retry-container state, cleanup-task ownership state, Sandy AppContainer profiles, and saved profiles.
- `--status --json` includes a top-level `summary` object with counts for instances, retry containers, retained/orphaned cleanup tasks, profiles, and saved profiles.

> [!IMPORTANT]
> If Sandy is killed via `taskkill /F` or power is lost, run `sandy.exe --cleanup` manually or wait for the next logon (the scheduled task handles it automatically).

---

## Building

Sandy needs one header-only library at build time: [toml11](https://github.com/ToruNiina/toml11). Put it next to the Sandy folder, so that `..\toml11\include` exists. There is no other dependency, and the built `sandy.exe` needs no runtime.

Open `sandy.sln` in Visual Studio and build the `x64 Release` configuration, or use MSBuild:

```
& 'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe' sandy.sln /p:Configuration=Release /p:Platform=x64 /v:minimal
```

The output is `x64\Release\sandy.exe`.

## License

[MIT](LICENSE)
