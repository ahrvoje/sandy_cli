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

## Quick Start

```
sandy.exe --print-container-toml > myconfig.toml     # generate template
sandy.exe --dry-run -c myconfig.toml -x python.exe   # validate config (no changes)
sandy.exe -c myconfig.toml -x python.exe script.py   # run sandboxed
sandy.exe --status                                   # check active instances
sandy.exe --cleanup                                  # fix stale state
sandy.exe --explain 131                              # decode exit code
```

## What is Sandy?

Sandy launches executables inside a kernel-enforced Windows sandbox — no elevation required. Three isolation modes are supported: [AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation) (App. Packages — the same technology used by UWP apps and Edge), **LPAC** (Restricted App. Packages — stricter AppContainer with explicit-grant-only access), and **Restricted Token** (restricting SIDs with configurable integrity level). The sandbox uses an explicit TOML model with safe, locked-down defaults for any omitted settings.

No VMs, Docker, WSL, or Hyper-V — just a single native executable. Sandy is lean, unprivileged sandboxing for agentic AI workflows, automation scripts, and tool-use pipelines: you define exactly which folders, files, and network access the process gets.

### Key Features

- 🔒 **Three sandbox modes** — AppContainer, LPAC, or Restricted Token with configurable integrity
- 📁 **Granular access control** — read, write, execute, append, delete, or full access per file or folder
- 🌐 **Network control** — internet and LAN/localhost configurable via unified `lan` key (AppContainer)
- 🏢 **Multi-instance safe** — true isolation with independent instance-specific grants
- 💾 **Profile-first design** — persistent sandbox identities with reusable grants and config
- 🛡️ **Explicit configuration** — uses a TOML model with strictly safe, locked-down defaults for omissions
- ⏱️ **Resource limits** — timeout, memory cap, and process count limits
- 📝 **Operational logging** — session logs and cleanup diagnostics
- 🔄 **Dynamic reload** — live config monitoring, applies only grant deltas while the sandbox runs
- ⚡ **Zero dependencies** — single native executable, no runtime needed

---

## Usage

```
sandy.exe -c <config.toml> [-y] [-l <logfile>] [-L] [-q] -x <executable> [args...]
sandy.exe -s "<toml>"      [-l <logfile>] [-L] [-q] -x <executable> [args...]
sandy.exe -p <profile>     [-l <logfile>] [-q] -x <executable> [args...]
sandy.exe --create-profile <name> -c <config.toml>  (create persistent sandbox profile)
sandy.exe --delete-profile <name>                   (delete profile + revoke ACLs)
sandy.exe --profile-info <name>                     (show profile details)
sandy.exe --print-container-toml          (print default appcontainer config)
sandy.exe --print-restricted-toml         (print default restricted config)
sandy.exe --cleanup                       (restore stale state from crashed runs)
sandy.exe --status [--json]                (show active instances and stale state)
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
| `-q`, `--quiet` | Suppress the config banner on stderr |
| `-v`, `--version` | Print version |
| `-h`, `--help` | Print full help text with config reference |
| `--print-container-toml` | Print default AppContainer config to stdout |
| `--print-restricted-toml` | Print default Restricted Token config to stdout |
| `--cleanup` | Restore stale state from crashed runs (liveness-gated: preserves live instances) |
| `--status [--json]` | Show active instances, stale state, saved profiles, and summary counts |
| `--json` | JSON output (with `--status`, includes summary counts) |
| `--explain <code>` | Decode exit code (Sandy 125-131, NTSTATUS, Win32) |
| `--dry-run`, `--check` | Validate config + show planned changes (no system modifications). Also supported with `--create-profile` to preview what would be created. |
| `--print-config` | Print resolved config to stdout (requires `-c`/`-s`) |
| `-y`, `--dynamic` | Live config reload: polls config file every 2s, applies only grant deltas (added/removed). Deny interactions handled correctly. Requires `-c` |

All sandy flags must come **before** `-x`. Arguments after `-x <executable>` are forwarded to it.

### Exit codes

Sandy follows the POSIX high-code convention used by `bash`, `env`, `timeout`, and `git bisect`. Child exit codes 0-124 pass through with zero ambiguity.

| Code | Meaning |
|:----:|---------|
| `0` | Success — child exited cleanly, or info command succeeded |
| `1`-`124` | Child's exit code (passed through unchanged) |
| `125` | Sandy internal / general error |
| `126` | Cannot execute — `CreateProcess` failed (permission denied, bad format) |
| `127` | Command not found — executable does not exist on disk |
| `128` | Configuration error — invalid TOML, wrong-mode keys, config file not found |
| `129` | Sandbox setup failed — token/SID creation, ACL grants, or stdin setup |
| `130` | Timeout — child killed by Sandy's timeout watchdog |
| `131` | Child crashed — NTSTATUS crash code detected (e.g. `0xC0000005`) |

> [!TIP]
> In automation scripts, check for `exit code >= 125` to detect Sandy-level errors. Codes 130 and 131 indicate the child ran but terminated abnormally.

---

## Config File

All sandbox behavior is controlled by a TOML config. Every config **must** include a `[sandbox]` section declaring the token mode. Use `-c` or `-s` (mutually exclusive). Mode-specific settings are validated — using a flag meant for the other mode is an error. All paths must be absolute and must exist on disk (non-existent paths are rejected as config errors).

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
workdir = 'C:\projects'   # child working directory (default: inherit Sandy's current working directory)
```

| Key | Values | Modes | Description |
|-----|--------|-------|-------------|
| `token` | `'appcontainer'`, `'lpac'`, `'restricted'` | all | Sandbox isolation model *(required)* |
| `integrity` | `'low'`, `'medium'` | restricted | Integrity level *(required)* · `'low'` = strongest isolation, `'medium'` = wider app compatibility |
| `strict` | `true`, `false` | restricted | Exclude user SID from restricting list · Default: `false`. When `true`, user-owned resources require explicit `[allow.*]` grants |
| `workdir` | path | both | Child process working directory (default: `'inherit'` — Sandy's current working directory) |

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
read    = ['C:\', 'C:\Users', 'C:\Users\H']    # directory listing only
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

#### Allow-inside-deny (depth-sorted pipeline)

Sandy supports carving out allowed subtrees from within denied areas. When an allow path is under a deny path, Sandy automatically strips the deny ACEs from the allowed subtree before granting access.

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
    ALLOW [STAT   ] C:\repos            <- strip deny (dir only)
    ALLOW [ALL    ] C:\repos\snipps     <- strip deny (subtree)
```

> [!TIP]
> **Common pattern:** Deny `all` on a broad directory, then allow specific subdirectories. The most specific (deepest) path always wins.

### `[privileges]` — Permissions

All keys are optional with safe defaults (shown below). Wrong-mode keys are rejected.

```toml
# AppContainer / LPAC mode — defaults shown:
[privileges]
network         = false              # default: false
lan             = false              # false | true | 'with localhost' | 'without localhost'
stdin           = false              # default: false (NUL)
clipboard_read  = false              # default: false
clipboard_write = false              # default: false
child_processes = true               # default: true

# Restricted mode — defaults shown:
[privileges]
named_pipes     = false   # default: false
desktop         = true    # default: true (WinSta0 + Desktop access)
stdin           = false   # default: false (NUL)
clipboard_read  = false   # default: false
clipboard_write = false   # default: false
child_processes = true    # default: true
```

| Key | Available in | Default | Description |
|-----|-------------|---------|-------------|
| `network` | appcontainer / lpac | `false` | Outbound internet access |
| `lan` | appcontainer / lpac | `false` | `false` • `true`/`'without localhost'` • `'with localhost'` — LAN and loopback control (see below) |
| `named_pipes` | restricted | `false` | Named pipe creation (`CreateNamedPipeW`) |
| `desktop` | restricted | `true` | Grant WinSta0 + Desktop access for interactive use |
| `stdin` | all | `false` | `true` = inherit, `false` = disabled (NUL), or a file path |
| `clipboard_read` | all | `false` | Allow reading from the clipboard |
| `clipboard_write` | all | `false` | Allow writing to the clipboard |
| `child_processes` | all | `true` | Allow spawning child processes (kernel-enforced) |

**`lan` key values:**

| Value | LAN | Localhost | Notes |
|-------|:---:|:---------:|-------|
| `false` | ❌ | ❌ | Default — no private network |
| `true` | ✅ | ❌ | LAN only (backward compat alias for `'without localhost'`) |
| `'without localhost'` | ✅ | ❌ | LAN access, loopback blocked |
| `'with localhost'` | ✅ | ✅ | LAN + loopback (requires admin for `CheckNetIsolation`) |

> [!NOTE]
> Loopback always implies LAN. Windows does not offer a localhost-only capability — the `privateNetworkClientServer` capability required for loopback also grants LAN. Sandy makes this explicit by combining both into one key.

#### AppContainer vs LPAC — App. Packages access

Both modes use the same AppContainer pipeline. The difference is membership in the `ALL APPLICATION PACKAGES` (App. Packages) group:

- **AppContainer** (`token = 'appcontainer'`): includes `ALL APPLICATION PACKAGES` SID, granting read access to system directories (`C:\Windows`, `C:\Program Files`) and other resources whose DACLs allow App. Packages.
- **LPAC** (`token = 'lpac'`): opts out of `ALL APPLICATION PACKAGES`. Access is limited to resources whose DACLs explicitly grant `ALL RESTRICTED APPLICATION PACKAGES` (Restricted App. Packages) — everything else requires explicit `[allow.*]` grants.

> [!TIP]
> Python's Windows installer sets `ALL APPLICATION PACKAGES` on its install directory. With `token = 'appcontainer'`, the Python folder is readable without an explicit `[allow.deep]` entry. With `token = 'lpac'`, you must add it to `[allow.deep]`.

### `[registry]` — Registry key grants *(restricted only)*

Grant read or write access to specific registry keys. Most keys under `HKLM\Software` and `HKCU` are already readable by default via `BUILTIN\Users`.

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

```toml
[limit]
timeout = 300       # kill process after N seconds (default: 0)
memory = 4096       # job-wide memory cap in MB (default: 0)
processes = 10      # max total active processes (default: 0)
```

> [!IMPORTANT]
> **Resource limits are strictly enforced (fail-closed).** If a resource limit (memory, process count, or clipboard restriction) is configured but cannot be applied to the job object, Sandy will terminate the child and exit with code 129 (setup error). This includes scenarios where `SetInformationJobObject` fails as well as cases where the job cannot be assigned to the child process. The sandbox never runs with unenforced limits.

> [!NOTE]
> **Effective enforcement visibility.** `--status` reports active and stale instances, scheduled tasks, AppContainer profiles, and saved profiles, but it is not yet a full structured "requested policy vs effective policy" report. Cleanup parsing errors and best-effort cleanup limitations are logged when encountered.

### Config availability summary

| Section / Key | AppContainer | LPAC | Restricted |
|---------------|:-------------|:-----|:-----------|
| **`[sandbox]`** | 🟢 required | 🟢 required | 🟢 required |
| &ensp; `token` | 🟢 required | 🟢 required | 🟢 required |
| &ensp; `integrity` | 🔴 n/a | 🔴 n/a | 🟢 required (`'low'` or `'medium'`) |
| &ensp; `strict` | 🔴 n/a | 🔴 n/a | 🔵 default: `false` |
| &ensp; `workdir` | 🔵 default: `'inherit'` | 🔵 default: `'inherit'` | 🔵 default: `'inherit'` |
| **`[allow.deep]`** | 🔵 default: `[]` | 🔵 default: `[]` | 🔵 default: `[]` |
| **`[allow.this]`** | 🔵 default: `[]` | 🔵 default: `[]` | 🔵 default: `[]` |
| **`[deny.deep]`** | 🔴 n/a | 🔴 n/a | 🔵 default: `[]` |
| **`[deny.this]`** | 🔴 n/a | 🔴 n/a | 🔵 default: `[]` |
| **`[privileges]`** | 🔵 optional | 🔵 optional | 🔵 optional |
| &ensp; `network` | 🔵 default: `false` | 🔵 default: `false` | 🔴 n/a |
| &ensp; `lan` | 🔵 default: `false` | 🔵 default: `false` | 🔴 n/a |
| &ensp; `named_pipes` | 🔴 n/a | 🔴 n/a | 🔵 default: `false` |
| &ensp; `desktop` | 🔴 n/a | 🔴 n/a | 🔵 default: `true` |
| &ensp; `stdin` | 🔵 default: `false` | 🔵 default: `false` | 🔵 default: `false` |
| &ensp; `clipboard_read` | 🔵 default: `false` | 🔵 default: `false` | 🔵 default: `false` |
| &ensp; `clipboard_write` | 🔵 default: `false` | 🔵 default: `false` | 🔵 default: `false` |
| &ensp; `child_processes` | 🔵 default: `true` | 🔵 default: `true` | 🔵 default: `true` |
| **`[registry]`** | 🔴 n/a | 🔴 n/a | 🔵 default: `[]` |
| **`[environment]`** | 🔵 optional | 🔵 optional | 🔵 optional |
| &ensp; `inherit` | 🔵 default: `false` | 🔵 default: `false` | 🔵 default: `false` |
| &ensp; `pass` | 🔵 default: `[]` | 🔵 default: `[]` | 🔵 default: `[]` |
| **`[limit]`** | 🔵 default: `0` | 🔵 default: `0` | 🔵 default: `0` |

🟢 required · 🔵 optional (safe default) · 🔴 not available (parse error if used)

---

## Sandbox Modes

Merged view across AppContainer, LPAC, and Restricted Token (Low / Medium integrity).

| Aspect | AppContainer | LPAC | Restricted Low | Restricted Medium |
|--------|:------------:|:----:|:--------------:|:-----------------:|
| **Integrity level** | 🔒 Low | 🔒 Low | 🔒 Low | 🔒 Medium |
| **Object namespace** | 🔒 Isolated | 🔒 Isolated | 🔒 Shared | 🔒 Shared |
| **Process identity** | 🔒 AppContainer SID | 🔒 AppContainer SID | 🔒 Per-instance SID restricted | 🔒 Per-instance SID restricted |
| **Elevation** | ❌ Blocked | ❌ Blocked | ❌ Blocked | ❌ Blocked |
| **Privilege stripping** | 🔒 All stripped | 🔒 All stripped | 🔒 All except SeChangeNotify | 🔒 All except SeChangeNotify |
| **Isolation layers** | 🔒 2: SID + namespace | 🔒 2: SID + namespace | 🔒 2: SIDs + integrity | 🔒 1: SIDs only |
| **Named pipes** | ❌ Blocked | ❌ Blocked | ⚙️ `named_pipes` | ⚙️ `named_pipes` |
| **Desktop access** | ✅ Inherited | ✅ Inherited | ⚙️ `desktop` | ⚙️ `desktop` |
| **Network** | ⚙️ `network` `lan` | ⚙️ `network` `lan` | ✅ Allowed | ✅ Allowed |
| **App. Packages access** | ✅ Included | ❌ Excluded ¹ | n/a | n/a |
| **System dir reads** | ✅ Via App. Packages | ✅ Via Restricted App. Packages ¹ | ✅ Allowed | ✅ Allowed |
| **System dir writes** | ❌ Blocked | ❌ Blocked | ❌ Blocked | ❌ Blocked |
| **User profile reads** | ⚙️ `[allow.*]` | ⚙️ `[allow.*]` | ✅ Allowed | ✅ Allowed |
| **User profile writes** | ⚙️ `[allow.*]` | ⚙️ `[allow.*]` | ⚙️ `[allow.*]` ² | ✅ Allowed |
| **Registry reads** | ✅ Private hive | ✅ Private hive | ✅ Allowed | ✅ Allowed |
| **Registry HKCU writes** | ❌ Blocked | ❌ Blocked | ❌ Blocked | ✅ Allowed |
| **Registry HKLM writes** | ❌ Blocked | ❌ Blocked | ❌ Blocked | ❌ Blocked |
| **DLL/API set resolution** | ✅ Allowed | ⚠️ May break apps ³ | ⚠️ May break apps | ✅ Allowed |
| **COM/RPC servers** | ❌ Blocked | ❌ Blocked | ✅ Allowed | ✅ Allowed |
| **Scheduled tasks** | ❌ Blocked | ❌ Blocked | ❌ Blocked | ✅ Allowed |
| **Window messages (UIPI)** | ❌ Blocked | ❌ Blocked | ❌ Blocked | ✅ Allowed |
| **Clipboard** | ⚙️ `clipboard_read/write` | ⚙️ `clipboard_read/write` | ⚙️ `clipboard_read/write` | ⚙️ `clipboard_read/write` |
| **Child processes** | ⚙️ `child_processes` | ⚙️ `child_processes` | ⚙️ `child_processes` | ⚙️ `child_processes` |
| **Stdin** | ⚙️ `stdin` | ⚙️ `stdin` | ⚙️ `stdin` | ⚙️ `stdin` |
| **Environment** | ⚙️ `inherit` | ⚙️ `inherit` | ⚙️ `inherit` | ⚙️ `inherit` |
| **File/folder grants** | ⚙️ `[allow.*]` | ⚙️ `[allow.*]` | ⚙️ `[allow.*]` | ⚙️ `[allow.*]` |
| **Resource limits** | ⚙️ `[limit]` | ⚙️ `[limit]` | ⚙️ `[limit]` | ⚙️ `[limit]` |

🔒 fixed · ❌ blocked · ✅ allowed · ⚙️ configurable · ⚠️ warning

¹ LPAC opts out of `ALL APPLICATION PACKAGES` (`S-1-15-2-1`). Windows system directories (`C:\Windows`, `System32`, `Program Files`) carry `ALL RESTRICTED APPLICATION PACKAGES` (`S-1-15-2-2`) ACEs on Win10+ and are readable by LPAC. However, user-installed application directories (e.g. Python under `AppData\Local\Programs`) typically carry only the APP ACE without ARAP, making them invisible to LPAC unless explicitly granted via `[allow.*]`.
² Restricted Low writes to medium-integrity folders (most of `C:\Users`) are blocked by mandatory integrity even with `[allow.*]` grants. Use `AppData\LocalLow` or Restricted Medium for user profile writes.
³ LPAC DLLs from system directories resolve normally (ARAP ACEs present). DLLs loaded from user-installed application paths may fail because those paths lack ARAP ACEs — the app needs explicit `[allow.*]` execute grants for those directories.

**Use AppContainer** when you need network isolation with broad system-directory access and don't require named pipes or COM.

**Use LPAC** when you want AppContainer isolation with minimum default access — only explicitly granted resources are reachable.

**Use Restricted Token** when the sandboxed app needs named pipes (Flutter, Chromium, Mojo) or COM/RPC.

### Examples

AppContainer with network access:

```toml
[sandbox]
token = 'appcontainer'

[allow.deep]
read = ['C:\Python314', 'C:\projects\my_agent']
all = ['C:\workspace']


[privileges]
network = true
lan = false
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

Restricted Token with pipes and medium integrity:

```toml
[sandbox]
token = 'restricted'
integrity = 'medium'

[allow.deep]
read = ['C:\Python314', 'C:\projects\my_agent']
all = ['C:\workspace']


[privileges]
named_pipes = true
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

**Log rotation:** If the target file already exists and `--log-stamp` is *not* used, Sandy automatically rotates with POSIX-style numbered suffixes:

```
session.log → session.log.1 → session.log.2 → ...
```

**Timestamped logs:** Use `-L` / `--log-stamp` to prepend a unique `YYYYMMDD_HHMMSS_uid_` prefix to log filenames. The 4-hex UID prevents collisions when multiple runs start in the same second:

```
sandy.exe -L -l session.log -x myapp.exe
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
> **Localhost access** (AppContainer only) requires administrator privileges and is enabled by setting `lan = 'with localhost'`. Sandy uses `CheckNetIsolation.exe` (resolved from `System32` to prevent search-order hijacking) to manage a per-instance loopback exemption (matching the AppContainer's unique `Sandy_<UUID>` profile name). If running without elevation, Sandy prints a warning and continues (localhost will remain blocked). Loopback always implies LAN access — there is no localhost-only capability in the Windows AppContainer model.

> [!NOTE]
> **Sandy stderr banner.** Sandy prints a config summary to stderr before running. Use `-q` to suppress it in automation pipelines where stderr is captured.

> [!NOTE]
> **Sandy runs without elevation in most cases.** It modifies folder ACLs to grant the sandbox access, which requires `WRITE_DAC` permission on each configured folder. Users have this permission on folders they own (e.g. under `%USERPROFILE%`). For folders owned by `SYSTEM`, `TrustedInstaller`, or other users, Sandy must be run as Administrator.

---

## Cleanup &amp; Crash Resilience

Sandy never leaves system state dirty. Five run-scoped resources are tracked and cleaned regardless of how the process exits:

| Resource | Created by | Persistence |
|----------|-----------|-------------|
| **ACL grants** | `[allow.*]` / `[deny.*]` folder/file grants | `HKCU\Software\Sandy\Grants\<UUID>` (TYPE\|PATH\|SID per grant) |
| **Registry persistence** | Grant write-ahead log | Same key (cleared with ACLs) |
| **Loopback exemption** | `lan = 'with localhost'` | In-memory flag + `CheckNetIsolation.exe` |
| **AppContainer profile** | Container creation | OS-managed (`Sandy_<UUID>`) — unique per instance |
| **Scheduled task** | Crash safety net | Task Scheduler (`SandyCleanup_<UUID>`) — one per instance |

### Exit scenarios

| Scenario | ACLs | Loopback | AppContainer | Sched. Task | Registry | Mechanism |
|----------|:----:|:--------:|:------------:|:-----------:|:--------:|-----------|
| **Clean exit** | ✅ | ✅ | ✅ | ✅ | ✅ | `cleanup()` lambda in `RunSandboxed` |
| **Child crash** | ✅ | ✅ | ✅ | ✅ | ✅ | Same — child exit doesn't affect Sandy |
| **Ctrl+C / close** | ✅ | ✅ | ✅ | ✅ | ✅ | Console signal handler → terminates child first → `CleanupSandbox()` |
| **Sandy crash (SEH)** | ✅ | ✅ | ✅ | ✅ | ✅ | `__except` handler → terminates child first → `CleanupSandbox()` |
| **Power loss / taskkill** | ✅ | ✅ | ✅ | ✅ | ✅ | Scheduled task at logon → `sandy.exe --cleanup` |

### How it works

1. **Write-ahead logging:** Before modifying any ACL, Sandy persists each grant as `TYPE|PATH|SID[|DENY:1]` to `HKCU\Software\Sandy\Grants\<UUID>`. The subkey also stores `_pid` (for liveness checks) and `_container` (AppContainer profile name). The recovery ledger is written *before* the system state is modified.

2. **Scheduled task safety net:** A per-instance `SandyCleanup_<UUID>` scheduled task is created to run `sandy.exe --cleanup` at next logon — for both normal and profile-mode (`-p`) runs. It only fires if Sandy didn't clean up normally (crash/power loss). Deleted on clean exit.

3. **Multi-instance safety:** Each instance generates a UUID at startup and uses a unique SID for all ACL operations — AppContainer uses a UUID-derived profile SID (`S-1-15-2-*`), Restricted Token uses a GUID-derived SID (`S-1-9-*`). This means concurrent instances have completely independent file grants that cannot interfere with each other. On exit, each instance removes only its own ACEs via `RemoveSidFromDacl`. Registry subkeys use the UUID as the key name, with stored PID for liveness checks during `--cleanup`.

   > **For agents and automation:** Multiple Sandy instances can safely run concurrently with overlapping folder grants. Each instance's sandbox is fully isolated. Use `--status` to inspect active instances and `--cleanup` to clear any stale state.

4. **Stale entry warning:** On startup, Sandy checks for leftover registry entries and warns:
   ```
   [Sandy] WARNING: Stale registry entries detected from a previous crashed run.
           Grants: HKCU\Software\Sandy\Grants
           Run 'sandy.exe --cleanup' to restore original state.
           If another sandy instance is running, its entries are expected.
   ```

5. **Liveness-gated cleanup:** `--cleanup` and startup cleanup correlate every transient AppContainer profile with the owning Sandy instance's PID and creation time before taking destructive action. Only resources belonging to dead instances are cleaned. Live instances retain their loopback exemptions and AppContainer profiles. Stale cleanup is **path+SID-precise**: when two instances share a path but use different SIDs, only the dead instance's ACEs are cleaned while the live instance's are preserved. Saved profiles (created via `--create-profile`) are permanently protected and never cleaned as stale. System helper processes (`schtasks.exe`, `CheckNetIsolation.exe`) are launched from fully-qualified `System32` paths to prevent search-order hijacking.

### Cleanup guarantees

| Guarantee | Mechanism |
|-----------|-----------|
| **ACL grants restored** on clean exit | RAII guard (`SandboxGuard::RunAll`) + `RemoveSidFromDacl` per SID |
| **Registry grants cleared** on clean exit | `RegDeleteTreeW` on instance subkey |
| **Loopback exemption removed** on clean exit | `CheckNetIsolation.exe LoopbackExempt -d` |
| **Scheduled task deleted** on clean exit | `schtasks /Delete` |
| **Stale ACLs restored** after crash | `--cleanup` parses persisted `TYPE|PATH|SID` records, removes SID's ACEs |
| **Parent registry keys permanent** | `Software\Sandy`, `Grants`, and `Profiles` are never deleted — preserved for visual tracking |

**Best-effort behaviors** (not guaranteed):
- **Desktop/window-station ACL cleanup** depends on `GetProcessWindowStation()` and `OpenDesktopW()` succeeding — these may fail in service or headless contexts. Failures are logged with error codes.
- **Loopback cleanup** depends on `CheckNetIsolation.exe` being available and the process running with sufficient privileges.
- **Persisted grant records** that are malformed (invalid TYPE, empty PATH, non-SID strings, or unknown flags) are skipped and logged — they will not cause cleanup to fail or corrupt system state.

### Validation notes

- Desktop/window-station ACL cleanup is now SID-targeted rather than snapshot-based, which is much safer for multi-instance use.
- This area remains operationally sensitive because it rebuilds ACLs on real host window objects; targeted repeated-grant, overlapping-instance, and crash-cleanup validation remains recommended.

### Status output notes

- `--status` prints both active and stale state for persisted grants, scheduled tasks, Sandy AppContainer profiles, and saved profiles.
- `--status --json` includes a top-level `summary` object with counts for instances, stale instances, scheduled tasks, profiles, and saved profiles.

> [!IMPORTANT]
> If Sandy is killed via `taskkill /F` or power is lost, run `sandy.exe --cleanup` manually or wait for the next logon (the scheduled task handles it automatically).

---

## Building

Open `sandy.sln` in Visual Studio and build the `x64 Release` configuration. No external dependencies required.

## License

[MIT](LICENSE)
