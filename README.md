<p align="center">
  <img src="resources/sandy_logo.png" alt="Sandy Logo" width="400"/>
</p>

<p align="center">
  <strong>A lightweight Windows sandbox runner</strong><br/>
  Run any executable in an isolated sandbox with fine-grained file, folder, and network access control.
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

Sandy launches executables inside a kernel-enforced Windows sandbox — no elevation required. Two isolation modes are supported: [AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation) (the same technology used by UWP apps and Edge) and **Restricted Token** (restricting SIDs with configurable integrity level). All settings are configured explicitly via TOML — no hidden defaults.

No VMs, Docker, WSL, or Hyper-V — just a single native executable. Sandy is lean, unprivileged sandboxing for agentic AI workflows, automation scripts, and tool-use pipelines: you define exactly which folders, files, and network access the process gets.

### Key Features

- 🔒 **Dual sandbox modes** — AppContainer or Restricted Token with configurable integrity
- 📁 **Granular access control** — read, write, execute, append, delete, peek, or full access per file or folder
- 🌐 **Network control** — internet, LAN, and localhost independently configurable (AppContainer)
- 🛡️ **Explicit configuration** — all settings mandatory, no hidden defaults or implicit behavior
- ⏱️ **Resource limits** — timeout, memory cap, and process count limits
- 📝 **Audit logging** — session logs, Procmon-based denial auditing, and crash dumps
- ⚡ **Zero dependencies** — single native executable, no runtime needed

---

## Usage

```
sandy.exe -c <config.toml> [-l <logfile>] [-a <auditlog>] [-d <dumpfile>] [-L] [-q] -x <executable> [args...]
sandy.exe -s "<toml>"      [-l <logfile>] [-a <auditlog>] [-d <dumpfile>] [-L] [-q] -x <executable> [args...]
sandy.exe -p <report>       -x <executable> [args...]
sandy.exe --print-container-toml          (print default appcontainer config)
sandy.exe --print-restricted-toml         (print default restricted config)
sandy.exe --cleanup                       (restore stale state from crashed runs)
sandy.exe --status [--json]                (show active instances and stale state)
sandy.exe --explain <code>                 (decode exit code: Sandy, NTSTATUS, Win32)
sandy.exe --dry-run -c <config.toml> [-x <exec>]  (validate + show plan, no changes)
sandy.exe --print-config -c <config.toml>  (print resolved config)
```

| Flag | Description |
|------|-------------|
| `-c <path>`, `--config <path>` | Path to TOML config file |
| `-s <toml>`, `--string <toml>` | Inline TOML config string (alternative to `-c`) |
| `-l <path>`, `--log <path>` | Session log (config, output, exit code) |
| `-a <path>`, `--audit <path>` | Audit log of denied resource access (requires Procmon + admin) |
| `-d <path>`, `--dump <path>` | Crash dump output path (independent of `-a`) |
| `-L`, `--log-stamp` | Prepend `YYYYMMDD_HHMMSS_uid_` to log/audit/dump filenames |
| `-p <path>`, `--profile <path>` | Profile unsandboxed run for sandbox feasibility (requires Procmon + admin) |
| `-x <path>`, `--exec <path>` | Executable to run sandboxed (consumes remaining args) |
| `-q`, `--quiet` | Suppress the config banner on stderr |
| `-v`, `--version` | Print version |
| `-h`, `--help` | Print full help text with config reference |
| `--print-container-toml` | Print default AppContainer config to stdout |
| `--print-restricted-toml` | Print default Restricted Token config to stdout |
| `--cleanup` | Restore stale state from crashed runs (loopback, ACLs, WER, scheduled task) |
| `--status [--json]` | Show active sandy instances, stale grants, scheduled tasks, and a summary count |
| `--explain <code>` | Decode exit code (Sandy 125-131, NTSTATUS, Win32) |
| `--dry-run`, `--check` | Validate config + show planned changes (no system modifications) |
| `--print-config` | Print resolved config to stdout (requires `-c`/`-s`) |

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
- Rules per section: max **256** entries in `[allow]`, `[deny]`, or `[registry]`

See [`sandy_config.toml`](sandy_config.toml) for the default template, [`sandy_config_appcontainer.toml`](sandy_config_appcontainer.toml) and [`sandy_config_restricted.toml`](sandy_config_restricted.toml) for mode-specific templates.

### `[sandbox]` — Mode selection

```toml
[sandbox]
token = 'appcontainer'    # or 'restricted'
integrity = 'low'         # restricted only: 'low' or 'medium' (required)
workdir = 'C:\projects'   # child working directory (default: sandy.exe folder)
```

| Key | Values | Modes | Description |
|-----|--------|-------|-------------|
| `token` | `'appcontainer'`, `'restricted'` | both | Sandbox isolation model *(required)* |
| `integrity` | `'low'`, `'medium'` | restricted | Integrity level *(required)* · `'low'` = strongest isolation, `'medium'` = wider app compatibility |
| `workdir` | path | both | Child process working directory (default: folder containing `sandy.exe`) |

### `[allow]` — File and folder grants

Grant the sandboxed process access to specific files or folders. Sandy modifies folder ACLs at launch and restores them on exit. Requires `WRITE_DAC` on each path (user-owned folders work without admin).

```toml
[allow]
peek    = ['C:\', 'C:\Users', 'C:\Users\H']    # non-recursive directory traversal
read    = ['C:\data\config.json', 'C:\Python314']
write   = ['C:\logs\agent.log', 'C:\temp\output']
execute = ['C:\tools\bin']
append  = ['C:\logs\audit.log']
delete  = ['C:\temp\scratch']
all     = ['C:\workspace']
```

| Key | Permission granted |
|-----|--------------------|
| `peek` | List directory + stat only — **non-recursive**, applies to the named directory only |
| `read` | Read files, list directories (recursive) |
| `write` | Create and modify files, no read (recursive) |
| `execute` | Read + execute files, list directories (recursive) |
| `append` | Append only, no overwrite, no read (recursive) |
| `delete` | Delete only (recursive) |
| `all` | Full access: read + write + execute + delete (recursive) |

> [!IMPORTANT]
> **Recursive propagation:** All grants except `peek` apply to the path **and all its descendants** — every subdirectory and file underneath inherits the same access level. `peek` is explicitly non-recursive: it grants access only to the named directory itself.

> [!IMPORTANT]
> Permissions are independent — `write` does **not** grant `read`, and `read` does **not** grant `execute`. Grant each permission explicitly, or use `all` for full access.

### `[deny]` — Deny access to specific paths

Block specific permissions on paths that would otherwise be accessible. Uses the same 6 access keys as `[allow]` (except `peek`). All 6 keys are required (use `[]` for none).

```toml
[deny]
read    = []
write   = ['C:\workspace\src\core']         # block writes in core/ even though workspace has all
execute = []
append  = []
delete  = []
all     = ['C:\workspace\secrets']           # fully block secrets/ even though workspace has all
```

**Key behaviors:**

- **Deny is recursive.** A deny on a directory blocks the denied permissions on that directory **and all descendants** — subdirectories and files at every depth.
- **Deny is surgical.** Only the specific permission type is blocked. For example, `deny.write` blocks writing and creating files, but `read`, `execute`, and `delete` remain allowed.
- **`deny.write` does NOT block delete.** `DELETE` is a separate Windows permission from `WRITE`. To block deletion, use `deny.delete` or `deny.all`.
- **`deny.read` blocks listing.** Denying read also blocks `os.listdir()` / `dir` because directory listing requires read-data permission.

#### Allow-inside-deny (depth-sorted pipeline)

Sandy supports carving out allowed subtrees from within denied areas. When an `[allow]` path is under a `[deny]` path, Sandy automatically strips the deny ACEs from the allowed subtree before granting access.

```toml
[deny]
all = ['C:\repos']                 # deny all access to repos 

[allow]
all  = ['C:\repos\snipps']         # but allow full access to snipps
peek = ['C:\repos']                # and allow listing the repos dir
```

**How it works:** All allow and deny entries are merged into a single pipeline, sorted by path depth (shallowest first). At each depth, deny is applied before allow. When an allow is detected under an active deny, Sandy strips the deny ACEs from the allow subtree before granting. For `peek`, the strip is non-recursive (directory only).

The pipeline execution is logged:
```
PIPELINE: sorted 3 entries by path depth:
    DENY  [ALL    ] C:\repos
    ALLOW [PEEK   ] C:\repos            <- strip deny (dir only)
    ALLOW [ALL    ] C:\repos\snipps     <- strip deny (subtree)
```

> [!TIP]
> **Common pattern:** Deny `all` on a broad directory, then allow specific subdirectories. The most specific (deepest) path always wins.

### `[privileges]` — Permissions

All keys must be explicitly set for the active mode. Omitting a key is a parse error. Wrong-mode keys are rejected.

```toml
# AppContainer mode — all 8 keys required:
[privileges]
system_dirs     = true
network         = false
localhost       = false
lan             = false
stdin           = false
clipboard_read  = false
clipboard_write = false
child_processes = true

# Restricted mode — all 5 keys required:
[privileges]
named_pipes     = false
stdin           = false
clipboard_read  = false
clipboard_write = false
child_processes = true
```

| Key | Required in | Description |
|-----|-------------|-------------|
| `system_dirs` | appcontainer | Read access to `C:\Windows`, `Program Files` |
| `network` | appcontainer | Outbound internet access |
| `localhost` | appcontainer | Loopback connections (requires admin) |
| `lan` | appcontainer | Local network access |
| `named_pipes` | restricted | Named pipe creation (`CreateNamedPipeW`) |
| `stdin` | both | `true` = inherit, `false` = disabled (NUL), or a file path |
| `clipboard_read` | both | Allow reading from the clipboard |
| `clipboard_write` | both | Allow writing to the clipboard |
| `child_processes` | both | Allow spawning child processes (kernel-enforced) |

#### What `system_dirs` exposes (AppContainer only)

Enables the `ALL_APPLICATION_PACKAGES` group, granting **read-only** access to:

| Path | Access |
|------|--------|
| `C:\Windows`, `System32`, `SysWOW64` | ✅ read |
| `C:\Program Files`, `Program Files (x86)` | ✅ read |
| `C:\Windows\Temp`, `ProgramData`, `C:\Users` | ❌ blocked |
| User profile (Desktop, Documents, Downloads) | ❌ blocked |

> [!TIP]
> Python's Windows installer sets `ALL_APPLICATION_PACKAGES` on its install directory. With `system_dirs = true`, the Python folder is readable without an explicit `[allow]` entry.

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

`inherit` must be explicitly set. When `false`, the child gets a clean environment with only essential Windows variables. Use `pass` to add specific variables.

```toml
[environment]
inherit = true            # pass full parent environment
# or:
inherit = false           # clean env + pass list
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
timeout = 300       # kill process after N seconds (exit code 1)
memory = 4096       # job-wide memory cap in MB (all processes combined)
processes = 10      # max total active processes (including main)
```

> [!IMPORTANT]
> **Resource limits are strictly enforced.** If a resource limit (memory, process count, or clipboard restriction) is configured but the job object cannot be assigned to the child process, Sandy will terminate the child and exit with code 129 (setup error). This fail-closed behavior ensures the sandbox never runs with unenforced limits.

> [!NOTE]
> **Effective enforcement visibility.** `--status` reports active and stale instances, WER entries, scheduled tasks, and AppContainer profiles, but it is not yet a full structured "requested policy vs effective policy" report. Cleanup parsing errors and best-effort cleanup limitations are logged when encountered.

### Config availability summary

| Section / Key | AppContainer | Restricted |
|---------------|:-------------|:-----------|
| **`[sandbox]`** | 🟢 required | 🟢 required |
| &ensp; `token` | 🟢 required | 🟢 required |
| &ensp; `integrity` | 🔴 n/a | 🟢 required (`'low'` or `'medium'`) |
| &ensp; `workdir` | 🟢 required (`'inherit'` or path) | 🟢 required (`'inherit'` or path) |
| **`[allow]`** | ­­🟢 required (all 7 keys) | 🟢 required (all 7 keys) |
| &ensp; `read` `write` `execute` `append` `delete` `all` `peek` | 🟢 required (`[]` for none) | 🟢 required (`[]` for none) |
| **`[deny]`** | 🟢 required (all 6 keys) | 🟢 required (all 6 keys) |
| &ensp; `read` `write` `execute` `append` `delete` `all` | 🟢 required (`[]` for none) | 🟢 required (`[]` for none) |
| **`[privileges]`** | 🟢 required | 🟢 required |
| &ensp; `system_dirs` | 🟢 required | 🔴 n/a |
| &ensp; `network` | 🟢 required | 🔴 n/a |
| &ensp; `localhost` | 🟢 required | 🔴 n/a |
| &ensp; `lan` | 🟢 required | 🔴 n/a |
| &ensp; `named_pipes` | 🔴 n/a | 🟢 required |
| &ensp; `stdin` | 🟢 required | 🟢 required |
| &ensp; `clipboard_read` | 🟢 required | 🟢 required |
| &ensp; `clipboard_write` | 🟢 required | 🟢 required |
| &ensp; `child_processes` | 🟢 required | 🟢 required |
| **`[registry]`** | 🔴 n/a | 🟢 required (both keys) |
| &ensp; `read` `write` | 🔴 n/a | 🟢 required (`[]` for none) |
| **`[environment]`** | 🟢 required | 🟢 required |
| &ensp; `inherit` | 🟢 required | 🟢 required |
| &ensp; `pass` | 🟢 required (`[]` for none) | 🟢 required (`[]` for none) |
| **`[limit]`** | 🟢 required (all 3 keys) | 🟢 required (all 3 keys) |
| &ensp; `timeout` `memory` `processes` | 🟢 required (`0` = unlimited) | 🟢 required (`0` = unlimited) |

🟢 required · 🔴 not available (parse error if used)

---

## Sandbox Modes

Merged view across AppContainer and Restricted Token (Low / Medium integrity).

| Aspect | AppContainer | Restricted Low | Restricted Medium |
|--------|:------------:|:--------------:|:-----------------:|
| **Integrity level** | 🔒 Low | 🔒 Low | 🔒 Medium |
| **Object namespace** | 🔒 Isolated | 🔒 Shared | 🔒 Shared |
| **Process identity** | 🔒 AppContainer SID | 🔒 Per-instance SID restricted | 🔒 Per-instance SID restricted |
| **Elevation** | ❌ Blocked | ❌ Blocked | ❌ Blocked |
| **Privilege stripping** | 🔒 All stripped | 🔒 All except SeChangeNotify | 🔒 All except SeChangeNotify |
| **Isolation layers** | 🔒 2: SID + namespace | 🔒 2: SIDs + integrity | 🔒 1: SIDs only |
| **Named pipes** | ❌ Blocked | ⚙️ `named_pipes` | ⚙️ `named_pipes` |
| **Network** | ⚙️ `network` `lan` `localhost` | ✅ Allowed | ✅ Allowed |
| **System dir reads** | ⚙️ `system_dirs` | ✅ Allowed | ✅ Allowed |
| **System dir writes** | ❌ Blocked | ❌ Blocked | ❌ Blocked |
| **User profile reads** | ⚙️ `[allow]` | ✅ Allowed | ✅ Allowed |
| **User profile writes** | ⚙️ `[allow]` | ⚙️ `[allow]` ¹ | ✅ Allowed |
| **Registry reads** | ✅ Private hive | ✅ Allowed | ✅ Allowed |
| **Registry HKCU writes** | ❌ Blocked | ❌ Blocked | ✅ Allowed |
| **Registry HKLM writes** | ❌ Blocked | ❌ Blocked | ❌ Blocked |
| **DLL/API set resolution** | ✅ Allowed | ⚠️ May break apps | ✅ Allowed |
| **COM/RPC servers** | ❌ Blocked | ✅ Allowed | ✅ Allowed |
| **Scheduled tasks** | ❌ Blocked | ❌ Blocked | ✅ Allowed |
| **Window messages (UIPI)** | ❌ Blocked | ❌ Blocked | ✅ Allowed |
| **Clipboard** | ⚙️ `clipboard_read/write` | ⚙️ `clipboard_read/write` | ⚙️ `clipboard_read/write` |
| **Child processes** | ⚙️ `child_processes` | ⚙️ `child_processes` | ⚙️ `child_processes` |
| **Stdin** | ⚙️ `stdin` | ⚙️ `stdin` | ⚙️ `stdin` |
| **Environment** | ⚙️ `inherit` | ⚙️ `inherit` | ⚙️ `inherit` |
| **File/folder grants** | ⚙️ `[allow]` | ⚙️ `[allow]` | ⚙️ `[allow]` |
| **Resource limits** | ⚙️ `[limit]` | ⚙️ `[limit]` | ⚙️ `[limit]` |

🔒 fixed · ❌ blocked · ✅ allowed · ⚙️ configurable · ⚠️ warning

¹ Restricted Low writes to medium-integrity folders (most of `C:\Users`) are blocked by mandatory integrity even with `[allow]` grants. Use `AppData\LocalLow` or Restricted Medium for user profile writes.

**Use AppContainer** when you need network isolation and don't require named pipes or COM.

**Use Restricted Token** when the sandboxed app needs named pipes (Flutter, Chromium, Mojo) or COM/RPC.

### Examples

AppContainer with network access:

```toml
[sandbox]
token = 'appcontainer'

[allow]
read = ['C:\Python314', 'C:\projects\my_agent']
all = ['C:\workspace']

[deny]
read    = []
write   = []
execute = []
append  = []
delete  = []
all     = []

[privileges]
system_dirs = true
network = true
localhost = false
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

[allow]
read = ['C:\Python314', 'C:\projects\my_agent']
all = ['C:\workspace']

[deny]
read    = []
write   = []
execute = []
append  = []
delete  = []
all     = []

[privileges]
named_pipes = true
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

Session logs (`-l`), audit logs (`-a`), and crash dumps (`-d`) write to the path you specify — relative paths resolve against the current working directory (standard POSIX behavior).

**Early logger initialization:** The logger starts immediately after CLI argument parsing — before config loading — so config parser warnings (e.g. duplicate paths) are captured in the log file.

**Console passthrough:** The child process inherits the parent's console handles directly (real TTY). Sandy does **not** interpose on stdout/stderr. This means interactive CLI tools (REPLs, Claude Code, etc.) work correctly with TTY detection, colors, and terminal features. To capture child output to a file, use standard shell redirection: `sandy ... -x myapp > output.log 2>&1`.

**Log rotation:** If the target file already exists and `--log-stamp` is *not* used, Sandy automatically rotates with POSIX-style numbered suffixes:

```
session.log → session.log.1 → session.log.2 → ...
```

**Timestamped logs:** Use `-L` / `--log-stamp` to prepend a unique `YYYYMMDD_HHMMSS_uid_` prefix to all log filenames. The 4-hex UID prevents collisions when multiple runs start in the same second:

```
sandy.exe -L -l session.log -a audit.log -x myapp.exe
→ 20260305_105426_a3f1_session.log
→ 20260305_105426_a3f1_audit.log
```

All log timestamps use **local time with ISO 8601 UTC offset** (e.g. `2026-03-05T10:54:26.123+01:00`).

**Error diagnostics:** When ACL operations fail, Sandy logs the exact Win32 error code and its human-readable description — e.g. `FAILED (0x00000005: Access is denied)`. This applies to file grants, deny rules, and registry grants.

**Pre-launch token validation (Restricted Token mode):** Before launching the child process, Sandy verifies the restricted token's integrity level matches the configured value (`low` = `0x1000`, `medium` = `0x2000`). If the check fails, Sandy aborts with exit code 129 and logs `TOKEN_VALIDATE: FAILED`.

---

## Audit

The `-a` flag captures resource denial events via [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) (headless). Requires Procmon on PATH + admin. Sandy records all file, registry, network, DLL, and process denials during the child's lifetime, then outputs a deduplicated post-mortem log.

```
sandy.exe -c config.toml -a audit.log -x myapp.exe
```

```
[13:07:38.12] T:4520   FILE    ACCESS DENIED       C:\Windows\System32\kernel32.dll
[13:07:38.34] T:4520   REG     ACCESS DENIED       HKLM\Software\MyApp

=== Summary: 47 unique events, 38 FILE, 3 REG, 4 NET, 2 IMAGE ===
=== Repeated (x count) ===
  x23  FILE    ACCESS DENIED       C:\Windows\System32
```

---

## Profile

The `-p` flag runs a process **unsandboxed** under [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon), analyzes its resource usage (files, registry, network, DLLs, pipes, child processes), and generates a feasibility report with a suggested TOML config. Requires Procmon on PATH + admin.

```
sandy.exe -p report.txt -x myapp.exe [args...]
```

Use profile mode **before** sandboxing an unfamiliar application. It tells you whether the process can be sandboxed, which mode works best, and what `[allow]` paths and `[privileges]` are needed.

```
--- Verdict ---
Sandboxable:     YES
AppContainer:    YES (recommended)

--- Suggested TOML Config ---
[sandbox]
token = 'appcontainer'
[allow]
read = ['C:\Users', 'C:\repos\myproject']
write = ['C:\Users\H\AppData\Local\Temp']
[privileges]
system_dirs = true
```

---

## Notes

> [!WARNING]
> **AppContainer: strict isolation.** Sandy blocks access to system folders (`C:\Windows`, `C:\Program Files`) unless `system_dirs = true` is set in `[privileges]`. Most executables need system DLLs to run, so the sample config ships with `system_dirs` enabled. In Restricted Token mode, system directories are always readable.

> [!NOTE]
> **Localhost access** (AppContainer only) requires administrator privileges. Sandy uses `CheckNetIsolation.exe` to manage a per-instance loopback exemption (matching the AppContainer's unique `Sandy_<UUID>` profile name). If running without elevation, Sandy prints a warning and continues (localhost will remain blocked).

> [!NOTE]
> **Sandy stderr banner.** Sandy prints a config summary to stderr before running. Use `-q` to suppress it in automation pipelines where stderr is captured.

> [!NOTE]
> **Sandy runs without elevation in most cases.** It modifies folder ACLs to grant the sandbox access, which requires `WRITE_DAC` permission on each configured folder. Users have this permission on folders they own (e.g. under `%USERPROFILE%`). For folders owned by `SYSTEM`, `TrustedInstaller`, or other users, Sandy must be run as Administrator.

---

## Cleanup &amp; Crash Resilience

Sandy never leaves system state dirty. Six resources are tracked and cleaned regardless of how the process exits:

| Resource | Created by | Persistence |
|----------|-----------|-------------|
| **ACL grants** | `[allow]` folder/file grants | `HKCU\Software\Sandy\Grants\<UUID>` (TYPE\|PATH\|SID per grant) |
| **Registry persistence** | Grant write-ahead log | Same key (cleared with ACLs) |
| **Loopback exemption** | `localhost = true` | In-memory flag + `CheckNetIsolation.exe` |
| **AppContainer profile** | Container creation | OS-managed (`Sandy_<UUID>`) — unique per instance |
| **Scheduled task** | Crash safety net | Task Scheduler (`SandyCleanup_<UUID>`) — one per instance |
| **WER keys** | `-a` or `-d` crash dumps | `HKCU\Software\Sandy\WER` (PID as value name) |

### Exit scenarios

| Scenario | ACLs | Loopback | AppContainer | Sched. Task | WER | Registry | Mechanism |
|----------|:----:|:--------:|:------------:|:-----------:|:---:|:--------:|-----------|
| **Clean exit** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | `cleanup()` lambda in `RunSandboxed` |
| **Child crash** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | Same — child exit doesn't affect Sandy |
| **Ctrl+C / close** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | Console signal handler → `CleanupSandbox()` |
| **Sandy crash (SEH)** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | `__except` handler → `CleanupSandbox()` |
| **Power loss / taskkill** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | Scheduled task at logon → `sandy.exe --cleanup` |

### How it works

1. **Write-ahead logging:** Before modifying any ACL, Sandy persists each grant as `TYPE|PATH|SID[|DENY:1][|TRAPPED:sids]` to `HKCU\Software\Sandy\Grants\<UUID>`. The subkey also stores `_pid` (for liveness checks) and `_container` (AppContainer profile name). WER exe names are stored in `HKCU\Software\Sandy\WER` with PID as value name. Both are written *before* the system state is modified.

2. **Scheduled task safety net:** A per-instance `SandyCleanup_<UUID>` scheduled task is created to run `sandy.exe --cleanup` at next logon. It only fires if Sandy didn't clean up normally (crash/power loss). Deleted on clean exit.

3. **Multi-instance safety:** Each instance generates a UUID at startup and uses a unique SID for all ACL operations — AppContainer uses a UUID-derived profile SID (`S-1-15-2-*`), Restricted Token uses a GUID-derived SID (`S-1-9-*`). This means concurrent instances have completely independent file grants that cannot interfere with each other. On exit, each instance removes only its own ACEs via `RemoveSidFromDacl`. Registry subkeys use the UUID as the key name, with stored PID for liveness checks during `--cleanup`.

   > **For agents and automation:** Multiple Sandy instances can safely run concurrently with overlapping folder grants. Each instance's sandbox is fully isolated. Use `--status` to inspect active instances and `--cleanup` to clear any stale state.

4. **Stale entry warning:** On startup, Sandy checks for leftover registry entries and warns:
   ```
   [Sandy] WARNING: Stale registry entries detected from a previous crashed run.
           Grants: HKCU\Software\Sandy\Grants   WER: HKCU\Software\Sandy\WER
           Run 'sandy.exe --cleanup' to restore original state.
           If another sandy instance is running, its entries are expected.
   ```

5. **Explicit cleanup only:** Stale state restoration (ACL reverts, WER key removal, AppContainer profile deletion) is performed exclusively by `sandy.exe --cleanup` — never during normal startup. Cleanup only processes entries from dead PIDs, preserving live instances' grants.

### Cleanup guarantees

| Guarantee | Mechanism |
|-----------|-----------|
| **ACL grants restored** on clean exit | RAII guard (`SandboxGuard::RunAll`) + `RemoveSidFromDacl` per SID |
| **Registry grants cleared** on clean exit | `RegDeleteTreeW` on instance subkey |
| **Loopback exemption removed** on clean exit | `CheckNetIsolation.exe LoopbackExempt -d` |
| **Scheduled task deleted** on clean exit | `schtasks /Delete` |
| **Stale ACLs restored** after crash | `--cleanup` parses persisted `TYPE|PATH|SID` records, removes SID's ACEs |
| **Parent registry key cascade** | `Software\Sandy\Grants` and `Software\Sandy` are deleted when empty |

**Best-effort behaviors** (not guaranteed):
- **Desktop/window-station ACL cleanup** depends on `GetProcessWindowStation()` and `OpenDesktopW()` succeeding — these may fail in service or headless contexts. Failures are logged with error codes.
- **Loopback cleanup** depends on `CheckNetIsolation.exe` being available and the process running with sufficient privileges.
- **Persisted grant records** that are malformed (invalid TYPE, empty PATH, non-SID strings, or unknown flags) are skipped and logged — they will not cause cleanup to fail or corrupt system state.
- **Parent registry cascade cleanup** (`Software\Sandy\Grants`, `Software\Sandy`) is opportunistic and may be skipped if keys are not empty or registry inspection fails.

### Validation notes

- Desktop/window-station ACL cleanup is now SID-targeted rather than snapshot-based, which is much safer for multi-instance use.
- This area remains operationally sensitive because it rebuilds ACLs on real host window objects; targeted repeated-grant, overlapping-instance, and crash-cleanup validation remains recommended.

### Status output notes

- `--status` prints both active and stale state for persisted grants, WER entries, scheduled tasks, and Sandy AppContainer profiles.
- `--status --json` includes a top-level `summary` object with counts for instances, stale instances, WER entries, stale WER entries, scheduled tasks, and profiles.

> [!IMPORTANT]
> If Sandy is killed via `taskkill /F` or power is lost, run `sandy.exe --cleanup` manually or wait for the next logon (the scheduled task handles it automatically).

---

## Building

Open `sandy.sln` in Visual Studio and build the `x64 Release` configuration. No external dependencies required.

## License

[MIT](LICENSE)
