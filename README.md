<p align="center">
  <img src="resources/sandy_logo.png" alt="Sandy Logo" width="400"/>
</p>

<p align="center">
  <strong>A lightweight Windows sandbox runner</strong><br/>
  Run any executable in an isolated sandbox with fine-grained file, folder, and network access control.
</p>

---

## What is Sandy?

Sandy launches executables inside a kernel-enforced Windows sandbox — no elevation required. Two isolation modes are supported: [AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation) (the same technology used by UWP apps and Edge) and **Restricted Token** (restricting SIDs with configurable integrity level). All settings are configured explicitly via TOML — no hidden defaults.

No VMs, Docker, WSL, or Hyper-V — just a single native executable. Sandy is lean, unprivileged sandboxing for agentic AI workflows, automation scripts, and tool-use pipelines: you define exactly which folders, files, and network access the process gets.

### Key Features

- 🔒 **Dual sandbox modes** — AppContainer or Restricted Token with configurable integrity
- 📁 **Granular access control** — read, write, execute, append, delete, or full access per file or folder
- 🌐 **Network control** — internet, LAN, and localhost independently configurable (AppContainer)
- 🛡️ **Explicit configuration** — all settings mandatory, no hidden defaults or implicit behavior
- ⏱️ **Resource limits** — timeout, memory cap, and process count limits
- 📝 **Audit logging** — session logs, Procmon-based denial auditing, and crash dumps
- ⚡ **Zero dependencies** — single native executable, no runtime needed

---

## Usage

```
sandy.exe -c <config.toml> [-l <logfile>] [-a <auditlog>] [-d <dumpfile>] [-q] -x <executable> [args...]
sandy.exe -s "<toml>"      [-l <logfile>] [-a <auditlog>] [-d <dumpfile>] [-q] -x <executable> [args...]
sandy.exe -p <report>       -x <executable> [args...]
sandy.exe --print-container-toml          (print default appcontainer config)
sandy.exe --print-restricted-toml         (print default restricted config)
sandy.exe --cleanup                       (restore stale state from crashed runs)
sandy.exe --status                        (show active instances and stale state)
```

| Flag | Description |
|------|-------------|
| `-c <path>`, `--config <path>` | Path to TOML config file |
| `-s <toml>`, `--string <toml>` | Inline TOML config string (alternative to `-c`) |
| `-l <path>`, `--log <path>` | Session log (config, output, exit code) |
| `-a <path>`, `--audit <path>` | Audit log of denied resource access (requires Procmon + admin) |
| `-d <path>`, `--dump <path>` | Crash dump output path (independent of `-a`) |
| `-p <path>`, `--profile <path>` | Profile unsandboxed run for sandbox feasibility (requires Procmon + admin) |
| `-x <path>`, `--exec <path>` | Executable to run sandboxed (consumes remaining args) |
| `-q`, `--quiet` | Suppress the config banner on stderr |
| `-v`, `--version` | Print version |
| `-h`, `--help` | Print full help text with config reference |
| `--print-container-toml` | Print default AppContainer config to stdout |
| `--print-restricted-toml` | Print default Restricted Token config to stdout |
| `--cleanup` | Restore stale state from crashed runs (loopback, ACLs, WER, scheduled task) |
| `--status` | Show active sandy instances, stale grants, and scheduled task |

All sandy flags must come **before** `-x`. Arguments after `-x <executable>` are forwarded to it. Sandy forwards the child process's exit code.

---

## Config File

All sandbox behavior is controlled by a TOML config. Every config **must** include a `[sandbox]` section declaring the token mode. Use `-c` or `-s` (mutually exclusive). Mode-specific settings are validated — using a flag meant for the other mode is an error. All paths must be absolute.

See [`sandy_config.toml`](sandy_config.toml) for the default template, [`sandy_config_appcontainer.toml`](sandy_config_appcontainer.toml) and [`sandy_config_restricted.toml`](sandy_config_restricted.toml) for mode-specific templates.

### `[sandbox]` — Mode selection *(mandatory)*

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

### `[access]` — File and folder grants

Grant the sandboxed process access to specific files or folders. Paths are recursive for directories. Sandy modifies folder ACLs at launch and restores them on exit. Requires `WRITE_DAC` on each path (user-owned folders work without admin).

```toml
[access]
read    = ['C:\data\config.json', 'C:\Python314']
write   = ['C:\logs\agent.log', 'C:\temp\output']
execute = ['C:\tools\bin']
append  = ['C:\logs\audit.log']
delete  = ['C:\temp\scratch']
all     = ['C:\workspace']
```

| Key | Permission granted |
|-----|--------------------|
| `read` | Read files, list directories |
| `write` | Create and modify files (no read) |
| `execute` | Execute (no read) |
| `append` | Append only (no overwrite, no read) |
| `delete` | Delete only |
| `all` | Full access (read + write + execute + delete) |

> [!IMPORTANT]
> Permissions are independent — `write` does **not** grant `read`, and `read` does **not** grant `execute`. Grant each permission explicitly, or use `all` for full access.

### `[allow]` — Permissions *(all keys mandatory)*

All keys must be explicitly set for the active mode. Omitting a key is a parse error. Wrong-mode keys are rejected.

```toml
# AppContainer mode — all 8 keys required:
[allow]
system_dirs     = true
network         = false
localhost       = false
lan             = false
stdin           = false
clipboard_read  = false
clipboard_write = false
child_processes = true

# Restricted mode — all 5 keys required:
[allow]
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
> Python's Windows installer sets `ALL_APPLICATION_PACKAGES` on its install directory. With `system_dirs = true`, the Python folder is readable without an explicit `[access]` entry.

### `[registry]` — Registry key grants *(restricted only)*

Grant read or write access to specific registry keys. Most keys under `HKLM\Software` and `HKCU` are already readable by default via `BUILTIN\Users`.

```toml
[registry]
read  = ['HKCU\Software\MyApp']
write = ['HKCU\Software\MyApp\Settings']
```

> [!NOTE]
> `[registry]` is not available in AppContainer mode — AppContainer provides a fixed private registry hive automatically.

### `[environment]` — Environment variables *(inherit is mandatory)*

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

### Config availability summary

| Section / Key | AppContainer | Restricted |
|---------------|:-------------|:-----------|
| **`[sandbox]`** | 🟢 required | 🟢 required |
| &ensp; `token` | 🟢 required | 🟢 required |
| &ensp; `integrity` | 🔴 n/a | 🟢 required (`'low'` or `'medium'`) |
| &ensp; `workdir` | 🟢 required (`'inherit'` or path) | 🟢 required (`'inherit'` or path) |
| **`[access]`** | 🟢 required (all 6 keys) | 🟢 required (all 6 keys) |
| &ensp; `read` `write` `execute` `append` `delete` `all` | 🟢 required (`[]` for none) | 🟢 required (`[]` for none) |
| **`[allow]`** | 🟢 required | 🟢 required |
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
| **Process identity** | 🔒 AppContainer SID | 🔒 User SID restricted | 🔒 User SID restricted |
| **Elevation** | ❌ Blocked | ❌ Blocked | ❌ Blocked |
| **Privilege stripping** | 🔒 All stripped | 🔒 All except SeChangeNotify | 🔒 All except SeChangeNotify |
| **Isolation layers** | 🔒 2: SID + namespace | 🔒 2: SIDs + integrity | 🔒 1: SIDs only |
| **Named pipes** | ❌ Blocked | ⚙️ `named_pipes` | ⚙️ `named_pipes` |
| **Network** | ⚙️ `network` `lan` `localhost` | ✅ Allowed | ✅ Allowed |
| **System dir reads** | ⚙️ `system_dirs` | ✅ Allowed | ✅ Allowed |
| **System dir writes** | ❌ Blocked | ❌ Blocked | ❌ Blocked |
| **User profile reads** | ⚙️ `[access]` | ✅ Allowed | ✅ Allowed |
| **User profile writes** | ⚙️ `[access]` | ⚙️ `[access]` ¹ | ✅ Allowed |
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
| **File/folder grants** | ⚙️ `[access]` | ⚙️ `[access]` | ⚙️ `[access]` |
| **Resource limits** | ⚙️ `[limit]` | ⚙️ `[limit]` | ⚙️ `[limit]` |

🔒 fixed · ❌ blocked · ✅ allowed · ⚙️ configurable · ⚠️ warning

¹ Restricted Low writes to medium-integrity folders (most of `C:\Users`) are blocked by mandatory integrity even with `[access]` grants. Use `AppData\LocalLow` or Restricted Medium for user profile writes.

**Use AppContainer** when you need network isolation and don't require named pipes or COM.

**Use Restricted Token** when the sandboxed app needs named pipes (Flutter, Chromium, Mojo) or COM/RPC.

### Examples

AppContainer with network access:

```toml
[sandbox]
token = 'appcontainer'

[access]
read = ['C:\Python314', 'C:\projects\my_agent']
all = ['C:\workspace']

[allow]
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
```

```
sandy.exe -c agent_config.toml -x C:\Python314\python.exe agent.py
```

Restricted Token with pipes and medium integrity:

```toml
[sandbox]
token = 'restricted'
integrity = 'medium'

[access]
read = ['C:\Python314', 'C:\projects\my_agent']
all = ['C:\workspace']

[allow]
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
```

---

## Demo

Full test run showing Sandy's isolation in action — 35 tests, all passing:

```
=== Sandy Sandbox Tests ===
Working dir: c:\repos\sandy_cli\x64\Release
Python:      C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe

--- App folder (read-only) ---
  [PASS] List app folder: 2 items
  [PASS] Create file in app folder: blocked -> PermissionError
  [PASS] Create subfolder in app folder: blocked -> PermissionError

--- System dir reads (allowed by AppContainer) ---
  [PASS] Read C:\Windows: 115 items
  [PASS] Read Program Files: 67 items
  [PASS] Read C:\Windows\System32: 5028 items

--- System dir writes (must be blocked) ---
  [PASS] Write to C:\Windows: blocked -> PermissionError
  [PASS] Write to C:\: blocked -> PermissionError
  [PASS] Write to System32: blocked -> PermissionError
  [PASS] Write to Program Files: blocked -> PermissionError
  [PASS] Create dir in C:\: blocked -> PermissionError

--- User profile (blocked) ---
  [PASS] Read user Desktop: blocked -> PermissionError
  [PASS] Read user Documents: blocked -> PermissionError
  [PASS] Write to user home: blocked -> PermissionError

--- Working directory ---
  [PASS] Write file after chdir to C:\Windows: blocked -> PermissionError

--- Network access (blocked) ---
  [PASS] HTTP request: blocked -> URLError

--- Permission folder tests ---
--- [Read-only] ---
  test_R = C:\Users\H\test_R
  [PASS] test_R: list dir: 1 items
  [PASS] test_R: read seed.txt: This is a seed file for read-only testing
  [PASS] test_R: create file (should fail): blocked -> PermissionError
  [PASS] test_R: delete seed.txt (should fail): blocked -> PermissionError

--- [Write-only] ---
  test_W = C:\Users\H\test_W
  [PASS] test_W: create file: 5
  [PASS] test_W: list dir (should fail): blocked -> PermissionError
  [PASS] test_W: read file (should fail): blocked -> PermissionError

--- [Read & Write] ---
  test_RW = C:\Users\H\test_RW
  [PASS] test_RW: create file: 5
  [PASS] test_RW: read file: hello
  [PASS] test_RW: list dir: 1 items
  [PASS] test_RW: delete file: deleted

--- File-level access tests ---
  file_R = C:\Users\H\test_file_R.txt
  [PASS] file_R: read content: File-level read test content
  [PASS] file_R: write (should fail): blocked -> PermissionError
  file_W = C:\Users\H\test_file_W.txt
  [PASS] file_W: write content: 5
  [PASS] file_W: read (should fail): blocked -> PermissionError
  file_RW = C:\Users\H\test_file_RW.txt
  [PASS] file_RW: write content: 5
  [PASS] file_RW: read content: hello
  [PASS] file_NONE: read (should fail): blocked -> FileNotFoundError
  [PASS] file_NONE: write (should fail): blocked -> PermissionError

=== Results: 35 passed, 0 failed ===
```

### Allow & Limits Tests

Separate test suite verifying network access, resource limits, timeout, and strict isolation:

```
=== Sandy Allow & Limits Tests ===

--- Network access (allowed) ---
  [PASS] HTTP GET example.com: HTTP 200

--- Memory limit (128 MB) ---
  [PASS] Allocate 50 MB: 50 MB OK
  [PASS] Allocate 1 GB (exceeds 128 MB limit): blocked -> MemoryError

--- Process count limit (3 max) ---
  [PASS] Spawn 1 child: child ok
  [PASS] Spawn 10 children (expect limit enforcement): 2 alive, 8 blocked (limit enforced)

=== Results: 5 passed, 0 failed ===
```

```
--- Timeout test (5 second limit) ---
  [Sandy] Process killed after 5 second timeout.
  [PASS] Timeout: process killed in ~9s

--- Strict mode (system_dirs disabled) ---
  [PASS] Strict mode: execution blocked
```

---

## Audit

The `-a` flag enables Procmon-based resource denial auditing. When a sandboxed process crashes or misbehaves, the audit log shows exactly which resources were denied.

```
sandy.exe -c config.toml -a audit.log -x myapp.exe
```

**Requirements:** [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) on PATH + admin privileges.

Sandy automatically launches Procmon in headless mode, captures all events during the child's lifetime, then parses the results into a filtered audit log containing only denials.

**What's captured:**

| Category | Events |
|----------|--------|
| FILE | File/folder open, read, write, delete denials |
| REG | Registry key/value access denials |
| NET | Network connection blocks |
| IMAGE | DLL/image load failures |
| PROCESS | Child process creation blocks |
| FILE | Named object (mutex, event, section) denials |



**Example audit log:**

```
[13:07:38.12] T:4520   FILE    ACCESS DENIED       C:\Windows\System32\kernel32.dll
[13:07:38.34] T:4520   REG     ACCESS DENIED       HKLM\Software\MyApp
[13:07:38.51] T:4520   FILE    NAME NOT FOUND      api-ms-win-crt-runtime-l1-1-0.dll

=== Process Tree ===
python.exe  PID:4520  exit:0xC0000022  CRASHED
  +- worker.exe  PID:6012  exit:0  OK

=== Summary: 47 unique events, 38 FILE, 3 REG, 4 NET, 2 IMAGE ===

=== Repeated (x count) ===
  x23  FILE    ACCESS DENIED       C:\Windows\System32
```

> [!NOTE]
> The audit log is generated after the child process exits (post-mortem). Events are deduplicated — repeated denials for the same path/result appear once with a repeat count.

---

## Profile

The `-p` flag runs a process **unsandboxed** under [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon), analyzes its resource usage, and generates a feasibility report with a suggested TOML config.

```
sandy.exe -p report.txt -x myapp.exe [args...]
```

**Requirements:** [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) on PATH + admin privileges.

Use profile mode **before** sandboxing an unfamiliar application. It answers:

- **Can this process be sandboxed at all?** (detects HKLM writes, system dir writes)
- **Which sandbox mode works?** (AppContainer, Restricted Low, Restricted Medium)
- **What config is needed?** (read paths, write paths, network, system_dirs, etc.)

**What's analyzed:**

| Category | Detection |
|----------|-----------|
| File reads | Directories the process reads from (collapsed to parent paths) |
| File writes | Directories the process writes to, temp dir usage |
| System writes | Writes to `C:\Windows` or `C:\Program Files` (blocks all modes) |
| User profile writes | Writes to `C:\Users\*` — blocks Restricted Low |
| Registry | HKLM writes (blocks all modes), HKCU writes |
| Network | TCP/UDP connections, localhost, DNS lookups |
| Named pipes | Pipe creation (requires Restricted mode) |
| DLL loading | System DLL dependencies (`system_dirs` detection) |
| Child processes | Process tree tracking |

**Example report:**

```
=== Sandy Profile Report ===
Executable: C:\Python314\python.exe
Exit code:  0 (0x00000000) OK
Events:     3444 total, 2437 file, 1006 reg

--- Verdict ---
Sandboxable:     YES
AppContainer:    YES (recommended)
Restricted Low:  YES
Restricted Med:  YES

--- Required Config ---
  [access] read:
    C:\Users
    C:\repos\myproject
  [access] write:
    C:\Users\H\AppData\Local\Temp
  system_dirs = true

--- Suggested TOML Config ---
[sandbox]
token = 'appcontainer'

[access]
read = ['C:\Users', 'C:\repos\myproject']
write = ['C:\Users\H\AppData\Local\Temp']

[allow]
system_dirs = true
```

> [!NOTE]
> Profile mode captures events using a Procmon include filter for the target process name. For accurate results, avoid running other instances of the same executable during profiling. Subdirectories are automatically collapsed to their common parent.

---

## Notes

> [!WARNING]
> **AppContainer: strict isolation.** Sandy blocks access to system folders (`C:\Windows`, `C:\Program Files`) unless `system_dirs = true` is set in `[allow]`. Most executables need system DLLs to run, so the sample config ships with `system_dirs` enabled. In Restricted Token mode, system directories are always readable.

> [!NOTE]
> **Localhost access** (AppContainer only) requires administrator privileges. Sandy uses `CheckNetIsolation.exe` to manage the loopback exemption. If running without elevation, Sandy prints a warning and continues (localhost will remain blocked).

> [!NOTE]
> **Sandy stderr banner.** Sandy prints a config summary to stderr before running. Use `-q` to suppress it in automation pipelines where stderr is captured.

> [!NOTE]
> **Sandy runs without elevation in most cases.** It modifies folder ACLs to grant the sandbox access, which requires `WRITE_DAC` permission on each configured folder. Users have this permission on folders they own (e.g. under `%USERPROFILE%`). For folders owned by `SYSTEM`, `TrustedInstaller`, or other users, Sandy must be run as Administrator.

---

## Cleanup &amp; Crash Resilience

Sandy never leaves system state dirty. Six resources are tracked and cleaned regardless of how the process exits:

| Resource | Created by | Persistence |
|----------|-----------|-------------|
| **ACL grants** | `[access]` folder/file grants | `HKCU\Software\Sandy\Grants\<UUID>` (write-ahead SDDL) |
| **Registry persistence** | Grant write-ahead log | Same key (cleared with ACLs) |
| **Loopback exemption** | `localhost = true` | In-memory flag + `CheckNetIsolation.exe` |
| **AppContainer profile** | Container creation | OS-managed (`Sandy_<UUID>`) — unique per instance |
| **Scheduled task** | Crash safety net | Task Scheduler (`SandyCleanup`) |
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

1. **Write-ahead logging:** Before modifying any DACL, Sandy persists the original SDDL to `HKCU\Software\Sandy\Grants\<UUID>`. The subkey also stores `_pid` (for liveness checks) and `_container` (AppContainer profile name). WER exe names are stored in `HKCU\Software\Sandy\WER` with PID as value name. Both are written *before* the system state is modified.

2. **Scheduled task safety net:** A `SandyCleanup` scheduled task is created to run `sandy.exe --cleanup` at next logon. It only fires if Sandy didn't clean up normally (crash/power loss). Deleted on clean exit.

3. **Multi-instance safety:** Each instance generates a UUID at startup and creates its own AppContainer profile (`Sandy_<UUID>`) with a unique SID. This means concurrent instances have completely independent file grants that cannot interfere with each other. On exit, an instance only revokes its own ACEs; paths still granted by other live instances are preserved. Registry subkeys use the UUID as the key name, with stored PID for liveness checks during `--cleanup`.

   > **For agents and automation:** Multiple Sandy instances can safely run concurrently with overlapping folder grants. Each instance's sandbox is fully isolated. Use `--status` to inspect active instances and `--cleanup` to clear any stale state.

4. **Stale entry warning:** On startup, Sandy checks for leftover registry entries and warns:
   ```
   [Sandy] WARNING: Stale registry entries detected from a previous crashed run.
           Grants: HKCU\Software\Sandy\Grants   WER: HKCU\Software\Sandy\WER
           Run 'sandy.exe --cleanup' to restore original state.
           If another sandy instance is running, its entries are expected.
   ```

5. **Explicit cleanup only:** Stale state restoration (ACL reverts, WER key removal, AppContainer profile deletion) is performed exclusively by `sandy.exe --cleanup` — never during normal startup. Cleanup only processes entries from dead PIDs, preserving live instances' grants.

> [!IMPORTANT]
> If Sandy is killed via `taskkill /F` or power is lost, run `sandy.exe --cleanup` manually or wait for the next logon (the scheduled task handles it automatically).

---

## Building

Open `sandy.sln` in Visual Studio and build the `x64 Release` configuration. No external dependencies required.

## License

[MIT](LICENSE)
