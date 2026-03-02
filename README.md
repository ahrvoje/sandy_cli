<p align="center">
  <img src="resources/sandy_logo.png" alt="Sandy Logo" width="400"/>
</p>

<p align="center">
  <strong>A lightweight Windows sandbox runner</strong><br/>
  Run any executable in an isolated sandbox with fine-grained file, folder, and network access control.
</p>

---

## What is Sandy?

Sandy launches executables inside a kernel-enforced Windows sandbox — no elevation required. Two isolation modes are supported: [AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation) (the same technology used by UWP apps and Edge) and **Restricted Token** (restricting SIDs with configurable integrity level). Each mode starts with its most restrictive defaults and is loosened via TOML config.

No VMs, Docker, WSL, or Hyper-V — just a single native executable. Sandy is lean, unprivileged sandboxing for agentic AI workflows, automation scripts, and tool-use pipelines: you define exactly which folders, files, and network access the process gets.

### Key Features

- 🔒 **Dual sandbox modes** — AppContainer or Restricted Token with configurable integrity
- 📁 **Granular access control** — read, write, execute, append, delete, or full access per file or folder
- 🌐 **Network control** — internet, LAN, and localhost independently configurable (AppContainer)
- 🛡️ **Hardened by default** — most restrictive configuration out of the box, loosened via config
- ⏱️ **Resource limits** — timeout, memory cap, and process count limits
- 📝 **Audit logging** — session logs, Procmon-based denial auditing, and crash dumps
- ⚡ **Zero dependencies** — single native executable, no runtime needed

---

## Usage

```
sandy.exe -c <config.toml> [-l <logfile>] [-a <auditlog>] [-d <dumpfile>] [-q] -x <executable> [args...]
sandy.exe -s "<toml>"      [-l <logfile>] [-a <auditlog>] [-d <dumpfile>] [-q] -x <executable> [args...]
sandy.exe -p <report>       -x <executable> [args...]
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
| `-v`, `--version` | Print version and exit |
| `-h`, `--help` | Print full help text with config reference and exit |

All sandy flags must come **before** `-x`. Arguments after `-x <executable>` are forwarded to it. Sandy forwards the child process's exit code.

---

## Config File

All sandbox behavior is controlled by a TOML config. Every config **must** include a `[sandbox]` section declaring the token mode. Use `-c` or `-s` (mutually exclusive). Mode-specific settings are validated — using a flag meant for the other mode is an error. All paths must be absolute.

See [`sandy_config.toml`](sandy_config.toml) for the default template, [`sandy_config_appcontainer.toml`](sandy_config_appcontainer.toml) and [`sandy_config_restricted.toml`](sandy_config_restricted.toml) for mode-specific templates.

### `[sandbox]` — Mode selection *(mandatory)*

```toml
[sandbox]
token = 'appcontainer'    # or 'restricted'
integrity = 'low'         # restricted only: 'low' (default) or 'medium'
workdir = 'C:\projects'   # child working directory (default: sandy.exe folder)
```

| Key | Values | Modes | Description |
|-----|--------|-------|-------------|
| `token` | `'appcontainer'`, `'restricted'` | both | Sandbox isolation model *(required)* |
| `integrity` | `'low'`, `'medium'` | restricted | Integrity level · `'low'` = strongest isolation, `'medium'` = wider app compatibility |
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

### `[allow]` — Opt-in permissions

Each option defaults to its most restrictive value for the active mode. Set to `true` to loosen. Settings are validated against the active mode.

```toml
[allow]
system_dirs     = true   # appcontainer only
network         = true   # appcontainer only
localhost       = true   # appcontainer only (admin required)
lan             = true   # appcontainer only
named_pipes     = true   # restricted only
stdin           = false  # both modes
clipboard_read  = false  # both modes (default: true)
clipboard_write = false  # both modes (default: true)
child_processes = false  # both modes (default: true)
```

| Key | Modes | Default | Description |
|-----|-------|---------|-------------|
| `system_dirs` | appcontainer | `false` | Read access to `C:\Windows`, `Program Files` |
| `network` | appcontainer | `false` | Outbound internet access |
| `localhost` | appcontainer | `false` | Loopback connections (requires admin) |
| `lan` | appcontainer | `false` | Local network access |
| `named_pipes` | restricted | `false` | Named pipe creation (`CreateNamedPipeW`) |
| `stdin` | both | `true` | `true` = inherit, `false` = disabled (NUL), or a file path |
| `clipboard_read` | both | `true` | Allow reading from the clipboard |
| `clipboard_write` | both | `true` | Allow writing to the clipboard |
| `child_processes` | both | `true` | Allow spawning child processes (kernel-enforced) |

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

### `[environment]` — Environment variables

By default, the child inherits the full parent environment. Set `inherit = false` to pass only essential Windows variables plus those listed in `pass`. The `pass` list has no effect when `inherit = true` (default).

```toml
[environment]
inherit = false
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
| **`[sandbox]`** | ✅ required | ✅ required |
| &ensp; `token` | ✅ required | ✅ required |
| &ensp; `integrity` | ❌ error | ✅ optional (default: `'low'`) |
| &ensp; `workdir` | ✅ optional | ✅ optional |
| **`[access]`** | ✅ optional | ✅ optional |
| **`[allow]`** | ✅ optional | ✅ optional |
| &ensp; `system_dirs` | ✅ | ❌ error |
| &ensp; `network` | ✅ | ❌ error |
| &ensp; `localhost` | ✅ | ❌ error |
| &ensp; `lan` | ✅ | ❌ error |
| &ensp; `named_pipes` | ❌ error | ✅ |
| &ensp; `stdin` | ✅ (`true`/`false`/path) | ✅ (`true`/`false`/path) |
| &ensp; `clipboard_read` | ✅ | ✅ |
| &ensp; `clipboard_write` | ✅ | ✅ |
| &ensp; `child_processes` | ✅ | ✅ |
| **`[registry]`** | ❌ error | ✅ optional |
| **`[environment]`** | ✅ optional | ✅ optional |
| **`[limit]`** | ✅ optional | ✅ optional |

---

## Sandbox Modes

Merged view across AppContainer and Restricted Token (Low / Medium integrity). ❌ = blocked · ✅ = allowed · ⚙️ = configurable via TOML.

| Aspect | AppContainer | Restricted Low | Restricted Medium |
|--------|:------------:|:--------------:|:-----------------:|
| **Integrity level** | ❌ Low (fixed) | ❌ Low | ❌ Medium |
| **Named pipes** | ❌ Blocked | ⚙️ `named_pipes` | ⚙️ `named_pipes` |
| **Network** | ⚙️ `network` `lan` `localhost` | ✅ Unrestricted | ✅ Unrestricted |
| **Object namespace** | ❌ Isolated | ✅ Shared | ✅ Shared |
| **System dir reads** | ⚙️ `system_dirs` | ✅ Always | ✅ Always |
| **System dir writes** | ❌ Blocked | ❌ Blocked | ❌ Blocked |
| **User profile reads** | ❌ Blocked | ✅ Allowed | ✅ Allowed |
| **User profile writes** | ❌ Blocked | ❌ Blocked (IL) | ✅ Allowed |
| **Registry reads** | ✅ Private hive | ✅ Most keys | ✅ Most keys |
| **Registry HKCU writes** | ❌ Blocked | ❌ Blocked (IL) | ✅ Allowed |
| **Registry HKLM writes** | ❌ Blocked | ❌ Blocked | ❌ Blocked |
| **DLL/API set resolution** | ✅ Works | ❌ Breaks some apps | ✅ Works |
| **COM/RPC servers** | ❌ Most blocked | ✅ Accessible | ✅ Accessible |
| **Scheduled tasks** | ❌ Blocked | ❌ Blocked (IL) | ✅ Allowed |
| **Window messages (UIPI)** | ❌ Blocked | ❌ Blocked (IL) | ✅ Allowed |
| **Process identity** | ❌ AppContainer SID | ❌ User SID (restricted) | ❌ User SID (restricted) |
| **Elevation** | ❌ Cannot escalate | ❌ Cannot escalate | ❌ Cannot escalate |
| **Privilege stripping** | ❌ All stripped | ❌ All except `SeChangeNotify` | ❌ All except `SeChangeNotify` |
| **Isolation layers** | 2 (SID + namespace) | 2 (SIDs + integrity) | 1 (SIDs only) |
| **Clipboard** | ⚙️ default: allowed | ⚙️ default: allowed | ⚙️ default: allowed |
| **Child processes** | ⚙️ default: allowed | ⚙️ default: allowed | ⚙️ default: allowed |
| **File/folder grants** | ⚙️ `[access]` | ⚙️ `[access]` | ⚙️ `[access]` |
| **Stdin** | ⚙️ default: inherited | ⚙️ default: inherited | ⚙️ default: inherited |
| **Environment** | ⚙️ `[environment]` | ⚙️ `[environment]` | ⚙️ `[environment]` |
| **Resource limits** | ⚙️ `[limit]` | ⚙️ `[limit]` | ⚙️ `[limit]` |

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
stdin = false

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
> **AppContainer: strict by default.** Sandy blocks access to system folders (`C:\Windows`, `C:\Program Files`) unless `system_dirs = true` is set in `[allow]`. Most executables need system DLLs to run, so the sample config ships with `system_dirs` enabled. In Restricted Token mode, system directories are always readable.

> [!NOTE]
> **Localhost access** (AppContainer only) requires administrator privileges. Sandy uses `CheckNetIsolation.exe` to manage the loopback exemption. If running without elevation, Sandy prints a warning and continues (localhost will remain blocked).

> [!NOTE]
> **Sandy stderr banner.** Sandy prints a config summary to stderr before running. Use `-q` to suppress it in automation pipelines where stderr is captured.

> [!NOTE]
> **Sandy runs without elevation in most cases.** It modifies folder ACLs to grant the sandbox access, which requires `WRITE_DAC` permission on each configured folder. Users have this permission on folders they own (e.g. under `%USERPROFILE%`). For folders owned by `SYSTEM`, `TrustedInstaller`, or other users, Sandy must be run as Administrator.

---

## Crash Resilience

Sandy is hardened against abnormal termination. On startup, it proactively cleans up any stale state from a previous crashed run (AppContainer profile, loopback exemptions, WER registry keys). A console signal handler catches Ctrl+C, Ctrl+Break, and window close events to ensure cleanup runs before exit. A top-level structured exception handler catches fatal errors in sandy itself. Combined, these ensure system state is never left dirty regardless of how sandy exits.

---

## Building

Open `sandy.sln` in Visual Studio and build the `x64 Release` configuration. No external dependencies required.

## License

[MIT](LICENSE)
