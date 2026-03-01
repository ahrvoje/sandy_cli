<p align="center">
  <img src="resources/sandy_logo.png" alt="Sandy Logo" width="400"/>
</p>

<p align="center">
  <strong>A lightweight Windows sandbox runner</strong><br/>
  Run any executable in an isolated sandbox with fine-grained file, folder, and network access control.
</p>

---

## What is Sandy?

Sandy launches executables inside a kernel-enforced Windows sandbox. Two isolation modes are supported: [AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation) (the same technology used by UWP apps and Edge) and **Restricted Token** (restricting SIDs with configurable integrity level). By default, sandboxed processes **cannot** access user files, the network, or write to system directories.

Modern agentic AI workflows — LLM-driven code agents, automation scripts, tool-use pipelines — need to execute code, but running them with full user privileges is reckless, and spinning up a VM or container for every script is heavyweight. Sandy strikes a practical balance: **unprivileged sandboxing** that works on any Windows machine without admin rights, Docker, WSL, or Hyper-V. You define exactly which folders, files, and network access the process gets — everything else is blocked at the kernel level.

Think of it as the lean middle ground between *running scripts completely unprotected* and *deploying a full OS-level sandbox*. Purpose-built for the agentic era, Sandy lets you run untrusted scripts with confidence in a single command.

### Key Features

- 🔒 **Dual sandbox modes** — AppContainer isolation or Restricted Token with configurable integrity
- 📁 **Granular access control** — read, write, execute, append, delete, or full access per file or folder
- 🌐 **Network control** — internet, LAN, and localhost independently configurable (AppContainer)
- 🛡️ **Locked down by default** — all access is opt-in via config
- ⏱️ **Resource limits** — timeout, memory cap, and process count limits
- 📝 **Session logging** — log config, process output, and exit code to file
- ⚡ **Zero dependencies** — single native executable, no runtime needed

---

## Usage

```
sandy.exe -c <config.toml> [-l <logfile>] -x <executable> [args...]
sandy.exe -s "<toml>"      [-l <logfile>] -x <executable> [args...]
```

| Flag | Description |
|------|-------------|
| `-c`, `--config <path>` | Path to TOML config file |
| `-s`, `--string <toml>` | Inline TOML config string (alternative to `-c`) |
| `-l`, `--log <path>` | Log file for session output, config, and exit code |
| `-x`, `--exec <path>` | Executable to run sandboxed (consumes remaining args) |
| `-q`, `--quiet` | Suppress the config banner on stderr |
| `-v`, `--version` | Print version and exit |
| `-h`, `--help` | Print full help text with config reference and exit |
| `--` | End of options; next arg is the executable |

Arguments after the executable path are forwarded to it.

---

## Config File

All sandbox behavior is controlled by a TOML config. Every config **must** include a `[sandbox]` section declaring the token mode. Mode-specific settings are validated — using a flag meant for the other mode is an error.

See [`sandy_config.toml`](sandy_config.toml) for the default template, [`sandy_config_appcontainer.toml`](sandy_config_appcontainer.toml) and [`sandy_config_restricted.toml`](sandy_config_restricted.toml) for mode-specific templates.

### `[sandbox]` — Mode selection *(mandatory)*

```toml
[sandbox]
token = "appcontainer"    # or "restricted"
integrity = "low"         # restricted only: "low" (default) or "medium"
```

| Key | Values | Modes | Description |
|-----|--------|-------|-------------|
| `token` | `"appcontainer"`, `"restricted"` | both | Sandbox isolation model *(required)* |
| `integrity` | `"low"`, `"medium"` | restricted | Integrity level · `"low"` = strongest isolation, `"medium"` = wider app compatibility |

### `[access]` — File and folder grants

Grant the sandboxed process access to specific files or folders. Paths are recursive for directories.

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
| `write` | Create and modify files |
| `execute` | Execute (no read) |
| `append` | Append only (no overwrite, no read) |
| `delete` | Delete only |
| `all` | Full access (read + write + execute + delete) |

### `[allow]` — Opt-in permissions

Everything is blocked unless set to `true`. Settings are validated against the active mode.

```toml
[allow]
system_dirs = true    # appcontainer only
network = true        # appcontainer only
localhost = true      # appcontainer only (admin required)
lan = true            # appcontainer only
named_pipes = true    # restricted only
stdin = false         # both modes
```

| Key | Modes | Default | Description |
|-----|-------|---------|-------------|
| `system_dirs` | appcontainer | `false` | Read access to `C:\Windows`, `Program Files` |
| `network` | appcontainer | `false` | Outbound internet access |
| `localhost` | appcontainer | `false` | Loopback connections (requires admin) |
| `lan` | appcontainer | `false` | Local network access |
| `named_pipes` | restricted | `false` | Named pipe creation (`CreateNamedPipeW`) |
| `stdin` | both | `true` | Inherit stdin (set `false` to redirect to NUL) |

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

Control which environment variables the sandboxed process inherits.

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
timeout = 300       # kill process after N seconds
memory = 4096       # max memory in MB
processes = 10      # max concurrent child processes
```

### Config availability summary

| Section / Key | AppContainer | Restricted |
|---------------|:------------:|:----------:|
| **`[sandbox]`** | ✅ required | ✅ required |
| &ensp; `token` | ✅ required | ✅ required |
| &ensp; `integrity` | ❌ error | ✅ optional (default: `"low"`) |
| **`[access]`** | ✅ optional | ✅ optional |
| **`[allow]`** | ✅ optional | ✅ optional |
| &ensp; `system_dirs` | ✅ | ❌ error |
| &ensp; `network` | ✅ | ❌ error |
| &ensp; `localhost` | ✅ | ❌ error |
| &ensp; `lan` | ✅ | ❌ error |
| &ensp; `named_pipes` | ❌ error | ✅ |
| &ensp; `stdin` | ✅ | ✅ |
| **`[registry]`** | ❌ error | ✅ optional |
| **`[environment]`** | ✅ optional | ✅ optional |
| **`[limit]`** | ✅ optional | ✅ optional |

---

## Sandbox Modes

**🔒** = fundamental OS limitation &nbsp;&nbsp; **→** = fixed (not configurable) &nbsp;&nbsp; **⚙️** = configurable via TOML

| Aspect | AppContainer | Restricted Token |
|--------|--------------|------------------|
| **Integrity level** | → Low (OS-enforced) | ⚙️ `integrity` · `"low"` or `"medium"` (default: `"low"`) |
| **Named pipes** | 🔒 Blocked (kernel prohibits at Low IL) | ⚙️ `named_pipes` · default: blocked |
| **Network** | ⚙️ `network` `localhost` `lan` · default: blocked | 🔒 Unrestricted (no capability model) |
| **Object namespace** | 🔒 Isolated (private per-container namespace) | 🔒 Shared (global namespace) |
| **System dirs** (Windows, Program Files) | ⚙️ `system_dirs` · default: blocked | → Always readable (Users SID in restricting list) |
| **User profile** (Desktop, Documents, etc.) | → Blocked (AppContainer SID excluded) | → Blocked at `"low"` IL · accessible at `"medium"` |
| **Registry** | → Private hive (reads OK, writes to HKLM/HKCU blocked) | ⚙️ `[registry]` `read`/`write` · most keys readable by default |
| **COM/RPC servers** | 🔒 Most reject AppContainer callers | → Accessible |
| **Process identity** | 🔒 AppContainer SID (different principal) | → User SID (same principal, restricted) |
| **Elevation** | 🔒 Cannot escalate | 🔒 Cannot escalate |
| **File/folder grants** | ⚙️ `[access]` | ⚙️ `[access]` |
| **Privilege stripping** | → All stripped | → All stripped except `SeChangeNotifyPrivilege` |
| **Environment** | ⚙️ `[environment]` | ⚙️ `[environment]` |
| **Resource limits** | ⚙️ `[limit]` | ⚙️ `[limit]` |
| **Stdin** | ⚙️ `stdin` · default: inherited | ⚙️ `stdin` · default: inherited |

> [!NOTE]
> **Integrity × compatibility trade-off** (restricted mode only):

| | Low | Medium | Nature |
|---|---|---|---|
| **Write to user files** | ❌ Blocked by mandatory IL | ✅ Allowed (User SID matches) | 🔒 Fundamental |
| **DLL/API set resolution** | ❌ Breaks some apps (Python 3.14+) | ✅ Works | 🔒 Fundamental |
| **User profile access** | ❌ Blocked | ✅ Accessible | 🔒 Fundamental |
| **Isolation layers** | 2 (SIDs + integrity) | 1 (SIDs only) | 🔒 Fundamental |
| **System dir reads** | ✅ Always readable | ✅ Always readable | → Fixed |
| **System dir writes** | ❌ Blocked | ❌ Blocked | → Fixed |
| **Named pipes** | ⚙️ Configurable | ⚙️ Configurable | ⚙️ Configurable |
| **Network** | ✅ Unrestricted | ✅ Unrestricted | 🔒 Fundamental |

**Use AppContainer** when you need network isolation and don't require named pipes or COM.
**Use Restricted Token** when the sandboxed app needs named pipes (Flutter, Chromium, Mojo) or COM/RPC.

### Examples

AppContainer with network access:

```toml
[sandbox]
token = "appcontainer"

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
token = "restricted"
integrity = "medium"

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

## Notes

> [!WARNING]
> **AppContainer: strict by default.** Sandy blocks access to system folders (`C:\Windows`, `C:\Program Files`) unless `system_dirs = true` is set in `[allow]`. Most executables need system DLLs to run, so the sample config ships with `system_dirs` enabled. In Restricted Token mode, system directories are always readable.

> [!NOTE]
> **Localhost access** (AppContainer only) requires administrator privileges. Sandy uses `CheckNetIsolation.exe` to manage the loopback exemption. If running without elevation, Sandy prints a warning and continues (localhost will remain blocked).

> [!NOTE]
> **Sandy runs without elevation in most cases.** It modifies folder ACLs to grant the sandbox access, which requires `WRITE_DAC` permission on each configured folder. Users have this permission on folders they own (e.g. under `%USERPROFILE%`). For folders owned by `SYSTEM`, `TrustedInstaller`, or other users, Sandy must be run as Administrator.

---

## Building

Open `sandy.sln` in Visual Studio and build the `x64 Release` configuration. No external dependencies required.

## License

[MIT](LICENSE)
