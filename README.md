<p align="center">
  <img src="resources/sandy_logo.png" alt="Sandy Logo" width="400"/>
</p>

<p align="center">
  <strong>A lightweight Windows AppContainer sandbox runner</strong><br/>
  Run any executable in an isolated sandbox with fine-grained file and folder access control.
</p>

---

## What is Sandy?

Sandy launches executables inside a [Windows AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation) — the same kernel-enforced isolation technology used by UWP apps and Microsoft Edge. By default, sandboxed processes **cannot** access user files, the network, or write to system directories.

Modern agentic AI workflows — LLM-driven code agents, automation scripts, tool-use pipelines — need to execute code, but running them with full user privileges is reckless, and spinning up a VM or container for every script is heavyweight. Sandy strikes a practical balance: **unprivileged sandboxing** that works on any Windows machine without admin rights, Docker, WSL, or Hyper-V. You define exactly which folders, files, and network access the process gets — everything else is blocked at the kernel level.

Think of it as the lean middle ground between *running scripts completely unprotected* and *deploying a full OS-level sandbox*. Purpose-built for the agentic era, Sandy lets you run untrusted scripts with confidence in a single command.

### Key Features

- 🔒 **AppContainer isolation** — kernel-enforced sandbox, not just permissions
- 📁 **Granular access control** — read, write, or read+write per file or folder
- 🌐 **Network control** — internet, LAN, and localhost independently configurable
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

All sandbox behavior is controlled by the TOML config. See [`sandy_config.toml`](sandy_config.toml) for a complete reference.

### Access

```toml
[access]
read = [
    'C:\data\config.json',             # single file
    'C:\Python314',                    # entire folder (recursive)
]
write = [
    'C:\logs\agent.log',               # single log file
    'C:\temp\output',                  # output folder
]
execute = ['C:\tools\bin']              # execute-only (no read)
append = ['C:\logs\audit.log']          # append-only (no overwrite)
delete = ['C:\temp\scratch']            # delete-only
all = ['C:\workspace']                  # full access
```

### Permissions (opt-in)

Everything is blocked unless set to `true` in `[allow]`:

```toml
[allow]
system_dirs = true   # read C:\Windows, Program Files (required for most executables)
# network = true     # outbound internet access
# localhost = true   # loopback/localhost connections                      (admin)
# lan = true         # local network access
# registry = true    # access user registry keys
# pipes = true       # access named pipes
# stdin = false      # block stdin (redirect to NUL)
```

#### What `system_dirs` exposes

`system_dirs` enables the Windows `ALL_APPLICATION_PACKAGES` group, granting **read-only** access to:

| Path | Access |
|------|--------|
| `C:\Windows` | ✅ read (115 items) |
| `C:\Windows\System32` | ✅ read (5,028 items) |
| `C:\Windows\SysWOW64` | ✅ read (3,105 items) |
| `C:\Windows\Temp` | ❌ blocked |
| `C:\Program Files` | ✅ read |
| `C:\Program Files (x86)` | ✅ read |
| `C:\ProgramData` | ❌ blocked |
| `C:\Users` | ❌ blocked |
| User profile (Desktop, Documents, Downloads) | ❌ blocked |
| `C:\` root | ❌ blocked |

Any other directory whose installer added `ALL_APPLICATION_PACKAGES` to its ACL will also be readable — for example, Python's Windows installer does this for its install folder. Writes are blocked everywhere.

### Environment

Control which environment variables the sandboxed process can see:

```toml
[environment]
inherit = false                          # don't inherit parent env vars
pass = ['PATH', 'PYTHONPATH', 'HOME']    # specific vars to pass through
```

When `inherit = false`, only essential Windows vars (`SYSTEMROOT`, `SYSTEMDRIVE`, `TEMP`, `TMP`) and the vars listed in `pass` are provided to the child process.

### Resource Limits

```toml
[limit]
# timeout = 300      # kill process after N seconds
# memory = 4096      # max memory in MB
# processes = 10     # max concurrent child processes
```

### Example

Run Python inside a sandbox with read access to a project folder and a 5-minute timeout:

```toml
[access]
read = [
    'C:\Python314',
    'C:\projects\my_agent',
]
all = [
    'C:\workspace',
]

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

---

## Logging

Use `-l <path>` to capture the full sandbox session — configuration, child process output, and exit status — into a log file:

```
sandy.exe -c config.toml -l session.log -x python.exe script.py
```

The log file contains:

```
=== Sandy Log ===

--- Configuration ---
Executable: C:\Python314\python.exe
Arguments:  script.py
Folders:    3 configured
  [R]  C:\Python314
  [RW] C:\workspace
  [W]  C:\logs
Network:     allowed
Timeout:     300 seconds
Memory:      2048 MB

--- Process Output ---
PID: 12345
... (full child stdout/stderr) ...

--- Process Exit ---
Exit code: 0 (0x00000000)
=== Log end ===
```

This is useful for post-mortem analysis — access denied errors (e.g. Python's `PermissionError`) appear in the process output section alongside all other child output.

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
> **Strict by default.** Sandy blocks access to system folders (`C:\Windows`, `C:\Program Files`) unless `system_dirs = true` is set in `[allow]`. Most executables need system DLLs to run, so the sample config ships with `system_dirs` enabled. Comment it out only for specialized containers where you explicitly grant the required runtime folders.

> [!NOTE]
> **Python note.** Python's Windows installer sets the `ALL_APPLICATION_PACKAGES` ACL on its install directory. This means that with `system_dirs = true`, the entire Python folder (DLLs, stdlib, `Lib/`, `Scripts/`) is readable even without an explicit `[access]` entry. You do not need to grant the Python folder — only `system_dirs = true` is required.

> [!NOTE]
> **Localhost access** requires administrator privileges. Sandy uses `CheckNetIsolation.exe` to manage the loopback exemption. If running without elevation, Sandy prints a warning and continues (localhost will remain blocked).

> [!NOTE]
> **Sandy runs without elevation in most cases.** It modifies folder ACLs to grant the AppContainer access, which requires `WRITE_DAC` permission on each configured folder. Users have this permission on folders they own (e.g. under `%USERPROFILE%`). For folders owned by `SYSTEM`, `TrustedInstaller`, or other users, Sandy must be run as Administrator.

---

## Building

Open `sandy.sln` in Visual Studio and build the `x64 Release` configuration. No external dependencies required.

## License

[MIT](LICENSE)
