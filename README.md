<p align="center">
  <img src="resources/sandy_logo.png" alt="Sandy Logo" width="400"/>
</p>

<p align="center">
  <strong>A lightweight Windows AppContainer sandbox runner</strong><br/>
  Run any executable in an isolated sandbox with fine-grained file and folder access control.
</p>

---

## What is Sandy?

Sandy launches executables inside a [Windows AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation) — the same isolation technology used by UWP apps and Microsoft Edge. By default, sandboxed processes **cannot** access user files, the network, or write to system directories.

A typical use case is running **agentic AI processes** — such as LLM-driven code agents, automation scripts, or tool-use pipelines — in a restricted environment where they can only touch the folders you explicitly allow. Sandy ensures that even if an agent misbehaves, it cannot read your documents, exfiltrate data over the network, or tamper with system files.

All sandbox settings — folder access, permissions, and resource limits — are defined in a single TOML config file.

### Key Features

- 🔒 **AppContainer isolation** — kernel-enforced sandbox, not just permissions
- 📁 **Granular access control** — read, write, or read+write per file or folder
- 🌐 **Network control** — internet, LAN, and localhost independently configurable
- 🛡️ **Locked down by default** — all access is opt-in via config
- ⏱️ **Resource limits** — timeout, memory cap, and process count limits
- ⚡ **Zero dependencies** — single native executable, no runtime needed

---

## Usage

```
sandy.exe -c <config.toml> -x <executable> [args...]
```

| Flag | Description |
|------|-------------|
| `-c <path>` | Path to TOML config file |
| `-x <path>` | Path to executable to run sandboxed |

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
readwrite = [
    'C:\workspace',                    # project folder
    'C:\data\state.db',                # database file
]
```

### Permissions (opt-in)

Everything is blocked unless set to `true` in `[allow]`:

```toml
[allow]
system_dirs = true   # read C:\Windows, Program Files (required for most executables)
# network = true     # outbound internet access
# localhost = true   # loopback/localhost connections                      (admin)
# lan = true         # local network access
```

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
readwrite = [
    'C:\workspace',
]

[allow]
system_dirs = true
network = true

[limit]
timeout = 300
memory = 2048
```

```
sandy.exe -c agent_config.toml -x C:\Python314\python.exe agent.py
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

---

## Notes

> [!WARNING]
> **Strict by default.** Sandy blocks access to system folders (`C:\Windows`, `C:\Program Files`) unless `system_dirs = true` is set in `[allow]`. Most executables need system DLLs to run, so the sample config ships with `system_dirs` enabled. Comment it out only for specialized containers where you explicitly grant the required runtime folders.

> [!NOTE]
> **Localhost access** requires administrator privileges. Sandy uses `CheckNetIsolation.exe` to manage the loopback exemption. If running without elevation, Sandy prints a warning and continues (localhost will remain blocked).

> [!NOTE]
> **Sandy runs without elevation in most cases.** It modifies folder ACLs to grant the AppContainer access, which requires `WRITE_DAC` permission on each configured folder. Users have this permission on folders they own (e.g. under `%USERPROFILE%`). For folders owned by `SYSTEM`, `TrustedInstaller`, or other users, Sandy must be run as Administrator.

---

## Building

Open `sandy.sln` in Visual Studio and build the `x64 Release` configuration. No external dependencies required.

## License

[MIT](LICENSE)
