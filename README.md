<p align="center">
  <img src="sandy_logo.png" alt="Sandy Logo" width="400"/>
</p>

<p align="center">
  <strong>A lightweight Windows AppContainer sandbox runner</strong><br/>
  Run any executable in an isolated sandbox with fine-grained folder access control.
</p>

---

## What is Sandy?

Sandy launches executables inside a [Windows AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation) — the same isolation technology used by UWP apps and Microsoft Edge. By default, sandboxed processes **cannot** access user files, the network, or write to system directories.

You define exactly which folders the sandboxed process can access — and at what level — through a simple TOML config file.

### Key Features

- 🔒 **AppContainer isolation** — kernel-enforced sandbox, not just permissions
- 📁 **Granular folder access** — read, write, or read+write per folder
- 🌐 **Network control** — outbound connections blocked by default, opt-in with `-n`
- 🛡️ **Strict mode** — optionally block reads to system directories (`-s`)
- ⚡ **Zero dependencies** — single native executable, no runtime needed

---

## Usage

```
sandy.exe -c <config.toml> -x <executable> [args...]
```

### Options

| Flag | Description |
|------|-------------|
| `-c <path>` | Path to TOML config file defining folder access |
| `-x <path>` | Path to executable to run sandboxed |
| `-s` | Strict isolation — block system folder reads (`C:\Windows`, `C:\Program Files`, etc.) |
| `-n` | Allow outbound network access |

Arguments after the executable path are forwarded to it.

### Config File Format

```toml
[read]
"C:\path\to\read\only\folder"

[write]
"C:\path\to\write\only\folder"

[readwrite]
"C:\path\to\full\access\folder"
```

### Example

Run Python inside a sandbox, granting read access to a project folder and read+write to a workspace:

```
sandy.exe -c my_config.toml -x C:\Python314\python.exe my_script.py
```

---

## Demo

Full test run showing Sandy's isolation in action — 27 tests, all passing:

```
=== Sandy Sandbox Tests ===
Working dir: c:\repos\sandy\x64\Release
Python:      C:\Users\H\AppData\Local\Programs\Python\Python314\python.exe

--- App folder (read-only) ---
  [PASS] List app folder: 4 items
  [PASS] Create file in app folder: blocked -> PermissionError
  [PASS] Create subfolder in app folder: blocked -> FileExistsError

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

=== Results: 27 passed, 0 failed ===
```

---

## Building

Open `sandy.sln` in Visual Studio and build the `x64 Release` configuration. No external dependencies required.

## License

[MIT](LICENSE)
