---
description: General coding style, architecture guidelines, and critical dos/don'ts for Sandy CLI
---

# Prerequisite Reading

**Before modifying any Sandy source code, read these files first:**

| File | Covers |
|------|--------|
| `.agents/acl_design.md` | ACL grant/deny design, mask math, PROTECTED_DACL, multi-instance safety |
| `.agents/resilience.md` | Cleanup, crash recovery, signal handling, registry persistence |
| `.agents/guidelines.md` | This file — general rules, logging, documentation |

These files contain **verified conclusions from previous work**. Decisions
documented there (e.g. why DENY ACEs cannot be used for AppContainer) are
**settled facts, not suggestions**. Violating them will introduce bugs that
have already been discovered, debugged, and fixed.

# Logging

- **All actions affecting any OS item** (files, registry, DACLs, processes, tokens,
  profiles, network rules) **must be logged via `g_logger.Log()` or `g_logger.LogFmt()`**.
- **Use `g_logger.LogFmt(fmt, ...)` for formatted messages** — never the manual
  `{ wchar_t buf[N]; swprintf(...); g_logger.Log(buf); }` pattern.
  `LogFmt` uses a 1024-char stack buffer for the common case and automatically
  switches to a dynamically-sized heap buffer for longer messages. A truncation
  counter is reported at session close via `LOG_DIAG`.
- **Never use stdout/stderr for operational logging** if `g_logger` can cover it.
  `printf`/`wprintf` is only for user-facing CLI output (banner, status, help).
  Everything else goes through the logger.

# Encoding

- **Never use UTF-16 for output.** No `_O_U16TEXT`, no `_setmode` to wide mode.
  All user-facing CLI output (stdout/stderr) must be ASCII or UTF-8.
- **Use `printf` with `%ls`** for user-facing output that includes wide strings.
  MSVC `printf` handles `%ls` natively, producing clean ASCII/UTF-8 bytes that
  work with cmd redirect, `findstr`, and piping.
- **Internal logging** (`fwprintf` to log files opened by Sandy) is fine as-is —
  the file handle encoding is controlled internally.

# AppContainer vs Restricted Token

These two sandbox modes have fundamentally different security models.
**Always be aware of which mode you are working with** before modifying
ACL, token, or cleanup logic.

| Aspect | AppContainer | Restricted Token |
|--------|-------------|-----------------|
| SID | Unique per instance (`S-1-15-2-*`) | Unique per instance (`S-1-9-*`) |
| DENY ACEs | **Ignored by kernel** | Honored normally |
| Deny mechanism | Allow-token arithmetic (mask reduction) | Real `DENY_ACCESS` ACEs |
| Cleanup | Remove ACEs by SID — zero interference | Remove ACEs by SID — zero interference |

# DENY Rules — INVARIANT

> [!CAUTION]
> **AXIOM: The Windows kernel does NOT evaluate `DENY_ACCESS` ACEs for
> AppContainer SIDs.** This is a property of the OS, not a design choice.
> It cannot be worked around, tested around, or reasoned around.
> It is as immutable as `1 + 1 = 2`.

**Consequences (all mandatory, no exceptions):**

1. `DENY_ACCESS` / `DENY_ACCESS` ACEs **must never** be placed on any object
   for an AppContainer SID. They have zero effect and pollute the DACL.
2. AppContainer deny is implemented **exclusively** via Allow-token arithmetic:
   read the existing ALLOW ACE mask, subtract denied bits, write back a
   reduced ALLOW ACE. See `acl_design.md` §"Deny Subtraction".
3. `PROTECTED_DACL_SECURITY_INFORMATION` **must** be set on denied paths
   to prevent parent ALLOW inheritance from overriding the reduced mask.
4. `TREE_SEC_INFO_RESET` **must** be used (not `SET`) for denied directory
   propagation to fully replace DACLs including inherited entries.
5. Restricted Token mode uses real `DENY_ACCESS` ACEs — the kernel evaluates
   DENY before ALLOW as expected. This path is completely separate.

**If you are about to write `DENY_ACCESS` + AppContainer in the same code
path, STOP. You are about to write dead code that will pass no test.**

# Documentation

- **All user options and critical behavior must be documented.**
- Documentation lives in **two places** — keep both in sync:
  1. **`README.md`** — full reference with examples, rationale, and edge cases.
  2. **`--help` output** (in `SandboxCLI.h`) — concise but fully informative on
     usage and critical side-effects. Users must be able to use Sandy correctly
     from `--help` alone without reading the README.
  - Help text separates **guaranteed** cleanup (ACE removal, profile deletion,
    loopback, instance registry key) from **permanent** state (parent keys
    Sandy, Grants, WER, Profiles — never deleted by cleanup) and **best-effort** cleanup
    (stale tasks, desktop/WinSta ACL). Documents **mode trust boundaries**
    (AC vs RT-low vs RT-medium).

# TOML Configuration — Optional Defaults

Most TOML settings are **optional** with restrictive defaults. Only `[sandbox]`
section and `token` key are always mandatory. Omitting a field **never grants
more access** — defaults are deny-all / disabled / unlimited.

## Mandatory Fields

| Field | When | Values |
|-------|------|--------|
| `[sandbox]` section | Always | Must be present |
| `token` | Always | `'appcontainer'` or `'restricted'` |
| `integrity` | Restricted only | `'low'` or `'medium'` |

## Optional Fields and Defaults

| Section | Key | Default | Notes |
|---------|-----|---------|-------|
| `[sandbox]` | `workdir` | `'inherit'` (exe folder) | |
| `[allow]` | `peek/read/write/execute/append/delete/all` | `[]` | No grants |
| `[deny]` | `read/write/execute/append/delete/all` | `[]` | No denies |
| `[privileges]` | `system_dirs` | `true` | AC only — false breaks most apps |
| `[privileges]` | `network` | `false` | AC only |
| `[privileges]` | `localhost` | `false` | AC only, needs admin |
| `[privileges]` | `lan` | `false` | AC only |
| `[privileges]` | `named_pipes` | `false` | RT only |
| `[privileges]` | `stdin` | `false` | `false`=NUL, `true`=inherit, path=file |
| `[privileges]` | `clipboard_read` | `false` | |
| `[privileges]` | `clipboard_write` | `false` | |
| `[privileges]` | `child_processes` | `true` | false breaks most apps |
| `[registry]` | `read/write` | `[]` | RT only |
| `[environment]` | `inherit` | `false` | filtered env |
| `[environment]` | `pass` | `[]` | |
| `[limit]` | `timeout/memory/processes` | `0` | 0 = no limit |

## Rules

- **Wrong-mode keys are rejected.** For example, `named_pipes` in an
  AppContainer config or `network` in a Restricted config → configuration error.
- **Unknown keys/sections are rejected.** Typos and unsupported keys → error.
- A minimal valid config is just 2-3 lines:
  ```toml
  [sandbox]
  token = 'appcontainer'
  ```

# Test Structure

- Tests use the **toml + py + bat** stack:
  - **`.toml`** — sandbox configuration (one per mode/scenario)
  - **`.py`** — probe script run inside the sandbox (tests access, writes markers)
  - **`.bat`** — orchestrator (manages lifecycle, DACL snapshots, assertions)
- Not all three are always needed, but **never inline TOML or Python into
  the `.bat` file**. Keep them as separate files.

## Test Header — MANDATORY

Every test `.bat` must start with this header (after `@echo off` / `setlocal`):

```batch
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
```

Do **not** set window titles in tests. Audit tests (`test_audit.bat`,
`test_audit_rt.bat`) require admin elevation and Procmon — they are excluded
from `run_all_tests.bat` and must be run standalone.

## Test Safety — Zero Side-Effects

Tests **must not** produce any side-effect on Sandy production data, other
running processes, or the host platform. Every rule below is mandatory.

### Registry

- **Never read, write, or delete** production keys under `HKCU\Software\Sandy`
  or `HKCU\Software\Sandy\Grants` — **except** for `--status` tests, which
  must inject stale entries into production paths (`Grants\<pid>`, `WER`)
  because `--status` only reads production keys.
- All other test-specific registry entries go under **`HKCU\Software\Sandy\Test`**.
- Cleanup of test keys is handled by `sandy --cleanup`
  (which calls `RegDeleteTreeW` on `Software\Sandy\Test`).
- **Parent keys are permanent.** Tests verifying cleanup must check for
  specific subkey/value removal, not parent key non-existence. An empty
  `Grants` or `WER` key with zero children is the expected clean state.


### Process Management

- **Never run blanket `taskkill /f /im sandy.exe`** or
  `taskkill /f /im python.exe` — this kills production instances and
  unrelated Python processes.
- All process termination **must target a precise PID** obtained during the
  test run (e.g. `taskkill /f /pid %SANDY_PID%`).
- If a test needs to confirm a process is gone, check by PID, not by image
  name.

### General

- Tests must not create, modify, or delete files outside the test's own
  working directory (`test\`) and the system `%TEMP%` folder.
- Tests must clean up all temporary files and directories they create.
- Scheduled tasks created by tests must be deleted by the same test on exit.

# Architecture — Pipeline Structure

`Sandbox.h` implements a **single linear pipeline** (`RunPipeline`) in 5 phases:

| Phase | Name | Key functions |
|-------|------|---------------|
| 1 | SETUP | `SetupAppContainer()` or `SetupRestrictedToken()` → `SetupResult` |
| 2 | GRANT | `ApplyAccessPipeline` (depth-sorted allow+deny), `GrantRegistryAccess` |
| 3 | PREPARE | `BuildCapabilities`, `BuildAttributeList`, `BuildEnvironmentBlock` |
| 4 | LAUNCH | `LaunchChildProcess`, `AssignJobObject`, `WaitForChildExit` |
| 5 | CLEANUP | `SandboxGuard::RunAll()`, `DeleteCleanupTask` |

- **Phase 1** is dispatched via `SetupAppContainer`/`SetupRestrictedToken` which
  return a flat `SetupResult` struct. Mode logic is contained inside these helpers.
- **All cleanup** is managed by `SandboxGuard` (RAII) — cleanup actions are registered
  via `guard.Add(lambda)` and execute in reverse order on scope exit or explicit
  `RunAll()`.
- **Entry point**: `RunSandboxed()` → generates instance ID, starts logger,
  cleans stale state → calls `RunPipeline()`.

# Shell Environment

- Sandy development runs under **PowerShell Constrained Language Mode**.
  Most `.ps1` scripts will not execute. Use `.bat` files for test
  orchestration and automation.
- For **UAC elevation**, use VBScript (`ShellExecute "runas"`) — this works
  reliably under Constrained Language Mode where PowerShell elevation methods
  are blocked.

# Build

The only reliable build command:

```
& 'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe' sandy.sln /p:Configuration=Release /p:Platform=x64 /v:minimal
```

- Solution file: `sandy.sln` in repo root.
- Output: `x64\Release\sandy.exe`.
- **Do not** use `devenv`, `cl.exe`, `cmake`, or other build methods.
- **Do not** omit quotes around the MSBuild path — it contains spaces.
- **Do not** call bare `msbuild` — it is not on the PATH:
  ```
  # BROKEN — msbuild is not recognized
  msbuild sandy.sln /p:Configuration=Release /p:Platform=x64
  ```
- **Do not** use the wrong solution filename — it is `sandy.sln`, not `sandy_cli.sln`:
  ```
  # BROKEN — MSB1009: Project file does not exist
  & "...MSBuild.exe" sandy_cli.sln /p:Configuration=Release /p:Platform=x64
  ```
- **Do not** wrap in `cmd /c` — nested quoting breaks path resolution:
  ```
  # BROKEN — 'C:\Program' is not recognized
  cmd /c ""%ProgramFiles%\...\MSBuild.exe" sandy.sln ..."
  ```
  Use PowerShell's `&` call operator with single-quoted path instead.
