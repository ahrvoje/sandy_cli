---
description: General coding style, architecture guidelines, and critical dos/don'ts for Sandy CLI
---

# Prerequisite Reading

**Before modifying any Sandy source code, read these files first:**

| File | Covers |
|------|--------|
| `.agents/acl_design.md` | ACL grant/deny design, mask math, PROTECTED_DACL, multi-owner safety |
| `.agents/resilience.md` | Cleanup, crash recovery, durable metadata, power-loss handling |
| `.agents/guidelines.md` | This file — coding rules, tests, architecture, docs |

These files contain **verified conclusions from previous work**. Decisions
documented there are **settled facts, not suggestions**. If a design here says
"never do X", it means X already caused real bugs.

# Logging

- **All actions affecting any OS item** (files, registry, DACLs, processes, tokens,
  profiles, network rules) **must be logged via `g_logger.Log()` or `g_logger.LogFmt()`**.
- **Use `g_logger.LogFmt(fmt, ...)` for formatted messages** — never the manual
  `{ wchar_t buf[N]; swprintf(...); g_logger.Log(buf); }` pattern.
- **Never use stdout/stderr for operational logging** if `g_logger` can cover it.
  `printf`/`wprintf` is only for user-facing CLI output (banner, status, help).

# Encoding

- **Never use UTF-16 for ANY output** — not stdout, not stderr, not log files.
- No `_O_U16TEXT`, no `_setmode` to wide mode, no `L"w"` without `ccs=UTF-8`.
- **Use `printf` with `%ls`** for user-facing output that includes wide strings.
- **Log files** opened with `_wfsopen`/`_wfopen` **must** use `L"w, ccs=UTF-8"`
  to ensure `fwprintf` transcodes wide strings to UTF-8 on disk.
- This is non-negotiable: UTF-16 files break `findstr`, `type`, `cat`, `grep`,
  and every standard text-processing tool.

# Ownership Model — Profile First

Sandy has **two ownership scopes**, and code must keep them separate:

| Scope | Purpose | Lifetime | Examples |
|-------|---------|----------|----------|
| **Profile** | Durable sandbox identity | Until `--delete-profile` | persistent AppContainer, durable ACL/registry grants, saved config |
| **Run** | One execution session | Until child and cleanup finish | live-state key, cleanup task, runtime bookkeeping |

**Profile-backed runs are not a special exception path.** They are normal runs
executed with a durable identity. Transient runs are the one-shot variant.

If code cannot answer **who owns this state** (`profile`, `run`, or host-global
best-effort state), the design is probably wrong.

# AppContainer vs Restricted Token

These sandbox modes still have fundamentally different security models.
Always know which mode you are changing before touching ACL or cleanup logic.
AC and LPAC share the same AppContainer pipeline; LPAC opts out of
App. Packages (`ALL APPLICATION PACKAGES`) for stricter default access.

| Aspect | AppContainer | Restricted Token |
|--------|-------------|-----------------|
| SID | Transient run: unique per run (`S-1-15-2-*`); saved profile: durable per profile (`S-1-15-2-*`) | Unique per run (`S-1-9-*`) |
| DENY ACEs | **Ignored by kernel** — deny not supported | Honored normally |
| Deny mechanism | Not available (config error) | Real `DENY_ACCESS` ACEs |
| Cleanup | Remove ACEs by owning SID | Remove ACEs by owning SID |

# DENY Rules — INVARIANT

> [!CAUTION]
> **AXIOM: The Windows kernel does NOT evaluate `DENY_ACCESS` ACEs for
> AppContainer SIDs.** This is an OS property, not a Sandy design choice.

**Consequences (mandatory, no exceptions):**

1. `[deny.*]` is **rejected at config time** for AppContainer mode.
2. Only Restricted Token mode supports deny rules (real `DENY_ACCESS` ACEs).
3. Deny uses standard `SetNamedSecurityInfoW` with auto-inheritance — same as
   grants. No `PROTECTED_DACL` or `TreeSet` required.

# Documentation

- **All user options and critical behavior must be documented.**
- Documentation lives in **three places** and they must stay consistent:
  1. **`README.md`** — full reference with examples and rationale.
  2. **`SandboxCLI.h` help text** — concise but complete `--help` contract.
  3. **`docs/` web pages** — user-facing static pages that must match the live CLI.
- If a feature is removed, **remove it everywhere**, including examples, test
  references, and “future work” sections that still describe it as active.

# TOML Configuration — Optional Defaults

Most TOML settings are **optional** with restrictive defaults. Only `[sandbox]`
and `token` are always mandatory. Omitting a field **never grants more access**.

## Mandatory Fields

| Field | When | Values |
|-------|------|--------|
| `[sandbox]` section | Always | Must be present |
| `token` | Always | `'appcontainer'`, `'lpac'`, or `'restricted'` |
| `integrity` | Restricted only | `'low'` or `'medium'` |

## Optional Fields and Defaults

| Section | Key | Default | Notes |
|---------|-----|---------|-------|
| `[sandbox]` | `strict` | `false` | RT only; excludes user SID from restricting list |
| `[sandbox]` | `workdir` | `'inherit'` (Sandy's CWD) | |
| `[allow.deep]` | `read/write/execute/append/delete/all/run/stat/touch/create` | `[]` | Recursive grants (OI\|CI) |
| `[allow.this]` | same keys | `[]` | Single-object grants (no inheritance) |
| `[deny.deep]` | `read/write/execute/append/delete/all/run/stat/touch/create` | `[]` | Recursive denies (RT only) |
| `[deny.this]` | same keys | `[]` | Single-object denies (RT only) |
| `[privileges]` | `network` | `false` | AC/LPAC only |
| `[privileges]` | `lan` | `false` | AC/LPAC only; `false` · `true` · `'with localhost'` · `'without localhost'` |
| `[privileges]` | `named_pipes` | `false` | RT only |
| `[privileges]` | `desktop` | `true` | RT only, WinSta0 + Desktop |
| `[privileges]` | `stdin` | `false` | `false` = NUL, `true` = inherit, path = file |
| `[privileges]` | `clipboard_read` | `false` | |
| `[privileges]` | `clipboard_write` | `false` | |
| `[privileges]` | `child_processes` | `true` | false breaks most apps |
| `[registry]` | `read/write` | `[]` | RT only |
| `[environment]` | `inherit` | `false` | filtered env |
| `[environment]` | `pass` | `[]` | |
| `[limit]` | `timeout/memory/processes` | `0` | 0 = no limit |

## Rules

- **Wrong-mode keys are rejected.**
- **Unknown keys/sections are rejected.**
- A minimal valid config is:
  ```toml
  [sandbox]
  token = 'appcontainer'
  ```

# Test Structure

- Tests use the **toml + py + bat** stack.
- Keep `.toml`, `.py`, and `.bat` separate. Do not inline TOML or Python into a batch script.

## Test Header — MANDATORY

Every test `.bat` must start with this header (after `@echo off` / `setlocal`):

```batch
for /f %%p in ('powershell -NoProfile -Command "$c=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId; (Get-CimInstance Win32_Process -Filter ('ProcessId='+$c)).ParentProcessId"') do echo  PID: %%p
```

Do **not** set window titles in tests. Procmon-backed audit/trace tests were
removed with the feature. If a feature is removed, add rejection/help-coverage
tests instead of leaving dead fixtures behind.

## Test Safety — Zero Side-Effects

Tests **must not** produce side-effects on Sandy production data, unrelated
processes, or the host platform.

### Registry

- **Never read, write, or delete** production keys under `HKCU\Software\Sandy`
  or `HKCU\Software\Sandy\Grants` — **except** for `--status` tests, which must
  inject stale entries into production paths because `--status` reads them.
- All other test-only registry entries go under **`HKCU\Software\Sandy\Test`**.
- Parent keys are **permanent**. Cleanup tests must verify subkey/value removal,
  not parent-key deletion.

### Process Management

- **Never** use blanket image-name kills like `taskkill /f /im sandy.exe`.
- All termination must target a specific PID obtained during the test.
- If a test verifies a process is gone, verify by PID, not by image name.

### General

- **NEVER** run the full suite automatically unless the user explicitly asked.
- Tests must stay inside `test\` and `%TEMP%`.
- Tests must delete their own temporary files, directories, and scheduled tasks.

# Architecture — Shared Run Pipeline

`Sandbox.h` implements a **single shared run pipeline** (`RunPipeline`) that both
transient and profile-backed runs use.

| Phase | Name | Key functions |
|-------|------|---------------|
| 1 | OWNERSHIP | `BeginRunSession`, `ExecutionIdentity` setup |
| 2 | SETUP | `SetupAppContainer()` or `SetupRestrictedToken()` |
| 3 | GRANT | `ApplyAccessPipeline`, `GrantRegistryAccess` |
| 4 | PREPARE | `BuildCapabilities`, `BuildAttributeList`, `BuildEnvironmentBlock` |
| 5 | LAUNCH/CLEANUP | `LaunchChildProcess`, `AssignJobObject`, `WaitForChildExit`, `SandboxGuard::RunAll()` |

Key rules:
- `RunSandboxed()` and `RunWithProfile()` both call `BeginRunSession()` and flow into `RunPipeline()`.
- Ownership-specific behavior comes from `ExecutionIdentity`, not from duplicated pipelines.
- Run-owned cleanup must only remove run-owned state. Profile-owned state must survive normal run exit.
- Any new feature that crosses profile and transient code paths should be modeled as shared primitives plus owner-specific metadata, not as copy-pasted branches.

# Dynamic Config Reload (`--dynamic` / `-y`)

A watcher thread polls the config file every 2 seconds while the child is running.
Only the **delta** is applied.

1. Build `GrantKey` sets from old and new config.
2. Revoke removed entries.
3. Apply added entries deny-first, then allows.
4. Apply registry deltas for RT mode.

Rules:
- Deny interactions must remain equivalent to a full pipeline run.
- State is updated only after reload work actually succeeds.
- Immutable after launch: `token`, `integrity`, `strict`, `workdir`, `[privileges]`, `[environment]`, `[limit]`, network flags.
- Dynamic-only sections: `[allow.deep]`, `[allow.this]`, `[deny.deep]`, `[deny.this]`, `[registry]`.
- **Compatibility:** requires `-c <file>`. Incompatible with `-s`, `-p`, `--dry-run`, `--print-config`, `--create-profile`.

# Removed Surface Area

Procmon-backed `--audit` / `--trace` is gone. Do not reintroduce host-global
helper tooling lightly. Features that mutate unrelated user tooling or require
host-global cleanup have repeatedly produced disproportionate regressions.

# Shell Environment

- Sandy development runs under **PowerShell Constrained Language Mode**.
- Prefer `.bat` for test orchestration.
- For **UAC elevation**, use VBScript (`ShellExecute "runas"`) rather than PowerShell elevation tricks.

# Build

The only reliable build command is:

```
& 'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe' sandy.sln /p:Configuration=Release /p:Platform=x64 /v:minimal
```

- Solution file: `sandy.sln`.
- Output: `x64\Release\sandy.exe`.
- **Do not** use `devenv`, `cl.exe`, `cmake`, or bare `msbuild`.
- **Do not** wrap the build in `cmd /c`.
