# Sandy source structure

This is a module map, not a generated function-count report.

| Module | Responsibility |
|---|---|
| `sandy.cpp` | Parse CLI modes, configure logging and UTF-8 conversion, handle signals and exceptions |
| `SandboxCLI.h` | Help text and argument quoting |
| `Sandbox.h` | Shared `BeginRunSession` / `RunPipeline`, launch and run-owned teardown |
| `SandboxTypes.h` | Configuration types, identity helpers, session logger |
| `TomlAdapter.h`, `SandboxConfig.h`, `SandboxConfigRender.h` | TOML parsing, presence and value validation, resolved configuration output |
| `SandboxDryRun.h` | Read-only run and profile creation previews |
| `SandboxSavedProfile.h`, `SandboxProfileRegistry.h` | Durable profile creation, validation, reuse and deletion |
| `SandboxACL.h` | Serialized ACE changes and DACL protection preservation |
| `SandboxGrants.h`, `SandboxRecoveryLedger.h` | Write-ahead grant inventory, ledger ownership and recovery |
| `SandboxCleanup.h` | Loopback, cleanup tasks and stale container cleanup |
| `SandboxToken.h` | Restricted token and desktop access |
| `SandboxCapabilities.h` | AppContainer capabilities and launch attributes |
| `SandboxProcess.h`, `SandboxEnvironment.h` | Child process/job lifecycle and environment |
| `SandboxPipeHook.h` | Extract, inject, and track the embedded pipe-hook payload |
| `SandboxRegistry.h` | Registry value and key helpers |
| `SandboxGuard.h` | Ordered RAII cleanup actions |
| `SandboxStatus.h` | Status, cleanup command and exit-code descriptions |

The pipe-hook payload is built by `pipehook/sandy_pipe_hook.vcxproj` and embedded
through `src/sandy.rc`. Keep its static CRT and manifest settings as documented
in `lpac_loader_debugging.md`.

The ownership and recovery contracts are in `guidelines.md`, `acl_design.md`,
and `resilience.md`. Function names and call edges should be checked in source.
