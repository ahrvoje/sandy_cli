# LPAC DLL loading: the pipe-hook manifest failure

## Scope and diagnosis

Recorded on 2026-10-10 during Sandy named-pipe interception work.

The initial injected pipe-hook DLL had a generated PE manifest. Loading it
inside LPAC required Windows side-by-side (SxS) activation, which needed access
unavailable to the zero-capability target. The fix was to stop generating the
hook's unnecessary manifest. This is a loader compatibility issue, separate
from whether the later named-pipe call uses a LOCAL name.

The retained reason is in
[the hook project](../pipehook/sandy_pipe_hook.vcxproj) and
[the payload source](../pipehook/dllmain.cpp). The original complete failing
loader trace was not found when these notes were written. Do not invent an
exact historical error code, denied registry subkey, or old manifest contents.
A new failure must be diagnosed from its own trace.

The important chain is:

1. Sandy creates the restricted child and asks its remote thread to load the
   extracted hook DLL.
2. Windows processes the DLL's dependencies and manifest before a successful
   load can be reported.
3. Manifest activation can need OS access in addition to read/execute access
   to the DLL itself.
4. LPAC without capabilities does not have the ordinary AppContainer access
   supplied through ALL APPLICATION PACKAGES.
5. The load fails before the pipe rewrite can help. A DLL-path or pipe-name
   change does not address that activation requirement.

An existing, readable DLL is not proof that LoadLibrary can complete.
A successful load in the unrestricted launcher does not prove a load in LPAC.
A manifest need not be malformed to introduce an incompatible dependency.

## Keep these build properties

[pipehook/sandy_pipe_hook.vcxproj](../pipehook/sandy_pipe_hook.vcxproj) sets:

```xml
<GenerateManifest>false</GenerateManifest>
```

It also uses the static CRT: `MultiThreaded` in Release (`/MT`) and
`MultiThreadedDebug` in Debug (`/MTd`).

These are separate controls:

- Static CRT removes the payload's dependency on separately deployed MSVC
  runtime DLLs.
- Disabling manifest generation removes the payload's own SxS activation
  requirement. `/MT` alone does not switch off manifest generation.
- `/MANIFESTUAC:NO` only suppresses a UAC fragment. It is not a replacement for
  `/MANIFEST:NO`.

The current Release link command contains `/MANIFEST:NO`. Do not restore
the default generated manifest when editing project settings. Build with the
one command in [guidelines.md](guidelines.md#build).

This rule belongs to this self-contained hook. Do not remove manifests from
Sandy's main executable or third-party applications as a general fix.
A component that genuinely requires SxS dependencies needs a separate design
and access review.

## Diagnose the stage before changing permissions

1. **Read the Sandy log.** Separate extraction failure, remote-thread creation
   failure, loader timeout, `PIPEHOOK: load/install failed`, successful
   injection, and a later application or pipe error. Preserve the exact log,
   Windows build, binary hashes, configuration, and actual child token.
2. **Check the basic inputs.** Confirm the extracted path and file, matching
   process/payload architecture, file read/execute access under the child
   token, and required DLL imports. Use the exact payload that Sandy embedded;
   replacing a loose DLL beside sandy.exe does not update that payload.
3. **Inspect PE resources as well as imports.** `dumpbin /dependents` reports
   imported DLLs, not the whole activation-context requirement. Inspect
   `RT_MANIFEST` (resource type 24); a normal DLL manifest is resource ID 2.
   Also check for external manifests and build settings that add or merge
   manifests. For a read-only resource probe use `LoadLibraryExW` with
   `LOAD_LIBRARY_AS_DATAFILE`, rather than executing the payload in the host.
4. **Obtain the failure from the target thread.** Break on the target's loader
   calls, or use a diagnostic wrapper that immediately saves the target
   thread's LoadLibrary return and GetLastError values. Distinguish a loader
   failure from DllMain returning FALSE. Sandy's DllMain can reject hook
   installation too; failure is not automatically a manifest problem.
5. **If still unclear, trace loader activation.** A debugger with loader snaps
   (`FLG_SHOW_LDR_SNAPS`, 0x2) can identify dependency/activation failures.
   Capture the failed operation, object path, requested access, and returned
   status. An access-denied event alone is not proof of the fatal cause:
   applications can tolerate failed probes. Prefer diagnostics scoped to the
   test process. Do not add persistent system-wide GFlags/IFEO changes or
   reintroduce Procmon integration into Sandy.
6. **Verify with the smallest LPAC case.** Use the existing pipe test, keeping
   its zero-capability token. Adding registryRead, disabling LPAC, running
   elevated, or granting broad system-folder access changes the test and can
   hide a payload regression.

### Remote injection reporting traps

[InjectHookDll](../src/SandboxPipeHook.h) calls LoadLibraryW on a remote thread.
The current failure log contains a **thread exit DWORD**. It is not the remote
thread's GetLastError value, nor necessarily an NTSTATUS.

- GetLastError is thread-local. Calling it in Sandy cannot retrieve the error
  left by LoadLibraryW in the child.
- HMODULE is pointer-sized. On x64, GetExitCodeThread cannot carry a full module
  handle. Sandy checks for the exact DLL path in the child's module list with
  `ChildHasModule`; preserve that check.
- A null load result does not distinguish a missing import, failed activation,
  or a DllMain failure. Capture loader evidence before naming the cause.

## Regression evidence and checks

A read-only inspection on 2026-10-10 confirmed:

- The built x64 Release hook DLL has no resource section; probes for manifest
  resource IDs 1, 2, and 3 report no resource data.
- Its direct import list contains only `KERNEL32.dll`.
- Its bytes match `sandy.exe` resource `IDR_SANDY_PIPEHOOK` (RCDATA, numeric ID
  200), so the distributed executable contains the intended payload.
- The saved `test/pipe_hook_proof.json` reports a passing `lpac_local_rewrite`
  case: AppContainer=1, LPAC=1, Low integrity, zero capabilities, successful
  request/reply, and exit 0. The unmapped non-LOCAL control fails with pipe
  creation error 5. That control error is not the historical DLL-load error.

The proof JSON is an ignored local artifact, not a permanent tracked fixture.
To regenerate the evidence after a relevant change, run the focused test
`py -3 test\test_pipe_hook.py` using an available Python interpreter, after the
documented solution build. Do not run the whole suite for this check.

Keep the assertions for the actual token, successful IPC, blocked unmapped
name, and cleanup. A successful LibreOffice run alone is insufficient:
LibreOffice's registryRead capability can mask this hook regression.

## Separate LibreOffice requirement

LibreOffice's own startup needs SxS registry access in the tested workflow.
Its launcher-generated configuration explicitly requests:

```toml
[privileges]
registry_read = true
com = true
```

`registry_read` adds the Windows `registryRead` capability to the LPAC token;
`com` adds `lpacCom` for a separate COM/OLE startup requirement. These are
application needs, not requirements of the pipe hook.

The capability approach needs no host registry ACL change or UAC elevation.
It grants access where ACLs accept that capability, broader than a single SxS
key. File grants stay separate. Do not describe it as unrestricted registry
access, registry writes, or a grant confined to one key.

Do not copy these capabilities into the basic pipe regression test to make
injection pass. Do not strip LibreOffice's manifest to avoid its requirements.

## References

- [Microsoft: manifest generation and embedding](https://learn.microsoft.com/en-us/cpp/build/understanding-manifest-generation-for-c-cpp-programs?view=msvc-170)
- [Microsoft: /MANIFEST, /MANIFEST:NO, and DLL resource ID 2](https://learn.microsoft.com/en-us/cpp/build/reference/manifest-create-side-by-side-assembly-manifest?view=msvc-170)
- [Microsoft: LoadLibraryW return value and DllMain failure](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw)
- [Microsoft: thread-local GetLastError](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror)
- [Microsoft: loader snaps](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/show-loader-snaps)
- [Microsoft: LPAC launch and capabilities](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)
