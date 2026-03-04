#pragma once
// =========================================================================
// Sandbox.h — Sandbox orchestrator (pipeline architecture)
//
// Two clean pipelines: RunAppContainer() and RunRestricted().
// Each pipeline is a sequence of self-contained, verifiable steps.
// All utility logic lives in dedicated headers.
// =========================================================================

#include "framework.h"
#include "SandboxConfig.h"
#include "SandboxACL.h"
#include "SandboxToken.h"
#include "SandboxAudit.h"
#include "SandboxCleanup.h"
#include "SandboxCapabilities.h"
#include "SandboxEnvironment.h"
#include "SandboxProcess.h"

namespace Sandbox {

    // -----------------------------------------------------------------------
    // GrantConfiguredAccess — apply all configured folder grants.
    //
    // Inputs:  pSid    — SID to grant access to
    //          config  — sandbox config with folders list
    // Returns: true if all grants succeeded
    // Verifiable: each folder's DACL contains the expected ACE
    // -----------------------------------------------------------------------
    inline bool GrantConfiguredAccess(PSID pSid, const SandboxConfig& config)
    {
        bool allOk = true;
        for (const auto& entry : config.folders) {
            bool ok = GrantObjectAccess(pSid, entry.path, entry.access);
            if (!ok) {
                fprintf(stderr, "[Warning] Could not grant access to: %ls\n", entry.path.c_str());
                allOk = false;
            }
            wchar_t msg[1024];
            swprintf(msg, 1024, L"GRANT: [%s] %s -> %s (mask=0x%08X)",
                     AccessTag(entry.access), entry.path.c_str(),
                     ok ? L"OK" : L"FAILED", AccessMask(entry.access));
            g_logger.Log(msg);
        }
        return allOk;
    }

    // -----------------------------------------------------------------------
    // ApplyDenyRules — apply all configured deny ACEs (after allows).
    //
    // Inputs:  pSid          — SID to deny access for
    //          config        — sandbox config with denyFolders list
    //          isAppContainer — true if running in AppContainer mode
    // Returns: true if all deny rules succeeded
    // Verifiable: each denied folder's DACL contains the expected DENY ACE
    // -----------------------------------------------------------------------
    inline bool ApplyDenyRules(PSID pSid, const SandboxConfig& config, bool isAppContainer)
    {
        bool allOk = true;
        for (const auto& entry : config.denyFolders) {
            if (entry.path.empty()) continue;
            bool ok = DenyObjectAccess(pSid, entry.path, entry.access, isAppContainer);
            if (!ok) {
                fprintf(stderr, "[Warning] Could not deny access to: %ls\n", entry.path.c_str());
                allOk = false;
            }
            wchar_t msg[1024];
            swprintf(msg, 1024, L"DENY: [%s] %s -> %s (mask=0x%08X)",
                     AccessTag(entry.access), entry.path.c_str(),
                     ok ? L"OK" : L"FAILED", AccessMask(entry.access));
            g_logger.Log(msg);
        }
        return allOk;
    }

    // -----------------------------------------------------------------------
    // GrantRegistryAccess — apply configured registry key grants.
    //
    // Inputs:  pSid   — SID to grant access to
    //          config — sandbox config with registryRead/registryWrite lists
    // Returns: true if all grants succeeded
    // Verifiable: each registry key's DACL contains the expected ACE
    // -----------------------------------------------------------------------
    inline bool GrantRegistryAccess(PSID pSid, const SandboxConfig& config)
    {
        bool allOk = true;
        for (const auto& key : config.registryRead) {
            std::wstring win32Path = RegistryToWin32Path(key);
            bool ok = GrantObjectAccess(pSid, win32Path, AccessLevel::Read, SE_REGISTRY_KEY);
            wchar_t msg[512];
            swprintf(msg, 512, L"GRANT_REG: [R] %s -> %s", key.c_str(), ok ? L"OK" : L"FAILED");
            g_logger.Log(msg);
            if (!ok) {
                fprintf(stderr, "[Warning] Could not grant registry read: %ls\n", key.c_str());
                allOk = false;
            }
        }
        for (const auto& key : config.registryWrite) {
            std::wstring win32Path = RegistryToWin32Path(key);
            bool ok = GrantObjectAccess(pSid, win32Path, AccessLevel::Write, SE_REGISTRY_KEY);
            wchar_t msg[512];
            swprintf(msg, 512, L"GRANT_REG: [W] %s -> %s", key.c_str(), ok ? L"OK" : L"FAILED");
            g_logger.Log(msg);
            if (!ok) {
                fprintf(stderr, "[Warning] Could not grant registry write: %ls\n", key.c_str());
                allOk = false;
            }
        }
        return allOk;
    }

    // -----------------------------------------------------------------------
    // AutoGrantExeFolderAccess — grant read access to exe and target folders.
    //
    // Grants read access to the sandy.exe folder and (if different) the
    // target executable's folder so its DLLs are accessible.
    //
    // Inputs:  pSid     — SID to grant access to
    //          exeFolder — sandy.exe working directory
    //          exePath   — target executable path
    // Effect:  DACL grants applied to both folders
    // Verifiable: folders have read ACE for the given SID
    // -----------------------------------------------------------------------
    inline void AutoGrantExeFolderAccess(PSID pSid, const std::wstring& exeFolder,
                                          const std::wstring& exePath)
    {
        GrantObjectAccess(pSid, exeFolder, AccessLevel::Read);
        g_logger.Log((L"GRANT_AUTO: [R] " + exeFolder).c_str());

        // Auto-grant read access to the target executable's folder
        wchar_t resolvedExe[MAX_PATH]{};
        DWORD found = SearchPathW(nullptr, exePath.c_str(), L".exe",
                                  MAX_PATH, resolvedExe, nullptr);
        if (found) {
            std::wstring targetFolder(resolvedExe);
            auto slash = targetFolder.find_last_of(L"\\/");
            if (slash != std::wstring::npos)
                targetFolder.resize(slash);
            if (_wcsicmp(targetFolder.c_str(), exeFolder.c_str()) != 0) {
                GrantObjectAccess(pSid, targetFolder, AccessLevel::Read);
                g_logger.Log((L"GRANT_AUTO: [R] " + targetFolder).c_str());
            }
        }
    }

    // -----------------------------------------------------------------------
    // SetupAudit — start Procmon audit capture if requested.
    //
    // Inputs:  auditLogPath — path for audit log (empty = no audit)
    //          quiet        — suppress stderr output
    // Outputs: procmonExe   — resolved Procmon path (for StopProcmonAudit)
    //          auditActive  — true if audit is capturing
    // Verifiable: Procmon process is running, PML file exists
    // -----------------------------------------------------------------------
    inline void SetupAudit(const std::wstring& auditLogPath, bool quiet,
                           std::wstring& procmonExe, bool& auditActive)
    {
        procmonExe.clear();
        auditActive = false;
        if (auditLogPath.empty()) return;

        procmonExe = FindProcmon();
        if (procmonExe.empty()) {
            fprintf(stderr, "[Audit] Procmon not found on PATH. Audit disabled.\n");
            return;
        }
        auditActive = StartProcmonAudit(procmonExe);
        if (auditActive && !quiet)
            fprintf(stderr, "Audit:      ACTIVE (Procmon)\n");
    }

    // -----------------------------------------------------------------------
    // SetupCrashDumps — enable WER crash dumps for the target process.
    //
    // Inputs:  auditLogPath — audit log path (triggers dumps if non-empty)
    //          dumpPath     — explicit dump path (also triggers dumps)
    //          exePath      — target executable (for WER key)
    // Outputs: crashExeName    — exe basename (for later cleanup)
    //          crashDumpsEnabled — true if WER was configured
    // Verifiable: HKLM\...\LocalDumps\<exe> key exists with DumpType=1
    // -----------------------------------------------------------------------
    inline void SetupCrashDumps(const std::wstring& auditLogPath,
                                 const std::wstring& dumpPath,
                                 const std::wstring& exePath,
                                 std::wstring& crashExeName,
                                 bool& crashDumpsEnabled)
    {
        crashExeName.clear();
        crashDumpsEnabled = false;
        if (auditLogPath.empty() && dumpPath.empty()) return;

        auto slash = exePath.find_last_of(L"\\/");
        crashExeName = (slash != std::wstring::npos) ? exePath.substr(slash + 1) : exePath;
        crashDumpsEnabled = EnableCrashDumps(crashExeName);
        if (crashDumpsEnabled)
            PersistWERExeName(crashExeName);
    }

    // -----------------------------------------------------------------------
    // FinalizeAuditAndDumps — stop audit, report crash dumps, clean WER.
    //
    // Inputs:  auditActive      — whether audit was running
    //          procmonExe       — Procmon path
    //          auditLogPath     — audit log destination
    //          dumpPath         — explicit dump path
    //          crashDumpsEnabled — whether WER was configured
    //          crashExeName     — exe basename for WER
    //          childPid         — child process PID (for audit filtering)
    //          exitCode         — child exit code (for crash detection)
    // Effect:  stops Procmon, writes audit log, reports/copies crash dump
    // Verifiable: audit log exists, crash dump copied to target path
    // -----------------------------------------------------------------------
    inline void FinalizeAuditAndDumps(bool auditActive,
                                       const std::wstring& procmonExe,
                                       const std::wstring& auditLogPath,
                                       const std::wstring& dumpPath,
                                       bool crashDumpsEnabled,
                                       const std::wstring& crashExeName,
                                       DWORD childPid, DWORD exitCode)
    {
        if (auditActive) {
            std::string processTree = StopProcmonAudit(procmonExe, auditLogPath, childPid);
            if (!processTree.empty()) {
                g_logger.Log(L"--- Process Tree ---");
                int len = MultiByteToWideChar(CP_ACP, 0, processTree.c_str(), -1, nullptr, 0);
                std::wstring wTree(len, L'\0');
                MultiByteToWideChar(CP_ACP, 0, processTree.c_str(), -1, &wTree[0], len);
                while (!wTree.empty() && (wTree.back() == L'\0' || wTree.back() == L'\n'))
                    wTree.pop_back();
                g_logger.Log(wTree.c_str());
            }
        }

        if (crashDumpsEnabled) {
            if (IsCrashExitCode(exitCode)) {
                Sleep(2000);
                std::wstring reportTarget = !dumpPath.empty() ? dumpPath : auditLogPath;
                std::wstring foundDump = ReportCrashDump(crashExeName, reportTarget);
                if (!foundDump.empty())
                    fprintf(stderr, "[Dump] Crash dump: %ls\n", foundDump.c_str());
                else
                    fprintf(stderr, "[Dump] Process crashed (0x%08X) but no dump was generated.\n", exitCode);
            }
            DisableCrashDumps(crashExeName);
            ClearWERExeName();
        }
    }

    // =====================================================================
    // APPCONTAINER PIPELINE
    //
    // Each line is a self-contained, independently verifiable step.
    // The pipeline reads top-to-bottom as a specification of what happens.
    // =====================================================================
    inline int RunAppContainer(const SandboxConfig& config,
                                const std::wstring& exePath,
                                const std::wstring& exeArgs,
                                const std::wstring& containerName,
                                const std::wstring& exeFolder,
                                const std::wstring& auditLogPath,
                                const std::wstring& dumpPath)
    {
        // --- Step 1: Create AppContainer profile ---
        PSID pContainerSid = nullptr;
        bool containerCreated = false;
        HRESULT hr = CreateAppContainerProfile(
            containerName.c_str(), L"Sandy Sandbox",
            L"Sandboxed environment for running executables",
            nullptr, 0, &pContainerSid);
        if (HRESULT_CODE(hr) == ERROR_ALREADY_EXISTS) {
            hr = DeriveAppContainerSidFromAppContainerName(containerName.c_str(), &pContainerSid);
            containerCreated = false;
        } else {
            containerCreated = SUCCEEDED(hr);
        }
        if (FAILED(hr) || !pContainerSid) {
            fprintf(stderr, "[Error] Could not create AppContainer (0x%08X).\n", hr);
            return 1;
        }

        g_logger.Log(L"MODE: appcontainer");
        {
            wchar_t msg[1024];
            swprintf(msg, 1024, L"CONTAINER: %s", containerCreated ? L"created" : L"reused existing");
            g_logger.Log(msg);
            LPWSTR sidStr = nullptr;
            if (ConvertSidToStringSidW(pContainerSid, &sidStr)) {
                swprintf(msg, 1024, L"CONTAINER_SID: %s", sidStr);
                g_logger.Log(msg);
                LocalFree(sidStr);
            }
            swprintf(msg, 1024, L"WORKDIR: %s", exeFolder.c_str());
            g_logger.Log(msg);
        }

        // --- Step 2: Auto-grant read access to exe folders ---
        AutoGrantExeFolderAccess(pContainerSid, exeFolder, exePath);

        // --- Step 3: Grant configured folder access ---
        bool grantFailed = !GrantConfiguredAccess(pContainerSid, config);

        // --- Step 4: Apply deny rules ---
        if (!ApplyDenyRules(pContainerSid, config, /*isAppContainer=*/true))
            grantFailed = true;

        if (grantFailed)
            fprintf(stderr, "          Run as Administrator to modify ACLs.\n");

        // --- Step 4: Enable loopback if requested ---
        if (config.allowLocalhost) {
            bool ok = EnableLoopback();
            if (!ok) {
                fprintf(stderr, "[Warning] Could not enable localhost access.\n");
                fprintf(stderr, "          Loopback exemption requires Administrator.\n");
            }
            g_logger.Log(ok ? L"LOOPBACK: enabled" : L"LOOPBACK: FAILED");
        }

        // --- Step 5: Build capabilities (network SIDs) ---
        CapabilityState caps = BuildCapabilities(config);

        // --- Step 6: Build SECURITY_CAPABILITIES and attribute list ---
        SECURITY_CAPABILITIES sc{};
        sc.AppContainerSid = pContainerSid;
        sc.Capabilities = caps.capCount > 0 ? caps.caps : nullptr;
        sc.CapabilityCount = caps.capCount;

        AttributeListState attrs = BuildAttributeList(config, &sc, /*isRestricted=*/false);
        if (!attrs.valid) {
            FreeCapabilities(caps);
            FreeSid(pContainerSid);
            return 1;
        }

        // --- Step 7: Log stdin, environment, and config summary ---
        LogStdinMode(config.stdinMode);
        std::vector<wchar_t> envBlock = BuildEnvironmentBlock(config);
        LogEnvironmentState(config);
        PrintConfigSummary(config, exePath, exeArgs, /*isRestricted=*/false);

        // --- Step 8: Setup audit and crash dumps ---
        std::wstring procmonExe;
        bool auditActive = false;
        SetupAudit(auditLogPath, config.quiet, procmonExe, auditActive);

        std::wstring crashExeName;
        bool crashDumpsEnabled = false;
        SetupCrashDumps(auditLogPath, dumpPath, exePath, crashExeName, crashDumpsEnabled);

        // --- Step 9: Create output pipe and stdin handle ---
        HANDLE hReadPipe = nullptr, hWritePipe = nullptr;
        if (!SetupOutputPipe(hReadPipe, hWritePipe)) {
            fprintf(stderr, "[Error] Could not create output pipe.\n");
            FreeAttributeList(attrs);
            FreeCapabilities(caps);
            FreeSid(pContainerSid);
            return 1;
        }
        HANDLE hStdin = nullptr, hStdinFile = nullptr;
        if (!SetupStdinHandle(config.stdinMode, hStdin, hStdinFile)) {
            CloseHandle(hReadPipe); CloseHandle(hWritePipe);
            FreeAttributeList(attrs);
            FreeCapabilities(caps);
            FreeSid(pContainerSid);
            return 1;
        }

        // --- Step 10: Launch the child process ---
        PROCESS_INFORMATION pi{};
        bool launched = LaunchChildProcess(
            /*isRestricted=*/false, nullptr, attrs.pAttrList,
            envBlock, exeFolder, exePath, exeArgs, hStdin, hWritePipe, pi);

        // Close write end and cleanup handles
        CloseHandle(hWritePipe);
        FreeAttributeList(attrs);
        if (hStdinFile) CloseHandle(hStdinFile);

        if (!launched) {
            g_logger.LogSummary(GetLastError(), false, 0);
            g_logger.Stop();
            CloseHandle(hReadPipe);
            // Cleanup
            RevokeAllGrants();
            DisableLoopback();
            DeleteAppContainerProfile(containerName.c_str());
            DeleteCleanupTask();
            FreeCapabilities(caps);
            FreeSid(pContainerSid);
            return 1;
        }

        g_logger.LogConfig(config, exePath, exeArgs);

        // --- Step 11: Assign job object for resource limits ---
        HANDLE hJob = AssignJobObject(config, pi.hProcess);

        // --- Step 12: Resume child and start timeout watchdog ---
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);

        TimeoutContext timeoutCtx = { pi.hProcess, config.timeoutSeconds, false };
        HANDLE hTimeoutThread = StartTimeoutWatchdog(timeoutCtx);

        // --- Step 13: Relay output and wait for exit ---
        DWORD exitCode = RelayOutputAndWait(pi.hProcess, hReadPipe,
                                             hTimeoutThread, timeoutCtx,
                                             config.timeoutSeconds);

        // --- Step 14: Log summary and finalize audit/dumps ---
        g_logger.LogSummary(exitCode, timeoutCtx.timedOut, config.timeoutSeconds);
        FinalizeAuditAndDumps(auditActive, procmonExe, auditLogPath, dumpPath,
                              crashDumpsEnabled, crashExeName, pi.dwProcessId, exitCode);

        // --- Step 15: Cleanup all sandbox state ---
        CloseHandle(pi.hProcess);
        if (hJob) CloseHandle(hJob);

        g_logger.Log(L"CLEANUP: starting");
        RevokeAllGrants();
        DisableLoopback();
        HRESULT hrDel = DeleteAppContainerProfile(containerName.c_str());
        g_logger.Log((L"PROFILE_DELETE: " + containerName +
            (SUCCEEDED(hrDel) ? L" -> OK" : L" -> FAILED")).c_str());
        DeleteCleanupTask();
        g_logger.Log(L"CLEANUP: complete");
        g_logger.Stop();
        FreeCapabilities(caps);
        FreeSid(pContainerSid);

        return static_cast<int>(exitCode);
    }

    // =====================================================================
    // RESTRICTED TOKEN PIPELINE
    //
    // Each line is a self-contained, independently verifiable step.
    // The pipeline reads top-to-bottom as a specification of what happens.
    // =====================================================================
    inline int RunRestricted(const SandboxConfig& config,
                              const std::wstring& exePath,
                              const std::wstring& exeArgs,
                              const std::wstring& exeFolder,
                              const std::wstring& auditLogPath,
                              const std::wstring& dumpPath)
    {
        // --- Step 1: Create restricted sandbox token ---
        HANDLE hRestrictedToken = CreateRestrictedSandboxToken(config.integrity);
        if (!hRestrictedToken) {
            fprintf(stderr, "[Error] Could not create restricted token (error %lu).\n", GetLastError());
            return 1;
        }

        // --- Step 2: Allocate restricted SID for DACL grants ---
        PSID pGrantSid = nullptr;
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        if (!AllocateAndInitializeSid(&ntAuth, 1, SECURITY_RESTRICTED_CODE_RID,
            0, 0, 0, 0, 0, 0, 0, &pGrantSid)) {
            fprintf(stderr, "[Error] Could not allocate restricted SID (error %lu).\n", GetLastError());
            CloseHandle(hRestrictedToken);
            return 1;
        }

        g_logger.Log(config.integrity == IntegrityLevel::Low
                     ? L"MODE: restricted token (Low integrity)"
                     : L"MODE: restricted token (Medium integrity)");
        g_logger.Log(config.allowNamedPipes ? L"Named Pipes: allowed (Everyone in restricting SIDs)"
                                       : L"Named Pipes: blocked (Everyone excluded)");
        {
            wchar_t msg[1024];
            swprintf(msg, 1024, L"WORKDIR: %s", exeFolder.c_str());
            g_logger.Log(msg);
        }

        // --- Step 3: Auto-grant read access to exe folders ---
        AutoGrantExeFolderAccess(pGrantSid, exeFolder, exePath);

        // --- Step 4: Grant desktop access for the restricted token ---
        GrantDesktopAccess(pGrantSid);
        g_logger.Log(L"DESKTOP: granted WinSta0 + Default access");

        // --- Step 5: Grant configured folder access ---
        bool grantFailed = !GrantConfiguredAccess(pGrantSid, config);

        // --- Step 6: Apply deny rules ---
        if (!ApplyDenyRules(pGrantSid, config, /*isAppContainer=*/false))
            grantFailed = true;

        // --- Step 7: Grant registry access ---
        if (!GrantRegistryAccess(pGrantSid, config))
            grantFailed = true;

        if (grantFailed)
            fprintf(stderr, "          Run as Administrator to modify ACLs.\n");

        // --- Step 8: Build attribute list (child process policy only) ---
        AttributeListState attrs = BuildAttributeList(config, nullptr, /*isRestricted=*/true);
        if (!attrs.valid) {
            FreeSid(pGrantSid);
            CloseHandle(hRestrictedToken);
            return 1;
        }

        // --- Step 9: Log stdin, environment, and config summary ---
        LogStdinMode(config.stdinMode);
        std::vector<wchar_t> envBlock = BuildEnvironmentBlock(config);
        LogEnvironmentState(config);
        PrintConfigSummary(config, exePath, exeArgs, /*isRestricted=*/true);

        // --- Step 10: Setup audit and crash dumps ---
        std::wstring procmonExe;
        bool auditActive = false;
        SetupAudit(auditLogPath, config.quiet, procmonExe, auditActive);

        std::wstring crashExeName;
        bool crashDumpsEnabled = false;
        SetupCrashDumps(auditLogPath, dumpPath, exePath, crashExeName, crashDumpsEnabled);

        // --- Step 11: Create output pipe and stdin handle ---
        HANDLE hReadPipe = nullptr, hWritePipe = nullptr;
        if (!SetupOutputPipe(hReadPipe, hWritePipe)) {
            fprintf(stderr, "[Error] Could not create output pipe.\n");
            FreeAttributeList(attrs);
            FreeSid(pGrantSid);
            CloseHandle(hRestrictedToken);
            return 1;
        }
        HANDLE hStdin = nullptr, hStdinFile = nullptr;
        if (!SetupStdinHandle(config.stdinMode, hStdin, hStdinFile)) {
            CloseHandle(hReadPipe); CloseHandle(hWritePipe);
            FreeAttributeList(attrs);
            FreeSid(pGrantSid);
            CloseHandle(hRestrictedToken);
            return 1;
        }

        // --- Step 12: Launch the child process ---
        PROCESS_INFORMATION pi{};
        bool launched = LaunchChildProcess(
            /*isRestricted=*/true, hRestrictedToken, attrs.pAttrList,
            envBlock, exeFolder, exePath, exeArgs, hStdin, hWritePipe, pi);

        CloseHandle(hWritePipe);
        FreeAttributeList(attrs);
        if (hStdinFile) CloseHandle(hStdinFile);

        if (!launched) {
            g_logger.LogSummary(GetLastError(), false, 0);
            g_logger.Stop();
            CloseHandle(hReadPipe);
            RevokeDesktopAccess();
            RevokeAllGrants();
            DeleteCleanupTask();
            FreeSid(pGrantSid);
            CloseHandle(hRestrictedToken);
            return 1;
        }

        g_logger.LogConfig(config, exePath, exeArgs);

        // --- Step 13: Assign job object for resource limits ---
        HANDLE hJob = AssignJobObject(config, pi.hProcess);

        // --- Step 14: Resume child and start timeout watchdog ---
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);

        TimeoutContext timeoutCtx = { pi.hProcess, config.timeoutSeconds, false };
        HANDLE hTimeoutThread = StartTimeoutWatchdog(timeoutCtx);

        // --- Step 15: Relay output and wait for exit ---
        DWORD exitCode = RelayOutputAndWait(pi.hProcess, hReadPipe,
                                             hTimeoutThread, timeoutCtx,
                                             config.timeoutSeconds);

        // --- Step 16: Log summary and finalize audit/dumps ---
        g_logger.LogSummary(exitCode, timeoutCtx.timedOut, config.timeoutSeconds);
        FinalizeAuditAndDumps(auditActive, procmonExe, auditLogPath, dumpPath,
                              crashDumpsEnabled, crashExeName, pi.dwProcessId, exitCode);

        // --- Step 17: Cleanup all sandbox state ---
        CloseHandle(pi.hProcess);
        if (hJob) CloseHandle(hJob);

        g_logger.Log(L"CLEANUP: starting");
        RevokeDesktopAccess();
        RevokeAllGrants();
        DeleteCleanupTask();
        g_logger.Log(L"CLEANUP: complete");
        g_logger.Stop();
        FreeSid(pGrantSid);
        CloseHandle(hRestrictedToken);

        return static_cast<int>(exitCode);
    }

    // =====================================================================
    // RunSandboxed — common entry point, dispatches to the correct pipeline.
    //
    // This is the top-level orchestrator. It performs instance-wide setup
    // (ID generation, logger start, stale state cleanup) then delegates
    // to either RunAppContainer() or RunRestricted().
    // =====================================================================
    inline int RunSandboxed(const SandboxConfig& config,
                            const std::wstring& exePath,
                            const std::wstring& exeArgs,
                            const std::wstring& auditLogPath = L"",
                            const std::wstring& dumpPath = L"")
    {
        // --- Generate instance ID (UUID) for this run ---
        g_instanceId = GenerateInstanceId();
        std::wstring containerName = ContainerNameFromId(g_instanceId);
        bool isRestricted = (config.tokenMode == TokenMode::Restricted);

        // --- Determine working directory ---
        std::wstring exeFolder = config.workdir.empty() ? GetExeFolder() : config.workdir;
        if (exeFolder.empty())
            return 1;

        // --- Start logger early for forensic logging ---
        if (!config.logPath.empty())
            g_logger.Start(config.logPath);

        // --- Common startup: clean stale state, warn, create safety net ---
        CleanupStaleStartupState(exePath);
        WarnStaleRegistryEntries();
        CreateCleanupTask();
        LogSandyIdentity();

        // --- Dispatch to mode-specific pipeline ---
        if (isRestricted) {
            return RunRestricted(config, exePath, exeArgs, exeFolder,
                                 auditLogPath, dumpPath);
        } else {
            return RunAppContainer(config, exePath, exeArgs, containerName,
                                    exeFolder, auditLogPath, dumpPath);
        }
    }

    // -----------------------------------------------------------------------
    // CleanupSandbox — full cleanup for --cleanup command (stale recovery)
    // -----------------------------------------------------------------------
    inline void CleanupSandbox()
    {
        RevokeDesktopAccess();
        RevokeAllGrants();
        DisableLoopback();
        std::wstring containerName = ContainerNameFromId(g_instanceId);
        if (!containerName.empty())
            DeleteAppContainerProfile(containerName.c_str());
        RestoreStaleGrants();
        RestoreStaleWER();
        DeleteCleanupTask();
    }

} // namespace Sandbox
