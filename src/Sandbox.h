#pragma once
// =========================================================================
// Sandbox.h — Sandbox orchestrator (single unified pipeline)
//
// One linear pipeline: RunPipeline().  Mode-specific steps use simple
// conditionals.  All cleanup is managed by SandboxGuard (RAII).
// =========================================================================

#include "framework.h"
#include "SandboxConfig.h"
#include "SandboxACL.h"
#include "SandboxGrants.h"
#include "SandboxGuard.h"
#include "SandboxToken.h"
#include "SandboxAudit.h"
#include "SandboxCrashDump.h"
#include "SandboxProfile.h"
#include "SandboxCleanup.h"
#include "SandboxCapabilities.h"
#include "SandboxEnvironment.h"
#include "SandboxProcess.h"

namespace Sandbox {

    // -----------------------------------------------------------------------
    // RecordGrant callback — bridges SandboxACL.h → SandboxGrants.h
    // -----------------------------------------------------------------------
    inline void RecordGrantCallback(const std::wstring& path,
                                     SE_OBJECT_TYPE objType,
                                     const std::wstring& sidString,
                                     const std::wstring& trappedSids,
                                     bool isDeny)
    {
        RecordGrant(path, objType, sidString, trappedSids, isDeny);
    }

    // -----------------------------------------------------------------------
    // GrantConfiguredAccess — apply all configured folder grants.
    // -----------------------------------------------------------------------
    inline bool GrantConfiguredAccess(PSID pSid, const SandboxConfig& config)
    {
        bool allOk = true;
        for (const auto& entry : config.folders) {
            bool ok = GrantObjectAccess(pSid, entry.path, entry.access, RecordGrantCallback);
            if (!ok) allOk = false;
            g_logger.LogFmt(L"GRANT: [%s] %s -> %s (mask=0x%08X)",
                            AccessTag(entry.access), entry.path.c_str(),
                            ok ? L"OK" : L"FAILED", AccessMask(entry.access));
        }
        return allOk;
    }

    // -----------------------------------------------------------------------
    // ApplyDenyRules — apply all configured deny ACEs (after allows).
    // -----------------------------------------------------------------------
    inline bool ApplyDenyRules(PSID pSid, const SandboxConfig& config, bool isAppContainer)
    {
        bool allOk = true;
        for (const auto& entry : config.denyFolders) {
            if (entry.path.empty()) continue;
            bool ok = DenyObjectAccess(pSid, entry.path, entry.access, isAppContainer, RecordGrantCallback);
            if (!ok) allOk = false;
            g_logger.LogFmt(L"DENY: [%s] %s -> %s (mask=0x%08X)",
                            AccessTag(entry.access), entry.path.c_str(),
                            ok ? L"OK" : L"FAILED", AccessMask(entry.access));
        }
        return allOk;
    }

    // -----------------------------------------------------------------------
    // GrantRegistryAccess — apply configured registry key grants.
    // -----------------------------------------------------------------------
    inline bool GrantRegistryAccess(PSID pSid, const SandboxConfig& config)
    {
        bool allOk = true;
        struct RegGrant { const std::vector<std::wstring>& keys; AccessLevel level; const wchar_t* tag; };
        for (auto& rg : { RegGrant{config.registryRead, AccessLevel::Read, L"R"},
                          RegGrant{config.registryWrite, AccessLevel::Write, L"W"} }) {
            for (const auto& key : rg.keys) {
                std::wstring win32Path = RegistryToWin32Path(key);
                bool ok = GrantObjectAccess(pSid, win32Path, rg.level, RecordGrantCallback, SE_REGISTRY_KEY);
                if (!ok) allOk = false;
                g_logger.LogFmt(L"GRANT_REG: [%s] %s -> %s", rg.tag, key.c_str(), ok ? L"OK" : L"FAILED");
            }
        }
        return allOk;
    }

    // -----------------------------------------------------------------------
    // AutoGrantExeFolderAccess — grant read access to exe and target folders.
    // -----------------------------------------------------------------------
    inline void AutoGrantExeFolderAccess(PSID pSid, const std::wstring& exeFolder,
                                          const std::wstring& exePath)
    {
        GrantObjectAccess(pSid, exeFolder, AccessLevel::Read, RecordGrantCallback);
        g_logger.Log((L"GRANT_AUTO: [R] " + exeFolder).c_str());

        wchar_t resolvedExe[MAX_PATH]{};
        DWORD found = SearchPathW(nullptr, exePath.c_str(), L".exe",
                                  MAX_PATH, resolvedExe, nullptr);
        if (found) {
            std::wstring targetFolder(resolvedExe);
            auto slash = targetFolder.find_last_of(L"\\/");
            if (slash != std::wstring::npos)
                targetFolder.resize(slash);
            if (_wcsicmp(targetFolder.c_str(), exeFolder.c_str()) != 0) {
                GrantObjectAccess(pSid, targetFolder, AccessLevel::Read, RecordGrantCallback);
                g_logger.Log((L"GRANT_AUTO: [R] " + targetFolder).c_str());
            }
        }
    }

    // -----------------------------------------------------------------------
    // SetupAudit — start Procmon audit capture if requested.
    // -----------------------------------------------------------------------
    inline void SetupAudit(const std::wstring& auditLogPath,
                           std::wstring& procmonExe, bool& auditActive)
    {
        procmonExe.clear();
        auditActive = false;
        if (auditLogPath.empty()) return;

        procmonExe = FindProcmon();
        if (procmonExe.empty()) {
            g_logger.Log(L"AUDIT: Procmon not found on PATH, audit disabled");
            return;
        }
        auditActive = StartProcmonAudit(procmonExe);
        if (auditActive)
            g_logger.Log(L"AUDIT: active (Procmon)");
    }

    // -----------------------------------------------------------------------
    // SetupCrashDumps — enable WER crash dumps for the target process.
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
        g_logger.Log(crashDumpsEnabled ? L"WER_DUMP: enabled" : L"WER_DUMP: failed to enable");
        if (crashDumpsEnabled)
            PersistWERExeName(crashExeName);
    }

    // -----------------------------------------------------------------------
    // FinalizeAuditAndDumps — stop Procmon, report crash dumps, clean WER.
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
                if (!foundDump.empty()) {
                    g_logger.Log((L"DUMP: captured -> " + foundDump).c_str());
                } else {
                    g_logger.Log(L"DUMP: process crashed but no dump generated");
                }
            }
            DisableCrashDumps(crashExeName);
            ClearWERExeName();
        }
    }

    // -----------------------------------------------------------------------
    // SetupResult — output of Phase 1 (token/SID setup)
    // -----------------------------------------------------------------------
    struct SetupResult {
        PSID   pSid = nullptr;
        HANDLE hRestrictedToken = nullptr;
        bool   containerCreated = false;
        bool   ok = false;
    };

    // -----------------------------------------------------------------------
    // SetupAppContainer — create AppContainer profile and get SID.
    // -----------------------------------------------------------------------
    inline SetupResult SetupAppContainer(const std::wstring& containerName, SandboxGuard& guard)
    {
        SetupResult r;
        PSID pContainerSid = nullptr;
        HRESULT hr = CreateAppContainerProfile(
            containerName.c_str(), L"Sandy Sandbox",
            L"Sandboxed environment for running executables",
            nullptr, 0, &pContainerSid);
        if (HRESULT_CODE(hr) == ERROR_ALREADY_EXISTS) {
            hr = DeriveAppContainerSidFromAppContainerName(containerName.c_str(), &pContainerSid);
            r.containerCreated = false;
        } else {
            r.containerCreated = SUCCEEDED(hr);
        }
        if (FAILED(hr) || !pContainerSid) {
            g_logger.LogFmt(L"ERROR: AppContainer creation failed (0x%08X)", hr);
            return r;
        }
        r.pSid = pContainerSid;
        guard.Add([pContainerSid]() { FreeSid(pContainerSid); });

        g_logger.Log(L"MODE: appcontainer");
        g_logger.LogFmt(L"CONTAINER: %s", r.containerCreated ? L"created" : L"reused existing");
        LPWSTR sidStr = nullptr;
        if (ConvertSidToStringSidW(pContainerSid, &sidStr)) {
            g_logger.LogFmt(L"CONTAINER_SID: %s", sidStr);
            LocalFree(sidStr);
        }
        r.ok = true;
        return r;
    }

    // -----------------------------------------------------------------------
    // SetupRestrictedToken — create per-instance SID and restricted token.
    // -----------------------------------------------------------------------
    inline SetupResult SetupRestrictedToken(const SandboxConfig& config, SandboxGuard& guard)
    {
        SetupResult r;

        // Generate per-instance grant SID (S-1-9-<uuid>)
        //
        // Uses SECURITY_RESOURCE_MANAGER_AUTHORITY — the Microsoft-
        // designated authority for third-party resource managers.
        // Each instance gets a unique SID derived from a GUID, so:
        //   - ACEs are distinguishable per instance
        //   - Cleanup removes only THIS instance's ACEs
        //   - No multi-instance DACL race conditions
        GUID sidGuid{};
        CoCreateGuid(&sidGuid);
        SID_IDENTIFIER_AUTHORITY rmAuth = { {0, 0, 0, 0, 0, 9} };
        PSID pGrantSid = nullptr;
        if (!AllocateAndInitializeSid(&rmAuth, 4,
                sidGuid.Data1,
                static_cast<DWORD>(sidGuid.Data2 | (sidGuid.Data3 << 16)),
                static_cast<DWORD>(sidGuid.Data4[0] | (sidGuid.Data4[1] << 8) |
                                   (sidGuid.Data4[2] << 16) | (sidGuid.Data4[3] << 24)),
                static_cast<DWORD>(sidGuid.Data4[4] | (sidGuid.Data4[5] << 8) |
                                   (sidGuid.Data4[6] << 16) | (sidGuid.Data4[7] << 24)),
                0, 0, 0, 0, &pGrantSid)) {
            g_logger.LogFmt(L"ERROR: SID allocation failed (error %lu)", GetLastError());
            return r;
        }
        r.pSid = pGrantSid;
        guard.Add([pGrantSid]() { FreeSid(pGrantSid); });

        // Create restricted token with per-instance SID
        r.hRestrictedToken = CreateRestrictedSandboxToken(config.integrity, pGrantSid);
        if (!r.hRestrictedToken) {
            g_logger.LogFmt(L"ERROR: restricted token creation failed (error %lu)", GetLastError());
            return r;
        }
        guard.Add([&r]() { if (r.hRestrictedToken) CloseHandle(r.hRestrictedToken); });

        LPWSTR sidStr = nullptr;
        if (ConvertSidToStringSidW(pGrantSid, &sidStr)) {
            g_logger.LogFmt(L"RT_SID: %s", sidStr);
            LocalFree(sidStr);
        }
        g_logger.Log(config.integrity == IntegrityLevel::Low
                     ? L"MODE: restricted token (Low integrity)"
                     : L"MODE: restricted token (Medium integrity)");
        g_logger.Log(config.allowNamedPipes ? L"Named Pipes: allowed (Everyone in restricting SIDs)"
                                           : L"Named Pipes: blocked (Everyone excluded)");
        r.ok = true;
        return r;
    }

    // =====================================================================
    // RunPipeline — single unified sandbox pipeline
    //
    // Phases:
    //   1. SETUP    — create token/SID, log mode
    //   2. GRANT    — apply ALLOW ACEs, DENY ACEs, registry, desktop
    //   3. PREPARE  — capabilities, env, audit, pipes
    //   4. LAUNCH   — create process, job, resume, relay output
    //   5. CLEANUP  — revoke grants, delete profile, free resources
    //
    // Mode-specific steps are marked with [AC] or [RT] comments.
    // =====================================================================
    inline int RunPipeline(const SandboxConfig& config,
                            const std::wstring& exePath,
                            const std::wstring& exeArgs,
                            const std::wstring& containerName,
                            const std::wstring& exeFolder,
                            const std::wstring& auditLogPath,
                            const std::wstring& dumpPath)
    {
        bool isRestricted = (config.tokenMode == TokenMode::Restricted);
        bool isAppContainer = !isRestricted;

        SandboxGuard guard;  // RAII — all cleanup goes through guard

        // =================================================================
        // PHASE 1: SETUP — create token/SID, log mode
        // =================================================================

        auto setup = isAppContainer
            ? SetupAppContainer(containerName, guard)
            : SetupRestrictedToken(config, guard);
        if (!setup.ok) return SandyExit::SetupError;

        PSID pSid = setup.pSid;
        HANDLE hRestrictedToken = setup.hRestrictedToken;

        g_logger.LogFmt(L"WORKDIR: %s", exeFolder.c_str());

        // =================================================================
        // PHASE 2: GRANT — apply ACLs (ALLOW, then DENY)
        // =================================================================
        ULONGLONG tGrantStart = GetTickCount64();

        // Step 2a: Auto-grant read access to exe folders
        AutoGrantExeFolderAccess(pSid, exeFolder, exePath);

        // Step 2b: [RT] Grant desktop access for the restricted token
        if (isRestricted) {
            GrantDesktopAccess(pSid);
            g_logger.Log(L"DESKTOP: granted WinSta0 + Default access");
            guard.Add([]() { RevokeDesktopAccess(); });
        }

        // Step 2c: Grant configured folder access
        bool grantFailed = !GrantConfiguredAccess(pSid, config);

        // Step 2d: Apply deny rules (always after allows — deny takes precedence)
        if (!ApplyDenyRules(pSid, config, isAppContainer))
            grantFailed = true;

        // Step 2e: [RT] Grant registry access
        if (isRestricted) {
            if (!GrantRegistryAccess(pSid, config))
                grantFailed = true;
        }

        // Step 2f: [AC] Enable loopback if requested
        if (isAppContainer && config.allowLocalhost) {
            bool ok = EnableLoopback(containerName);
            g_logger.Log(ok ? L"LOOPBACK: enabled" : L"LOOPBACK: FAILED (need Administrator)");
            guard.Add([]() { DisableLoopback(); });
        }

        if (grantFailed) {
            g_logger.Log(L"WARNING: some grants failed (need Administrator)");
        }

        // Register grant revocation in guard (runs on any exit)
        guard.Add([]() { RevokeAllGrants(); });

        g_logger.LogFmt(L"TIMING: grants applied in %llums", GetTickCount64() - tGrantStart);

        // =================================================================
        // PHASE 3: PREPARE — capabilities, env, pipes
        // =================================================================

        // Step 3a: [AC] Build capabilities (network SIDs)
        CapabilityState caps = {};
        SECURITY_CAPABILITIES sc{};
        if (isAppContainer) {
            caps = BuildCapabilities(config);
            sc.AppContainerSid = pSid;
            sc.Capabilities = caps.capCount > 0 ? caps.caps : nullptr;
            sc.CapabilityCount = caps.capCount;
            guard.Add([&caps]() { FreeCapabilities(caps); });
        }

        // Step 3b: Build attribute list
        AttributeListState attrs = BuildAttributeList(config,
            isAppContainer ? &sc : nullptr, isRestricted);
        if (!attrs.valid) return SandyExit::SetupError;
        guard.Add([&attrs]() { FreeAttributeList(attrs); });

        // Step 3c: Log stdin, build environment, print config summary
        LogStdinMode(config.stdinMode);
        std::vector<wchar_t> envBlock = BuildEnvironmentBlock(config);
        LogEnvironmentState(config);
        if (!g_logger.IsActive())
            PrintConfigSummary(config, exePath, exeArgs, isRestricted);

        // Step 3d: Setup audit and crash dumps
        std::wstring procmonExe;
        bool auditActive = false;
        SetupAudit(auditLogPath, procmonExe, auditActive);

        std::wstring crashExeName;
        bool crashDumpsEnabled = false;
        SetupCrashDumps(auditLogPath, dumpPath, exePath, crashExeName, crashDumpsEnabled);

        // Step 3e: Create output pipe and stdin handle
        HANDLE hReadPipe = nullptr, hWritePipe = nullptr;
        if (!SetupOutputPipe(hReadPipe, hWritePipe)) {
            g_logger.Log(L"ERROR: pipe creation failed");
            return SandyExit::SetupError;
        }
        HANDLE hStdin = nullptr, hStdinFile = nullptr;
        if (!SetupStdinHandle(config.stdinMode, hStdin, hStdinFile)) {
            CloseHandle(hReadPipe); CloseHandle(hWritePipe);
            return SandyExit::SetupError;
        }

        g_logger.LogFmt(L"TIMING: total setup %llums (ready to launch)", GetTickCount64() - tGrantStart);

        // =================================================================
        // PHASE 4: LAUNCH & RUN
        // =================================================================

        // Log config before launch so it's always in the log even for instant failures
        g_logger.LogConfig(config, exePath, exeArgs);

        // Step 4a: Launch the child process (suspended)
        PROCESS_INFORMATION pi{};
        bool launched = LaunchChildProcess(
            isRestricted,
            isRestricted ? hRestrictedToken : nullptr,
            attrs.pAttrList, envBlock, exeFolder, exePath, exeArgs,
            hStdin, hWritePipe, pi);

        // Close write end (parent doesn't need it) and stdin file
        CloseHandle(hWritePipe);
        if (hStdinFile) CloseHandle(hStdinFile);

        if (!launched) {
            DWORD launchErr = GetLastError();
            g_logger.Log(L"LAUNCH: FAILED (see LAUNCH_FAILED above)");
            g_logger.LogSummary(launchErr, false, 0);
            CloseHandle(hReadPipe);
            // [AC] Delete profile on launch failure
            if (isAppContainer)
                DeleteAppContainerProfile(containerName.c_str());
            guard.RunAll();
            DeleteCleanupTask(g_instanceId);
            g_logger.Log(L"CLEANUP: complete (launch failure)");
            g_logger.Stop();
            // POSIX convention: 127 = not found, 126 = cannot execute
            bool notFound = (launchErr == ERROR_FILE_NOT_FOUND ||
                             launchErr == ERROR_PATH_NOT_FOUND);
            return notFound ? SandyExit::NotFound : SandyExit::CannotExec;
        }

        // Step 4b: Assign job object for resource limits
        HANDLE hJob = AssignJobObject(config, pi.hProcess);
        bool jobNeeded = (config.memoryLimitMB > 0 || config.maxProcesses > 0 ||
                          !config.allowClipboardRead || !config.allowClipboardWrite);
        if (jobNeeded && !hJob) {
            g_logger.Log(L"ERROR: job object assignment failed — aborting (limits NOT enforced)");
            TerminateProcess(pi.hProcess, SandyExit::SetupError);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            if (isAppContainer)
                DeleteAppContainerProfile(containerName.c_str());
            guard.RunAll();
            DeleteCleanupTask(g_instanceId);
            g_logger.Log(L"CLEANUP: complete (job assignment failure)");
            g_logger.Stop();
            return SandyExit::SetupError;
        }

        // Step 4c: Resume child and start timeout watchdog
        ResumeThread(pi.hThread);
        g_logger.Log(L"CHILD: resumed");
        CloseHandle(pi.hThread);

        TimeoutContext timeoutCtx = { pi.hProcess, config.timeoutSeconds, false };
        HANDLE hTimeoutThread = StartTimeoutWatchdog(timeoutCtx);

        // Step 4d: Relay output and wait for exit
        DWORD exitCode = RelayOutputAndWait(pi.hProcess, hReadPipe,
                                             hTimeoutThread, timeoutCtx,
                                             config.timeoutSeconds);

        // =================================================================
        // PHASE 5: CLEANUP (guard handles grants, SID, token, caps, attrs)
        // =================================================================

        // Step 5a: Log summary and finalize audit/dumps
        g_logger.LogSummary(exitCode, timeoutCtx.timedOut, config.timeoutSeconds);
        if (timeoutCtx.timedOut)
            g_logger.Log(L"EXIT_CLASS: TIMEOUT");
        else if (IsCrashExitCode(exitCode))
            g_logger.LogFmt(L"EXIT_CLASS: CRASH (0x%08X)", exitCode);
        else if (exitCode != 0)
            g_logger.LogFmt(L"EXIT_CLASS: ERROR (code=%ld)", (long)exitCode);
        else
            g_logger.Log(L"EXIT_CLASS: CLEAN");
        FinalizeAuditAndDumps(auditActive, procmonExe, auditLogPath, dumpPath,
                              crashDumpsEnabled, crashExeName, pi.dwProcessId, exitCode);

        // Step 5b: Close process and job handles
        CloseHandle(pi.hProcess);
        if (hJob) CloseHandle(hJob);

        // Step 5c: Mode-specific cleanup
        g_logger.Log(L"CLEANUP: starting");
        DWORD cleanupStart = GetTickCount();

        // [AC] Delete AppContainer profile
        if (isAppContainer) {
            HRESULT hrDel = DeleteAppContainerProfile(containerName.c_str());
            g_logger.Log((L"PROFILE_DELETE: " + containerName +
                (SUCCEEDED(hrDel) ? L" -> OK" : L" -> FAILED")).c_str());
        }

        // Run all guard cleanups explicitly (RevokeAllGrants, RevokeDesktopAccess,
        // DisableLoopback, FreeCapabilities, FreeAttributeList, FreeSid, CloseHandle)
        // This must finish BEFORE DeleteCleanupTask so our own grants subkey is gone.
        guard.RunAll();

        DeleteCleanupTask(g_instanceId);
        g_logger.LogFmt(L"CLEANUP: complete (%lums)", GetTickCount() - cleanupStart);
        g_logger.Stop();

        // Map child exit code to Sandy exit code:
        //   timeout  → SandyExit::Timeout (7)
        //   crash    → SandyExit::ChildCrash (9)
        //   normal   → child's exit code as-is
        int sandyExit;
        if (timeoutCtx.timedOut)
            sandyExit = SandyExit::Timeout;
        else if (IsCrashExitCode(exitCode))
            sandyExit = SandyExit::ChildCrash;
        else
            sandyExit = static_cast<int>(exitCode);

        return sandyExit;
    }

    // =====================================================================
    // RunSandboxed — common entry point.
    //
    // Instance-wide setup (ID, logger, stale state) then RunPipeline().
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

        // --- Determine working directory ---
        std::wstring exeFolder = config.workdir.empty() ? GetExeFolder() : config.workdir;
        if (exeFolder.empty())
            return SandyExit::SetupError;

        // --- Start logger early for forensic logging ---
        if (!config.logPath.empty())
            g_logger.Start(config.logPath);

        // --- Common startup: clean stale state, warn, create safety net ---
        CleanupStaleStartupState(exePath);
        WarnStaleRegistryEntries();
        CreateCleanupTask(g_instanceId);
        LogSandyIdentity();
        g_logger.Log((L"INSTANCE: " + g_instanceId).c_str());
        if (!config.configSource.empty())
            g_logger.Log((L"CONFIG_SOURCE: " + config.configSource).c_str());

        // --- Run the unified pipeline ---
        return RunPipeline(config, exePath, exeArgs, containerName,
                            exeFolder, auditLogPath, dumpPath);
    }

    // -----------------------------------------------------------------------
    // CleanupSandbox — full cleanup for --cleanup command (stale recovery)
    // -----------------------------------------------------------------------
    inline void CleanupSandbox()
    {
        g_logger.Log(L"EMERGENCY_CLEANUP: starting");
        RevokeDesktopAccess();
        RevokeAllGrants();
        DisableLoopback();
        std::wstring containerName = ContainerNameFromId(g_instanceId);
        if (!containerName.empty()) {
            HRESULT hr = DeleteAppContainerProfile(containerName.c_str());
            g_logger.Log((L"PROFILE_DELETE: " + containerName +
                (SUCCEEDED(hr) ? L" -> OK" : L" -> FAILED")).c_str());
        }
        RestoreStaleGrants();
        RestoreStaleWER();
        DeleteStaleCleanupTasks();
        g_logger.Log(L"EMERGENCY_CLEANUP: complete");
        g_logger.Stop();
    }

} // namespace Sandbox
