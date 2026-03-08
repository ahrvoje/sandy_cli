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
                                     bool isDeny,
                                     bool isPeek)
    {
        RecordGrant(path, objType, sidString, trappedSids, isDeny, isPeek);
    }

    // -----------------------------------------------------------------------
    // ApplyAccessPipeline — depth-sorted grant/deny execution.
    //
    // Merges all allow + deny entries into a single pipeline sorted by path
    // depth (shallowest first).  When an allow path is under a previously
    // applied deny, strips the deny ACEs from the allow subtree first, then
    // grants.  Peek strips are non-recursive (directory only).
    //
    // This ensures the most specific (deepest) path always wins.
    // -----------------------------------------------------------------------

    struct PipelineEntry {
        std::wstring path;
        AccessLevel  access;
        bool         isDeny;
        int          depth;
    };

    static int PathDepth(const std::wstring& p) {
        int d = 0;
        for (auto c : p) if (c == L'\\') d++;
        return d;
    }

    // Check if `child` is at or under `parent` (case-insensitive, backslash boundary)
    static bool IsPathUnder(const std::wstring& child, const std::wstring& parent) {
        if (child.size() < parent.size()) return false;
        if (_wcsnicmp(child.c_str(), parent.c_str(), parent.size()) != 0) return false;
        // Exact match or child continues with backslash
        return child.size() == parent.size() || child[parent.size()] == L'\\';
    }

    inline bool ApplyAccessPipeline(PSID pSid, const SandboxConfig& config, bool isAppContainer)
    {
        // 1. Build pipeline
        std::vector<PipelineEntry> pipeline;
        for (const auto& e : config.folders) {
            if (e.path.empty()) continue;
            pipeline.push_back({ e.path, e.access, false, PathDepth(e.path) });
        }
        for (const auto& e : config.denyFolders) {
            if (e.path.empty()) continue;
            pipeline.push_back({ e.path, e.access, true, PathDepth(e.path) });
        }

        // 2. Stable sort: by depth ascending, deny before allow at same depth
        std::stable_sort(pipeline.begin(), pipeline.end(),
            [](const PipelineEntry& a, const PipelineEntry& b) {
                if (a.depth != b.depth) return a.depth < b.depth;
                // deny before allow at same depth
                if (a.isDeny != b.isDeny) return a.isDeny;
                return false;
            });

        // 3. Log the sorted plan
        g_logger.LogFmt(L"PIPELINE: sorted %zu entries by path depth:", pipeline.size());
        // Pre-scan: collect deny paths for annotation
        std::vector<std::wstring> preDenyPaths;
        for (const auto& e : pipeline) {
            if (e.isDeny) {
                preDenyPaths.push_back(e.path);
            }
        }
        for (const auto& e : pipeline) {
            bool underDeny = false;
            if (!e.isDeny) {
                for (const auto& dp : preDenyPaths) {
                    if (IsPathUnder(e.path, dp)) { underDeny = true; break; }
                }
            }
            if (e.isDeny) {
                g_logger.LogFmt(L"    DENY  [%-7s] %s",
                    AccessTag(e.access), e.path.c_str());
            } else if (underDeny && e.access == AccessLevel::Peek) {
                g_logger.LogFmt(L"    ALLOW [%-7s] %s  <- strip deny (dir only)",
                    AccessTag(e.access), e.path.c_str());
            } else if (underDeny) {
                g_logger.LogFmt(L"    ALLOW [%-7s] %s  <- strip deny (subtree)",
                    AccessTag(e.access), e.path.c_str());
            } else {
                g_logger.LogFmt(L"    ALLOW [%-7s] %s",
                    AccessTag(e.access), e.path.c_str());
            }
        }

        // 4. Execute pipeline
        bool allOk = true;
        std::vector<std::wstring> activeDenyPaths;
        // Convert SID to string once (for RemoveSidFromDacl calls)
        std::wstring sidStr;
        {
            LPWSTR s = nullptr;
            if (ConvertSidToStringSidW(pSid, &s)) {
                sidStr = s;
                LocalFree(s);
            }
        }

        for (const auto& e : pipeline) {
            if (e.isDeny) {
                // Apply deny
                DWORD rc = DenyObjectAccess(pSid, e.path, e.access, isAppContainer, RecordGrantCallback);
                bool ok = (rc == ERROR_SUCCESS);
                if (!ok) allOk = false;
                if (ok) {
                    g_logger.LogFmt(L"DENY: [%s] %s -> OK (mask=0x%08X)",
                        AccessTag(e.access), e.path.c_str(), AccessMask(e.access));
                    activeDenyPaths.push_back(e.path);
                } else {
                    g_logger.LogFmt(L"DENY: [%s] %s -> FAILED (0x%08X: %s)",
                        AccessTag(e.access), e.path.c_str(),
                        rc, GetSystemErrorMessage(rc).c_str());
                }
            } else {
                // Check if this allow is under an active deny
                bool underDeny = false;
                for (const auto& dp : activeDenyPaths) {
                    if (IsPathUnder(e.path, dp)) { underDeny = true; break; }
                }

                // Strip deny ACEs if needed
                if (underDeny && !sidStr.empty()) {
                    bool isPeek = (e.access == AccessLevel::Peek);
                    g_logger.LogFmt(L"STRIP_DENY: %s (%s)",
                        e.path.c_str(), isPeek ? L"dir only" : L"subtree");
                    RemoveSidFromDacl(e.path, sidStr, SE_FILE_OBJECT,
                                     true, L"", isPeek);
                }

                // Apply allow
                DWORD rc = GrantObjectAccess(pSid, e.path, e.access, RecordGrantCallback);
                bool ok = (rc == ERROR_SUCCESS);
                if (!ok) allOk = false;
                if (ok) {
                    g_logger.LogFmt(L"GRANT: [%s] %s -> OK (mask=0x%08X)",
                        AccessTag(e.access), e.path.c_str(), AccessMask(e.access));
                } else {
                    g_logger.LogFmt(L"GRANT: [%s] %s -> FAILED (0x%08X: %s)",
                        AccessTag(e.access), e.path.c_str(),
                        rc, GetSystemErrorMessage(rc).c_str());
                }
            }
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
                DWORD rc = GrantObjectAccess(pSid, win32Path, rg.level, RecordGrantCallback, SE_REGISTRY_KEY);
                bool ok = (rc == ERROR_SUCCESS);
                if (!ok) allOk = false;
                if (ok) {
                    g_logger.LogFmt(L"GRANT_REG: [%s] %s -> OK", rg.tag, key.c_str());
                } else {
                    g_logger.LogFmt(L"GRANT_REG: [%s] %s -> FAILED (0x%08X: %s)",
                                    rg.tag, key.c_str(), rc, GetSystemErrorMessage(rc).c_str());
                }
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
                           std::wstring& procmonExe, bool& auditActive,
                           std::wstring& auditPmlPath)
    {
        procmonExe.clear();
        auditActive = false;
        auditPmlPath.clear();
        if (auditLogPath.empty()) return;

        procmonExe = FindProcmon();
        if (procmonExe.empty()) {
            g_logger.Log(L"AUDIT: Procmon not found on PATH, audit disabled");
            return;
        }
        auditActive = StartProcmonAudit(procmonExe, auditPmlPath);
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
                                       const std::wstring& auditPmlPath,
                                       const std::wstring& dumpPath,
                                       bool crashDumpsEnabled,
                                       const std::wstring& crashExeName,
                                       DWORD childPid, DWORD exitCode)
    {
        if (auditActive) {
            std::string processTree = StopProcmonAudit(procmonExe, auditLogPath, auditPmlPath, childPid);
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
        PSID pGrantSid = AllocateInstanceSid();
        if (!pGrantSid) {
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

    // -----------------------------------------------------------------------
    // PipelineContext — carries pre-created state for profile mode.
    //
    // Normal mode:  pSid=nullptr, hToken=nullptr, profileMode=false
    //               → RunPipeline creates SID/token in Phase 1.
    // Profile mode: pSid=<profile SID>, hToken=<restricted token or nullptr>,
    //               profileMode=true
    //               → RunPipeline skips SID creation, skips grants, skips
    //                 grant revocation on cleanup.
    // -----------------------------------------------------------------------
    struct PipelineContext {
        PSID   pSid = nullptr;           // pre-created SID (profile mode)
        HANDLE hToken = nullptr;         // pre-created restricted token (profile RT mode)
        bool   profileMode = false;      // skip grants + revocation
    };

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
    // Profile mode skips grant application (Phase 2) and revocation (Phase 5).
    // =====================================================================
    inline int RunPipeline(const SandboxConfig& config,
                            const std::wstring& exePath,
                            const std::wstring& exeArgs,
                            const std::wstring& containerName,
                            const std::wstring& exeFolder,
                            const std::wstring& auditLogPath,
                            const std::wstring& dumpPath,
                            const PipelineContext& ctx = {})
    {
        bool isRestricted = (config.tokenMode == TokenMode::Restricted);
        bool isAppContainer = !isRestricted;

        SandboxGuard guard;  // RAII — all cleanup goes through guard

        // =================================================================
        // PHASE 1: SETUP — create token/SID, log mode
        // =================================================================

        PSID pSid = nullptr;
        HANDLE hRestrictedToken = nullptr;

        if (ctx.pSid) {
            // Profile mode: SID and token are pre-created by caller
            pSid = ctx.pSid;
            hRestrictedToken = ctx.hToken;
        } else {
            // Normal mode: create fresh SID/token
            auto setup = isAppContainer
                ? SetupAppContainer(containerName, guard)
                : SetupRestrictedToken(config, guard);
            if (!setup.ok) return SandyExit::SetupError;
            pSid = setup.pSid;
            hRestrictedToken = setup.hRestrictedToken;
        }

        g_logger.LogFmt(L"WORKDIR: %s", exeFolder.c_str());

        // =================================================================
        // PHASE 2: GRANT — apply ACLs (ALLOW, then DENY)
        // =================================================================

        if (ctx.profileMode) {
            // Profile mode: ACLs are persistent from --create-profile
            g_logger.Log(L"GRANTS: skipped (persistent profile)");
        } else {
            ULONGLONG tGrantStart = GetTickCount64();

            // Step 2a: Auto-grant read access to exe folders
            AutoGrantExeFolderAccess(pSid, exeFolder, exePath);

            // Step 2b: Apply depth-sorted access pipeline (allow + deny, most specific wins)
            bool grantFailed = !ApplyAccessPipeline(pSid, config, isAppContainer);

            // Step 2c: [RT] Grant registry access
            if (isRestricted) {
                if (!GrantRegistryAccess(pSid, config))
                    grantFailed = true;
            }

            if (grantFailed) {
                g_logger.Log(L"WARNING: some grants failed (need Administrator)");
            }

            // Register grant revocation in guard (runs on any exit)
            guard.Add([]() { RevokeAllGrants(); });

            g_logger.LogFmt(L"TIMING: grants applied in %llums", GetTickCount64() - tGrantStart);
        }

        // Desktop and loopback are per-run (even in profile mode)

        // [RT] Grant desktop access for the restricted token
        if (isRestricted) {
            GrantDesktopAccess(pSid);
            g_logger.Log(L"DESKTOP: granted WinSta0 + Default access");
            guard.Add([]() { RevokeDesktopAccess(); });
        }

        // [AC] Enable loopback if requested
        if (isAppContainer && config.allowLocalhost) {
            bool ok = EnableLoopback(containerName);
            g_logger.Log(ok ? L"LOOPBACK: enabled" : L"LOOPBACK: FAILED (need Administrator)");
            guard.Add([]() { DisableLoopback(); });
        }

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
        std::wstring auditPmlPath;
        SetupAudit(auditLogPath, procmonExe, auditActive, auditPmlPath);

        std::wstring crashExeName;
        bool crashDumpsEnabled = false;
        SetupCrashDumps(auditLogPath, dumpPath, exePath, crashExeName, crashDumpsEnabled);

        // Step 3e: Setup stdin handle
        HANDLE hStdin = nullptr, hStdinFile = nullptr;
        if (!SetupStdinHandle(config.stdinMode, hStdin, hStdinFile)) {
            return SandyExit::SetupError;
        }

        // =================================================================
        // PHASE 4: LAUNCH & RUN
        // =================================================================

        // Log config before launch so it's always in the log even for instant failures
        g_logger.LogConfig(config, exePath, exeArgs);

        // Step 3f: [RT] Pre-launch token integrity validation (defense-in-depth)
        // Verify the restricted token's integrity level matches the configured
        // value before handing it to CreateProcessAsUser.  Catches any subtle
        // mutation that could have occurred during Phases 2-3.
        if (isRestricted && hRestrictedToken) {
            DWORD ilSize = 0;
            GetTokenInformation(hRestrictedToken, TokenIntegrityLevel, nullptr, 0, &ilSize);
            if (ilSize > 0) {
                std::vector<BYTE> ilBuf(ilSize);
                auto* pTIL = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(ilBuf.data());
                if (GetTokenInformation(hRestrictedToken, TokenIntegrityLevel, pTIL, ilSize, &ilSize)) {
                    DWORD actualIL = *GetSidSubAuthority(pTIL->Label.Sid,
                                     *GetSidSubAuthorityCount(pTIL->Label.Sid) - 1);
                    DWORD expectedIL = (config.integrity == IntegrityLevel::Low)
                                       ? SECURITY_MANDATORY_LOW_RID
                                       : SECURITY_MANDATORY_MEDIUM_RID;
                    if (actualIL != expectedIL) {
                        g_logger.LogFmt(L"TOKEN_VALIDATE: FAILED — expected IL 0x%04X, got 0x%04X. Aborting launch.",
                                        expectedIL, actualIL);
                        if (hStdinFile) CloseHandle(hStdinFile);
                        guard.RunAll();
                        if (!ctx.profileMode) DeleteCleanupTask(g_instanceId);
                        g_logger.Stop();
                        return SandyExit::SetupError;
                    }
                    g_logger.LogFmt(L"TOKEN_VALIDATE: OK (IL=0x%04X)", actualIL);
                }
            }
        }

        // Step 4a: Launch the child process (suspended, console passthrough)
        PROCESS_INFORMATION pi{};
        bool launched = LaunchChildProcess(
            isRestricted,
            isRestricted ? hRestrictedToken : nullptr,
            attrs.pAttrList, envBlock, exeFolder, exePath, exeArgs,
            hStdin, pi);

        // Close stdin file handle (parent doesn't need it)
        if (hStdinFile) CloseHandle(hStdinFile);

        if (!launched) {
            DWORD launchErr = GetLastError();
            g_logger.Log(L"LAUNCH: FAILED (see LAUNCH_FAILED above)");
            g_logger.LogSummary(launchErr, false, 0);
            // [AC] Delete profile on launch failure (normal mode only)
            if (isAppContainer && !ctx.profileMode)
                DeleteAppContainerProfile(containerName.c_str());
            guard.RunAll();
            if (!ctx.profileMode) DeleteCleanupTask(g_instanceId);
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
            if (isAppContainer && !ctx.profileMode)
                DeleteAppContainerProfile(containerName.c_str());
            guard.RunAll();
            if (!ctx.profileMode) DeleteCleanupTask(g_instanceId);
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

        // Step 4d: Wait for child exit (console passthrough — no pipe relay)
        DWORD exitCode = WaitForChildExit(pi.hProcess,
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
        FinalizeAuditAndDumps(auditActive, procmonExe, auditLogPath, auditPmlPath, dumpPath,
                              crashDumpsEnabled, crashExeName, pi.dwProcessId, exitCode);

        // Step 5b: Close process and job handles
        CloseHandle(pi.hProcess);
        if (hJob) CloseHandle(hJob);

        // Step 5c: Mode-specific cleanup
        if (ctx.profileMode)
            g_logger.Log(L"CLEANUP: starting (profile — grants preserved)");
        else
            g_logger.Log(L"CLEANUP: starting");
        DWORD cleanupStart = GetTickCount();

        // [AC] Delete AppContainer profile (normal mode only)
        if (isAppContainer && !ctx.profileMode) {
            HRESULT hrDel = DeleteAppContainerProfile(containerName.c_str());
            g_logger.Log((L"PROFILE_DELETE: " + containerName +
                (SUCCEEDED(hrDel) ? L" -> OK" : L" -> FAILED")).c_str());
        }

        // Run all guard cleanups explicitly (RevokeAllGrants, RevokeDesktopAccess,
        // DisableLoopback, FreeCapabilities, FreeAttributeList, FreeSid, CloseHandle)
        // This must finish BEFORE DeleteCleanupTask so our own grants subkey is gone.
        guard.RunAll();

        if (!ctx.profileMode) DeleteCleanupTask(g_instanceId);
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

        // --- Logger is already started by sandy.cpp (early init) ---

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
