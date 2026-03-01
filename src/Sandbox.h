#pragma once
// Sandbox.h — Sandbox orchestrator
// Launches executables inside AppContainer or Restricted Token sandboxes.
// All behavior is controlled by SandboxConfig (loaded via SandboxConfig.h).

#include "framework.h"
#include "SandboxConfig.h"
#include "SandboxACL.h"
#include "SandboxToken.h"

namespace Sandbox {


    // Track loopback state for cleanup
    static bool g_loopbackGranted = false;

    // -----------------------------------------------------------------------
    // Loopback exemption — allow localhost access for AppContainer.
    // Uses CheckNetIsolation.exe (additive, safe for other apps).
    // Requires administrator privileges.
    // -----------------------------------------------------------------------
    inline bool EnableLoopback()
    {
        wchar_t cmd[] = L"CheckNetIsolation.exe LoopbackExempt -a -n=SandySandbox";

        STARTUPINFOW si = { sizeof(si) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        PROCESS_INFORMATION pi = {};
        if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
            return false;

        WaitForSingleObject(pi.hProcess, 5000);
        DWORD exitCode = 1;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        g_loopbackGranted = (exitCode == 0);
        return g_loopbackGranted;
    }

    inline void DisableLoopback()
    {
        if (!g_loopbackGranted) return;

        wchar_t cmd[] = L"CheckNetIsolation.exe LoopbackExempt -d -n=SandySandbox";

        STARTUPINFOW si = { sizeof(si) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        PROCESS_INFORMATION pi = {};
        if (CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        {
            WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
        g_loopbackGranted = false;
    }

    // -----------------------------------------------------------------------
    // Timeout watchdog — terminates child process after N seconds
    // -----------------------------------------------------------------------
    struct TimeoutContext {
        HANDLE hProcess;
        DWORD  seconds;
        bool   timedOut;
    };

    static DWORD WINAPI TimeoutThread(LPVOID param)
    {
        auto* ctx = static_cast<TimeoutContext*>(param);
        ctx->timedOut = false;
        if (WaitForSingleObject(ctx->hProcess, ctx->seconds * 1000) == WAIT_TIMEOUT) {
            ctx->timedOut = true;
            TerminateProcess(ctx->hProcess, 1);
        }
        return 0;
    }

    // -----------------------------------------------------------------------
    // Build a filtered environment block for CreateProcessW
    // -----------------------------------------------------------------------
    inline std::vector<wchar_t> BuildEnvironmentBlock(const SandboxConfig& config)
    {
        std::vector<wchar_t> block;

        if (config.envInherit)
            return block;  // empty = pass nullptr to CreateProcessW (inherit all)

        // Collect environment variables
        // Hidden vars (starting with '=', e.g. =C:=C:\path) are drive-letter
        // assignments required by the Windows loader — always include them.
        std::vector<std::wstring> hiddenVars;
        std::vector<std::pair<std::wstring, std::wstring>> env;

        LPWCH envStrings = GetEnvironmentStringsW();
        if (envStrings) {
            for (LPCWSTR p = envStrings; *p; p += wcslen(p) + 1) {
                std::wstring entry(p);
                if (entry[0] == L'=') {
                    hiddenVars.push_back(entry);
                    continue;
                }
                auto eq = entry.find(L'=');
                if (eq != std::wstring::npos && eq > 0)
                    env.push_back({ entry.substr(0, eq), entry.substr(eq + 1) });
            }
            FreeEnvironmentStringsW(envStrings);
        }

        // Keep only essential vars + explicitly passed vars
        std::vector<std::pair<std::wstring, std::wstring>> filtered;
        auto isAllowed = [&](const std::wstring& name) {
            // Always pass essential Windows vars needed by the loader
            static const wchar_t* essential[] = {
                L"SYSTEMROOT", L"SYSTEMDRIVE", L"WINDIR",
                L"TEMP", L"TMP",
                L"COMSPEC", L"PATHEXT",
                L"LOCALAPPDATA", L"APPDATA",
                L"USERPROFILE", L"HOMEDRIVE", L"HOMEPATH",
                L"PROCESSOR_ARCHITECTURE", L"NUMBER_OF_PROCESSORS",
                L"OS",
            };
            for (auto* e : essential) {
                if (_wcsicmp(name.c_str(), e) == 0) return true;
            }
            // Check pass list
            for (auto& allowed : config.envPass) {
                if (_wcsicmp(name.c_str(), allowed.c_str()) == 0) return true;
            }
            return false;
        };
        for (auto& p : env) {
            if (isAllowed(p.first)) filtered.push_back(p);
        }
        env = std::move(filtered);

        // Sort regular vars alphabetically by name (required by Windows)
        std::sort(env.begin(), env.end(),
            [](const std::pair<std::wstring, std::wstring>& a,
               const std::pair<std::wstring, std::wstring>& b) {
                return _wcsicmp(a.first.c_str(), b.first.c_str()) < 0;
            });

        // Serialize: hidden vars first, then KEY=VALUE\0...\0
        for (auto& h : hiddenVars) {
            block.insert(block.end(), h.begin(), h.end());
            block.push_back(L'\0');
        }
        for (auto& p : env) {
            std::wstring line = p.first + L"=" + p.second;
            block.insert(block.end(), line.begin(), line.end());
            block.push_back(L'\0');
        }
        block.push_back(L'\0');
        return block;
    }



    inline int RunSandboxed(const SandboxConfig& config,
                            const std::wstring& exePath,
                            const std::wstring& exeArgs)
    {
        // --- Mode-specific state ---
        PSID pContainerSid = nullptr;
        HANDLE hRestrictedToken = nullptr;
        PSID pGrantSid = nullptr;          // SID used for DACL grants
        bool containerCreated = false;
        bool isRestricted = (config.tokenMode == TokenMode::Restricted);

        // --- Determine working directory (folder containing sandy.exe) ---
        std::wstring exeFolder = GetExeFolder();
        if (exeFolder.empty())
            return 1;

        // --- Start logger early for forensic logging ---
        if (!config.logPath.empty()) {
            g_logger.Start(config.logPath);
        }

        // --- Forensic: Sandy identity ---
        {
            wchar_t msg[512];
            swprintf(msg, 512, L"SANDY: PID %lu", GetCurrentProcessId());
            g_logger.Log(msg);

            HANDLE hToken = nullptr;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
                DWORD ilSize = 0;
                GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &ilSize);
                if (ilSize > 0) {
                    std::vector<BYTE> ilBuf(ilSize);
                    auto* pTIL = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(ilBuf.data());
                    if (GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, ilSize, &ilSize)) {
                        DWORD il = *GetSidSubAuthority(pTIL->Label.Sid,
                                    *GetSidSubAuthorityCount(pTIL->Label.Sid) - 1);
                        const wchar_t* ilName = il >= SECURITY_MANDATORY_HIGH_RID ? L"High (elevated)" :
                                                il >= SECURITY_MANDATORY_MEDIUM_RID ? L"Medium" : L"Low";
                        swprintf(msg, 512, L"SANDY: integrity=%s (0x%04X)", ilName, il);
                        g_logger.Log(msg);
                    }
                }
                CloseHandle(hToken);
            }
        }

        if (isRestricted) {
            // =============================================================
            // RESTRICTED TOKEN PATH
            // =============================================================
            hRestrictedToken = CreateRestrictedSandboxToken(config.integrity);
            if (!hRestrictedToken) {
                fprintf(stderr, "[Error] Could not create restricted token (error %lu).\n", GetLastError());
                return 1;
            }

            // Use RESTRICTED SID (S-1-5-12) for DACL grants
            SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
            AllocateAndInitializeSid(&ntAuth, 1, SECURITY_RESTRICTED_CODE_RID,
                0, 0, 0, 0, 0, 0, 0, &pGrantSid);

            g_logger.Log(config.integrity == IntegrityLevel::Low
                         ? L"MODE: restricted token (Low integrity)"
                         : L"MODE: restricted token (Medium integrity)");
            g_logger.Log(config.allowNamedPipes ? L"Named Pipes: allowed (Everyone in restricting SIDs)"
                                           : L"Named Pipes: blocked (Everyone excluded)");

            // Auto-grant read access to the exe folder (sandy.exe location)
            GrantObjectAccess(pGrantSid, exeFolder, AccessLevel::Read);
            g_logger.Log((L"GRANT_AUTO: [R] " + exeFolder).c_str());

            // Auto-grant read access to the target executable's folder
            // so its DLLs (python314.dll, vcruntime etc.) are accessible.
            {
                wchar_t resolvedExe[MAX_PATH]{};
                DWORD found = SearchPathW(nullptr, exePath.c_str(), L".exe",
                                          MAX_PATH, resolvedExe, nullptr);
                if (found) {
                    std::wstring targetFolder(resolvedExe);
                    auto slash = targetFolder.find_last_of(L"\\/");
                    if (slash != std::wstring::npos)
                        targetFolder.resize(slash);
                    if (_wcsicmp(targetFolder.c_str(), exeFolder.c_str()) != 0) {
                        GrantObjectAccess(pGrantSid, targetFolder, AccessLevel::Read);
                        g_logger.Log((L"GRANT_AUTO: [R] " + targetFolder).c_str());
                    }
                }
            }

            // Grant window station and desktop access for the restricted token
            GrantDesktopAccess(pGrantSid);
            g_logger.Log(L"DESKTOP: granted WinSta0 + Default access");

            wchar_t msg[512];
            swprintf(msg, 512, L"WORKDIR: %s", exeFolder.c_str());
            g_logger.Log(msg);

        } else {
            // =============================================================
            // APPCONTAINER PATH
            // =============================================================
            HRESULT hr = CreateAppContainerProfile(
                kContainerName, L"Sandy Sandbox",
                L"Sandboxed environment for running executables",
                nullptr, 0, &pContainerSid);

            containerCreated = true;
            if (HRESULT_CODE(hr) == ERROR_ALREADY_EXISTS) {
                hr = DeriveAppContainerSidFromAppContainerName(kContainerName, &pContainerSid);
                containerCreated = false;
            }

            if (FAILED(hr) || !pContainerSid) {
                fprintf(stderr, "[Error] Could not create AppContainer (0x%08X).\n", hr);
                return 1;
            }

            pGrantSid = pContainerSid;  // Use container SID for DACL grants

            g_logger.Log(L"MODE: appcontainer");
            {
                wchar_t msg[512];
                swprintf(msg, 512, L"CONTAINER: %s", containerCreated ? L"created" : L"reused existing");
                g_logger.Log(msg);

                LPWSTR sidStr = nullptr;
                if (ConvertSidToStringSidW(pContainerSid, &sidStr)) {
                    swprintf(msg, 512, L"CONTAINER_SID: %s", sidStr);
                    g_logger.Log(msg);
                    LocalFree(sidStr);
                }

                swprintf(msg, 512, L"WORKDIR: %s", exeFolder.c_str());
                g_logger.Log(msg);
            }
        }

        // --- Grant configured folder access (common to both modes) ---
        bool grantFailed = false;
        for (const auto& entry : config.folders) {
            bool ok = GrantObjectAccess(pGrantSid, entry.path, entry.access);
            if (!ok) {
                fprintf(stderr, "[Warning] Could not grant access to: %ls\n", entry.path.c_str());
                grantFailed = true;
            }
            wchar_t msg[512];
            swprintf(msg, 512, L"GRANT: [%s] %s -> %s (mask=0x%08X)",
                     AccessTag(entry.access), entry.path.c_str(),
                     ok ? L"OK" : L"FAILED", AccessMask(entry.access));
            g_logger.Log(msg);
        }

        // --- Grant registry access (restricted mode only) ---
        if (isRestricted) {
            for (const auto& key : config.registryRead) {
                std::wstring win32Path = RegistryToWin32Path(key);
                bool ok = GrantObjectAccess(pGrantSid, win32Path, AccessLevel::Read, SE_REGISTRY_KEY);
                wchar_t msg[512];
                swprintf(msg, 512, L"GRANT_REG: [R] %s -> %s", key.c_str(), ok ? L"OK" : L"FAILED");
                g_logger.Log(msg);
                if (!ok) {
                    fprintf(stderr, "[Warning] Could not grant registry read: %ls\n", key.c_str());
                    grantFailed = true;
                }
            }
            for (const auto& key : config.registryWrite) {
                std::wstring win32Path = RegistryToWin32Path(key);
                bool ok = GrantObjectAccess(pGrantSid, win32Path, AccessLevel::Write, SE_REGISTRY_KEY);
                wchar_t msg[512];
                swprintf(msg, 512, L"GRANT_REG: [W] %s -> %s", key.c_str(), ok ? L"OK" : L"FAILED");
                g_logger.Log(msg);
                if (!ok) {
                    fprintf(stderr, "[Warning] Could not grant registry write: %ls\n", key.c_str());
                    grantFailed = true;
                }
            }
        }

        if (grantFailed)
            fprintf(stderr, "          Run as Administrator to modify ACLs.\n");

        // --- Enable loopback (localhost) if requested (AppContainer only) ---
        if (config.allowLocalhost && !isRestricted) {
            bool ok = EnableLoopback();
            if (!ok) {
                fprintf(stderr, "[Warning] Could not enable localhost access.\n");
                fprintf(stderr, "          Loopback exemption requires Administrator.\n");
            }
            g_logger.Log(ok ? L"LOOPBACK: enabled" : L"LOOPBACK: FAILED");
        }

        // --- Print config summary ---
        if (!config.quiet) {
        fprintf(stderr, "Sandy - %s Sandbox\n", isRestricted ? "Restricted Token" : "AppContainer");
        fprintf(stderr, "Executable: %ls\n", exePath.c_str());
        if (!exeArgs.empty())
            fprintf(stderr, "Arguments:  %ls\n", exeArgs.c_str());
        fprintf(stderr, "Folders:    %zu configured\n", config.folders.size());
        for (const auto& e : config.folders) {
            fprintf(stderr, "  [%ls] %ls\n", AccessTag(e.access), e.path.c_str());
        }
        if (isRestricted && (!config.registryRead.empty() || !config.registryWrite.empty())) {
            fprintf(stderr, "Registry:   %zu keys\n", config.registryRead.size() + config.registryWrite.size());
            for (const auto& k : config.registryRead)  fprintf(stderr, "  [R]  %ls\n", k.c_str());
            for (const auto& k : config.registryWrite) fprintf(stderr, "  [W]  %ls\n", k.c_str());
        }
        fprintf(stderr, "---\n");
        if (isRestricted)
            fprintf(stderr, "Named Pipes: %s\n", config.allowNamedPipes ? "ALLOWED" : "BLOCKED");
        if (!config.allowSystemDirs && !isRestricted)
            fprintf(stderr, "System:     STRICT (system folders blocked)\n");
        fprintf(stderr, "Network:    %s\n", isRestricted ? "unrestricted (no capability model)" :
                                            config.allowNetwork ? "INTERNET" :
                                            config.allowLan     ? "LAN ONLY" : "BLOCKED");
        if (config.allowLocalhost && !isRestricted)
            fprintf(stderr, "Localhost:  ALLOWED\n");
        if (!config.allowStdin)
            fprintf(stderr, "Stdin:      BLOCKED\n");
        if (!config.allowClipboardRead || !config.allowClipboardWrite)
            fprintf(stderr, "Clipboard:  read=%s write=%s\n",
                    config.allowClipboardRead ? "ALLOWED" : "BLOCKED",
                    config.allowClipboardWrite ? "ALLOWED" : "BLOCKED");
        if (!config.allowChildProcesses)
            fprintf(stderr, "Children:   BLOCKED\n");
        if (!config.envInherit)
            fprintf(stderr, "Env:        filtered (%zu pass vars)\n", config.envPass.size());
        if (config.timeoutSeconds > 0)
            fprintf(stderr, "Timeout:    %lu seconds\n", config.timeoutSeconds);
        if (config.memoryLimitMB > 0)
            fprintf(stderr, "Memory:     %zu MB\n", config.memoryLimitMB);
        if (config.maxProcesses > 0)
            fprintf(stderr, "Processes:  %lu max\n", config.maxProcesses);
        }

        // --- Prepare capabilities (AppContainer only) ---
        SID_AND_ATTRIBUTES caps[2] = {};
        DWORD capCount = 0;
        PSID pNetSid = nullptr;
        PSID pLanSid = nullptr;

        if (!isRestricted && config.allowNetwork) {
            SID_IDENTIFIER_AUTHORITY appAuthority = SECURITY_APP_PACKAGE_AUTHORITY;
            if (AllocateAndInitializeSid(&appAuthority,
                SECURITY_BUILTIN_APP_PACKAGE_RID_COUNT,
                SECURITY_CAPABILITY_BASE_RID,
                SECURITY_CAPABILITY_INTERNET_CLIENT,
                0, 0, 0, 0, 0, 0, &pNetSid))
            {
                caps[capCount].Sid = pNetSid;
                caps[capCount].Attributes = SE_GROUP_ENABLED;
                capCount++;
                LPWSTR capSidStr = nullptr;
                if (ConvertSidToStringSidW(pNetSid, &capSidStr)) {
                    std::wstring capMsg = std::wstring(L"CAPABILITY: INTERNET_CLIENT SID=") + capSidStr;
                    g_logger.Log(capMsg.c_str());
                    LocalFree(capSidStr);
                } else {
                    g_logger.Log(L"CAPABILITY: INTERNET_CLIENT");
                }
            }
        }

        if (!isRestricted && config.allowLan) {
            SID_IDENTIFIER_AUTHORITY appAuthority = SECURITY_APP_PACKAGE_AUTHORITY;
            if (AllocateAndInitializeSid(&appAuthority,
                SECURITY_BUILTIN_APP_PACKAGE_RID_COUNT,
                SECURITY_CAPABILITY_BASE_RID,
                SECURITY_CAPABILITY_PRIVATE_NETWORK_CLIENT_SERVER,
                0, 0, 0, 0, 0, 0, &pLanSid))
            {
                caps[capCount].Sid = pLanSid;
                caps[capCount].Attributes = SE_GROUP_ENABLED;
                capCount++;
                LPWSTR capSidStr = nullptr;
                if (ConvertSidToStringSidW(pLanSid, &capSidStr)) {
                    std::wstring capMsg = std::wstring(L"CAPABILITY: PRIVATE_NETWORK SID=") + capSidStr;
                    g_logger.Log(capMsg.c_str());
                    LocalFree(capSidStr);
                } else {
                    g_logger.Log(L"CAPABILITY: PRIVATE_NETWORK");
                }
            }
        }

        // --- Cleanup helper ---
        auto cleanup = [&]() {
            if (pContainerSid) FreeSid(pContainerSid);
            if (hRestrictedToken) CloseHandle(hRestrictedToken);
            if (pGrantSid && pGrantSid != pContainerSid) FreeSid(pGrantSid);
            if (pNetSid) FreeSid(pNetSid);
            if (pLanSid) FreeSid(pLanSid);
        };

        // --- Build STARTUPINFOEX ---
        SECURITY_CAPABILITIES sc{};
        DWORD attrCount = 0;
        bool strictIsolation = false;
        DWORD allAppPackagesPolicy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
        DWORD childProcessPolicy = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
        bool needChildAttr = !config.allowChildProcesses;

        if (!isRestricted) {
            sc.AppContainerSid = pContainerSid;
            sc.Capabilities = capCount > 0 ? caps : nullptr;
            sc.CapabilityCount = capCount;
            strictIsolation = !config.allowSystemDirs;
            attrCount = 1;  // SECURITY_CAPABILITIES
            if (strictIsolation) attrCount++;
            if (needChildAttr) attrCount++;
        } else {
            // Restricted mode only needs attributes if child process is blocked
            if (needChildAttr) attrCount = 1;
        }

        SIZE_T attrSize = 0;
        LPPROC_THREAD_ATTRIBUTE_LIST pAttrList = nullptr;
        std::vector<BYTE> attrBuf;

        if (attrCount > 0) {
            InitializeProcThreadAttributeList(nullptr, attrCount, 0, &attrSize);
            attrBuf.resize(attrSize);
            pAttrList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrBuf.data());
            if (!InitializeProcThreadAttributeList(pAttrList, attrCount, 0, &attrSize)) {
                fprintf(stderr, "[Error] InitializeProcThreadAttributeList failed.\n");
                cleanup();
                return 1;
            }

            if (!isRestricted) {
                if (!UpdateProcThreadAttribute(pAttrList, 0,
                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                    &sc, sizeof(sc), nullptr, nullptr))
                {
                    fprintf(stderr, "[Error] UpdateProcThreadAttribute (security) failed.\n");
                    DeleteProcThreadAttributeList(pAttrList);
                    cleanup();
                    return 1;
                }

                if (strictIsolation) {
                    if (!UpdateProcThreadAttribute(pAttrList, 0,
                        PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                        &allAppPackagesPolicy, sizeof(allAppPackagesPolicy), nullptr, nullptr))
                    {
                        fprintf(stderr, "[Error] UpdateProcThreadAttribute (isolation policy) failed.\n");
                        DeleteProcThreadAttributeList(pAttrList);
                        cleanup();
                        return 1;
                    }
                    g_logger.Log(L"ISOLATION: strict (ALL_APPLICATION_PACKAGES opt-out)");
                }
            }

            if (needChildAttr) {
                if (!UpdateProcThreadAttribute(pAttrList, 0,
                    PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
                    &childProcessPolicy, sizeof(childProcessPolicy), nullptr, nullptr))
                {
                    fprintf(stderr, "[Error] UpdateProcThreadAttribute (child process) failed.\n");
                    DeleteProcThreadAttributeList(pAttrList);
                    cleanup();
                    return 1;
                }
                g_logger.Log(L"CHILD_PROCESS: restricted (kernel-enforced)");
            }
        }

        // --- Forensic: log allow flags ---
        if (!config.allowStdin)    g_logger.Log(L"STDIN: blocked (NUL)");
        else                       g_logger.Log(L"STDIN: inherited");

        // --- Build environment block ---
        std::vector<wchar_t> envBlock = BuildEnvironmentBlock(config);
        {
            wchar_t msg[256];
            if (config.envInherit)
                swprintf(msg, 256, L"ENV: inherit all");
            else
                swprintf(msg, 256, L"ENV: filtered (pass=%zu vars)", config.envPass.size());
            g_logger.Log(msg);

            if (!config.envInherit) {
                g_logger.Log(L"ENV_ESSENTIAL: SYSTEMROOT SYSTEMDRIVE WINDIR TEMP TMP COMSPEC PATHEXT LOCALAPPDATA APPDATA USERPROFILE HOMEDRIVE HOMEPATH PROCESSOR_ARCHITECTURE NUMBER_OF_PROCESSORS OS");
                if (!config.envPass.empty()) {
                    std::wstring passVars = L"ENV_PASS:";
                    for (auto& v : config.envPass) passVars += L" " + v;
                    g_logger.Log(passVars.c_str());
                }
            }
        }

        // --- Create pipes for child stdout/stderr ---
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = TRUE;

        HANDLE hReadPipe = nullptr, hWritePipe = nullptr;
        if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
            fprintf(stderr, "[Error] Could not create output pipe.\n");
            if (pAttrList) DeleteProcThreadAttributeList(pAttrList);
            cleanup();
            return 1;
        }
        SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

        {
            wchar_t msg[256];
            swprintf(msg, 256, L"PIPE: stdout/stderr read=0x%p write=0x%p",
                     (void*)hReadPipe, (void*)hWritePipe);
            g_logger.Log(msg);
        }

        // --- Stdin handle ---
        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
        HANDLE hNulIn = nullptr;
        if (!config.allowStdin) {
            hNulIn = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ,
                                &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            hStdin = hNulIn;
        }

        STARTUPINFOEXW siex{};
        siex.StartupInfo.cb = sizeof(siex);
        siex.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        siex.StartupInfo.hStdOutput = hWritePipe;
        siex.StartupInfo.hStdError  = hWritePipe;
        siex.StartupInfo.hStdInput  = hStdin;
        if (pAttrList) siex.lpAttributeList = pAttrList;

        // --- Build command line ---
        std::wstring cmdLine = L"\"" + exePath + L"\"";
        if (!exeArgs.empty())
            cmdLine += L" " + exeArgs;

        // --- Launch the target executable ---
        PROCESS_INFORMATION pi{};
        BOOL created;
        DWORD createFlags = CREATE_UNICODE_ENVIRONMENT;
        if (pAttrList) createFlags |= EXTENDED_STARTUPINFO_PRESENT;

        if (isRestricted) {
            // Restricted token: use CreateProcessAsUser
            // Works for restricted tokens derived from the caller's own token.
            // Requires SE_INCREASE_QUOTA_NAME (available to admins).
            created = CreateProcessAsUser(
                hRestrictedToken, nullptr, &cmdLine[0], nullptr, nullptr, TRUE,
                createFlags,
                envBlock.empty() ? nullptr : envBlock.data(),
                exeFolder.c_str(),
                pAttrList ? reinterpret_cast<LPSTARTUPINFOW>(&siex) : &siex.StartupInfo,
                &pi);
        } else {
            // AppContainer: use CreateProcessW with EXTENDED_STARTUPINFO_PRESENT
            created = CreateProcessW(
                nullptr, &cmdLine[0], nullptr, nullptr, TRUE,
                createFlags,
                envBlock.empty() ? nullptr : envBlock.data(),
                exeFolder.c_str(), &siex.StartupInfo, &pi);
        }

        // Close write end in parent so ReadFile gets EOF when child exits
        CloseHandle(hWritePipe);
        if (pAttrList) DeleteProcThreadAttributeList(pAttrList);
        if (hNulIn) CloseHandle(hNulIn);

        if (!created) {
            DWORD err = GetLastError();
            fprintf(stderr, "[Error] Could not launch: %ls (error %lu)\n", exePath.c_str(), err);
            // Enhanced failure diagnostics for post-mortem
            wchar_t msg[1024];
            swprintf(msg, 1024, L"LAUNCH_FAILED: %s (error %lu)", exePath.c_str(), err);
            g_logger.Log(msg);
            swprintf(msg, 1024, L"LAUNCH_DIAG: cmdline=%zu chars, envBlock=%zu wchars (%s)",
                     cmdLine.size(), envBlock.size(),
                     envBlock.empty() ? L"inherited" : L"custom");
            g_logger.Log(msg);
            swprintf(msg, 1024, L"LAUNCH_DIAG: workdir=%s", exeFolder.c_str());
            g_logger.Log(msg);
            g_logger.LogSummary(err, false, 0);
            g_logger.Stop();
            CloseHandle(hReadPipe);
            cleanup();
            return 1;
        }

        // Forensic: log launch
        g_logger.LogConfig(config, exePath, exeArgs);
        {
            wchar_t pidMsg[256];
            swprintf(pidMsg, 256, L"LAUNCH: PID %lu, cmd=\"%s\"", pi.dwProcessId, cmdLine.c_str());
            g_logger.Log(pidMsg);
        }

        CloseHandle(pi.hThread);

        // --- Assign to Job Object for resource limits and UI restrictions ---
        HANDLE hJob = nullptr;
        bool needJob = (config.memoryLimitMB > 0 || config.maxProcesses > 0 ||
                        !config.allowClipboardRead || !config.allowClipboardWrite);
        if (needJob) {
            hJob = CreateJobObjectW(nullptr, nullptr);
            if (hJob) {
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli{};
                if (config.memoryLimitMB > 0) {
                    jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
                    jeli.JobMemoryLimit = config.memoryLimitMB * 1024 * 1024;
                }
                if (config.maxProcesses > 0) {
                    jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
                    jeli.BasicLimitInformation.ActiveProcessLimit = config.maxProcesses;
                }
                SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));

                // UI restrictions (clipboard blocking)
                DWORD uiFlags = 0;
                if (!config.allowClipboardRead)  uiFlags |= JOB_OBJECT_UILIMIT_READCLIPBOARD;
                if (!config.allowClipboardWrite) uiFlags |= JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
                if (uiFlags) {
                    JOBOBJECT_BASIC_UI_RESTRICTIONS uiRestrict{};
                    uiRestrict.UIRestrictionsClass = uiFlags;
                    SetInformationJobObject(hJob, JobObjectBasicUIRestrictions, &uiRestrict, sizeof(uiRestrict));
                    g_logger.Log(L"CLIPBOARD: restricted via job UI limits");
                }

                AssignProcessToJobObject(hJob, pi.hProcess);

                wchar_t msg[256];
                swprintf(msg, 256, L"JOB: memory=%zuMB, processes=%lu, ui_flags=0x%X",
                         config.memoryLimitMB, config.maxProcesses, uiFlags);
                g_logger.Log(msg);
            }
        }

        // --- Start timeout watchdog thread ---
        TimeoutContext timeoutCtx = { pi.hProcess, config.timeoutSeconds, false };
        HANDLE hTimeoutThread = nullptr;
        if (config.timeoutSeconds > 0) {
            hTimeoutThread = CreateThread(nullptr, 0, TimeoutThread, &timeoutCtx, 0, nullptr);
            wchar_t msg[128];
            swprintf(msg, 128, L"TIMEOUT: armed %lus", config.timeoutSeconds);
            g_logger.Log(msg);
        }

        // --- Read child output and relay to our stdout ---
        char buffer[4096];
        DWORD bytesRead = 0;
        HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);

        while (ReadFile(hReadPipe, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0) {
            DWORD written = 0;
            WriteFile(hStdout, buffer, bytesRead, &written, nullptr);
            g_logger.LogOutput(buffer, bytesRead);
        }
        CloseHandle(hReadPipe);

        // --- Wait for child and get exit code ---
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);

        // --- Handle timeout thread ---
        if (hTimeoutThread) {
            WaitForSingleObject(hTimeoutThread, INFINITE);
            CloseHandle(hTimeoutThread);
            if (timeoutCtx.timedOut)
                fprintf(stderr, "[Sandy] Process killed after %lu second timeout.\n", config.timeoutSeconds);
        }

        // --- Write log summary and stop logger ---
        g_logger.LogSummary(exitCode, timeoutCtx.timedOut, config.timeoutSeconds);
        g_logger.Stop();

        // --- Cleanup ---
        CloseHandle(pi.hProcess);
        if (hJob) CloseHandle(hJob);

        cleanup();
        return static_cast<int>(exitCode);
    }

    // -----------------------------------------------------------------------
    // Delete the AppContainer profile and clean up loopback exemption
    // -----------------------------------------------------------------------
    inline void CleanupSandbox()
    {
        DisableLoopback();
        DeleteAppContainerProfile(kContainerName);
    }

} // namespace Sandbox
