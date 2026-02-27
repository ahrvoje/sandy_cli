#pragma once
// Sandbox.h — AppContainer sandbox with TOML-based configuration.
// All sandbox settings (folder access, permissions, resource limits) are
// defined in a single TOML config file. The CLI only needs -c and -x.

#include "framework.h"

namespace Sandbox {

    // Container identity — used for both creation and cleanup
    constexpr const wchar_t* kContainerName = L"SandySandbox";

    // -----------------------------------------------------------------------
    // Folder access level
    // -----------------------------------------------------------------------
    enum class AccessLevel { Read, Write, ReadWrite };

    struct FolderEntry {
        std::wstring path;
        AccessLevel  access;
    };

    // -----------------------------------------------------------------------
    // Full sandbox configuration (parsed from TOML)
    // -----------------------------------------------------------------------
    struct SandboxConfig {
        std::vector<FolderEntry> folders;

        // [allow] — opt-in permissions (default: all blocked)
        bool allowNetwork    = false;
        bool allowLocalhost  = false;
        bool allowLan        = false;
        bool allowSystemDirs = false;

        // [limit] — resource constraints (0 = unlimited)
        DWORD  timeoutSeconds = 0;
        SIZE_T memoryLimitMB  = 0;
        DWORD  maxProcesses   = 0;

        // Logging (set via -l CLI flag, not TOML)
        std::wstring logPath;

        // Quiet mode (set via -q CLI flag, not TOML)
        bool quiet = false;
    };

    // -----------------------------------------------------------------------
    // Sandy Logger — Process output and sandbox event log
    // Logs sandbox configuration, child process output, limit events,
    // and exit code to a file specified by -l <path>.
    // Child output already contains access denied messages from Python etc.
    // -----------------------------------------------------------------------
    struct SandyLogger {
        std::wstring logFilePath;
        bool active = false;

        // ISO 8601 timestamp with millisecond precision (UTC)
        static std::wstring Timestamp() {
            SYSTEMTIME st;
            GetSystemTime(&st);
            wchar_t buf[32];
            swprintf(buf, 32, L"%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                     st.wYear, st.wMonth, st.wDay,
                     st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
            return buf;
        }

        bool Start(const std::wstring& logPath) {
            // Truncate/create the file and write header
            FILE* f = nullptr;
            _wfopen_s(&f, logPath.c_str(), L"w");
            if (!f) {
                fprintf(stderr, "[Warning] Could not create log file: %ls\n", logPath.c_str());
                return false;
            }
            fwprintf(f, L"[%s] === Sandy Log ===\n", Timestamp().c_str());
            fclose(f);
            logFilePath = logPath;
            active = true;
            return true;
        }

        void LogConfig(const SandboxConfig& config, const std::wstring& exe,
                       const std::wstring& args) {
            if (!active) return;
            FILE* f = nullptr;
            _wfopen_s(&f, logFilePath.c_str(), L"a");
            if (!f) return;
            auto ts = Timestamp();
            fwprintf(f, L"[%s] --- Configuration ---\n", ts.c_str());
            fwprintf(f, L"[%s] Executable: %s\n", ts.c_str(), exe.c_str());
            if (!args.empty())
                fwprintf(f, L"[%s] Arguments:  %s\n", ts.c_str(), args.c_str());

            fwprintf(f, L"[%s] Folders:    %zu configured\n", ts.c_str(), config.folders.size());
            for (auto& entry : config.folders) {
                const wchar_t* tag = entry.access == AccessLevel::Read ? L"R" :
                                     entry.access == AccessLevel::Write ? L"W" : L"RW";
                fwprintf(f, L"[%s]   [%s]  %s\n", ts.c_str(), tag, entry.path.c_str());
            }

            if (config.allowSystemDirs) fwprintf(f, L"[%s] System dirs: allowed\n", ts.c_str());
            if (config.allowNetwork)    fwprintf(f, L"[%s] Network:     allowed\n", ts.c_str());
            if (config.allowLocalhost)  fwprintf(f, L"[%s] Localhost:   allowed\n", ts.c_str());
            if (config.allowLan)        fwprintf(f, L"[%s] LAN:         allowed\n", ts.c_str());
            if (config.timeoutSeconds)  fwprintf(f, L"[%s] Timeout:     %lu seconds\n", ts.c_str(), config.timeoutSeconds);
            if (config.memoryLimitMB)   fwprintf(f, L"[%s] Memory:      %zu MB\n", ts.c_str(), config.memoryLimitMB);
            if (config.maxProcesses)    fwprintf(f, L"[%s] Processes:   %lu max\n", ts.c_str(), config.maxProcesses);

            fwprintf(f, L"[%s] --- Process Output ---\n", ts.c_str());
            fclose(f);
        }

        void LogOutput(const char* data, DWORD len) {
            if (!active || !data || len == 0) return;
            FILE* f = nullptr;
            _wfopen_s(&f, logFilePath.c_str(), L"ab");
            if (!f) return;
            fwrite(data, 1, len, f);
            fclose(f);
        }

        void Log(const wchar_t* msg) {
            if (!active) return;
            FILE* f = nullptr;
            _wfopen_s(&f, logFilePath.c_str(), L"a");
            if (!f) return;
            fwprintf(f, L"[%s] %s\n", Timestamp().c_str(), msg);
            fclose(f);
        }

        void LogSummary(DWORD exitCode, bool timedOut, DWORD timeoutSec) {
            if (!active) return;
            FILE* f = nullptr;
            _wfopen_s(&f, logFilePath.c_str(), L"a");
            if (!f) return;
            auto ts = Timestamp();
            fwprintf(f, L"[%s] --- Process Exit ---\n", ts.c_str());
            if (timedOut)
                fwprintf(f, L"[%s] TIMEOUT: killed after %lu seconds\n", ts.c_str(), timeoutSec);
            fwprintf(f, L"[%s] Exit code: %ld (0x%08X)\n", ts.c_str(), (long)exitCode, exitCode);
            fwprintf(f, L"[%s] === Log end ===\n", ts.c_str());
            fclose(f);
        }

        void Stop() { active = false; }
        ~SandyLogger() { Stop(); }
    };

    static SandyLogger g_logger;

    // Track loopback state for cleanup
    static bool g_loopbackGranted = false;

    // -----------------------------------------------------------------------
    // Check if the current process is already running inside an AppContainer
    // -----------------------------------------------------------------------
    inline bool IsRunningInAppContainer()
    {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
            return false;

        DWORD isAppContainer = 0;
        DWORD size = sizeof(isAppContainer);
        BOOL ok = GetTokenInformation(hToken, TokenIsAppContainer, &isAppContainer, size, &size);
        CloseHandle(hToken);

        return ok && isAppContainer != 0;
    }

    // -----------------------------------------------------------------------
    // Get the folder that contains the running exe
    // -----------------------------------------------------------------------
    inline std::wstring GetExeFolder()
    {
        wchar_t buf[MAX_PATH]{};
        DWORD len = GetModuleFileNameW(nullptr, buf, MAX_PATH);
        if (len == 0 || len >= MAX_PATH) {
            fprintf(stderr, "[Error] Could not determine exe path.\n");
            return {};
        }
        std::wstring folder(buf, len);
        auto pos = folder.find_last_of(L"\\/");
        if (pos != std::wstring::npos)
            folder.resize(pos);
        return folder;
    }

    // -----------------------------------------------------------------------
    // Parse TOML configuration string
    //
    //   [access]  read / write / readwrite arrays for folder/file access
    //   [allow]   opt-in permissions
    //   [limit]   resource constraints
    // -----------------------------------------------------------------------
    inline SandboxConfig ParseConfig(const std::wstring& content)
    {
        SandboxConfig config;
        enum class Section { None, Folders, Allow, Limit };
        Section currentSection = Section::None;

        std::wstringstream ss(content);
        std::wstring line;

        while (std::getline(ss, line)) {
            // Trim \r
            if (!line.empty() && line.back() == L'\r')
                line.pop_back();
            // Trim whitespace
            size_t start = line.find_first_not_of(L" \t");
            if (start == std::wstring::npos)
                continue;
            line = line.substr(start);
            size_t end = line.find_last_not_of(L" \t");
            if (end != std::wstring::npos)
                line.resize(end + 1);

            if (line.empty() || line[0] == L'#')
                continue;

            // Strip inline comments (outside of quotes)
            if (line.front() != L'"' && line.front() != L'\'') {
                auto commentPos = line.find(L'#');
                if (commentPos != std::wstring::npos) {
                    line = line.substr(0, commentPos);
                    end = line.find_last_not_of(L" \t");
                    if (end != std::wstring::npos) line.resize(end + 1);
                    else continue;
                }
            }

            // Section headers
            if (line == L"[access]")    { currentSection = Section::Folders;   continue; }
            if (line == L"[allow]")     { currentSection = Section::Allow;     continue; }
            if (line == L"[limit]")     { currentSection = Section::Limit;     continue; }

            // [access] — key = [ 'path', ... ] arrays
            if (currentSection == Section::Folders) {
                // Detect which access level from key prefix
                AccessLevel level = AccessLevel::ReadWrite;
                if (line.find(L"readwrite") == 0) level = AccessLevel::ReadWrite;
                else if (line.find(L"read") == 0)  level = AccessLevel::Read;
                else if (line.find(L"write") == 0) level = AccessLevel::Write;

                // Extract all quoted paths from this and continuation lines
                // Handles both 'literal' and "basic" TOML strings
                auto extractPaths = [&](const std::wstring& text) {
                    size_t pos = 0;
                    while (pos < text.size()) {
                        // Find single or double quote
                        auto sq = text.find(L'\'', pos);
                        auto dq = text.find(L'"', pos);
                        if (sq == std::wstring::npos && dq == std::wstring::npos) break;

                        bool isSingle = (sq != std::wstring::npos && (dq == std::wstring::npos || sq < dq));
                        wchar_t quote = isSingle ? L'\'' : L'"';
                        size_t qstart = isSingle ? sq : dq;
                        auto qend = text.find(quote, qstart + 1);
                        if (qend == std::wstring::npos) break;

                        std::wstring path = text.substr(qstart + 1, qend - qstart - 1);
                        if (!path.empty())
                            config.folders.push_back({ path, level });
                        pos = qend + 1;
                    }
                };

                extractPaths(line);

                // If line contains '[' but no ']', read continuation lines
                if (line.find(L'[') != std::wstring::npos && line.find(L']') == std::wstring::npos) {
                    std::wstring contLine;
                    while (std::getline(ss, contLine)) {
                        if (!contLine.empty() && contLine.back() == L'\r') contLine.pop_back();
                        auto cs = contLine.find_first_not_of(L" \t");
                        if (cs == std::wstring::npos) continue;
                        contLine = contLine.substr(cs);
                        if (contLine[0] == L'#') continue;
                        extractPaths(contLine);
                        if (contLine.find(L']') != std::wstring::npos) break;
                    }
                }
                continue;
            }

            // [allow] — key = true/false entries
            if (currentSection == Section::Allow) {
                auto eq = line.find(L'=');
                if (eq != std::wstring::npos) {
                    std::wstring key = line.substr(0, eq);
                    std::wstring val = line.substr(eq + 1);
                    auto kt = key.find_last_not_of(L" \t");
                    if (kt != std::wstring::npos) key.resize(kt + 1);
                    auto vs = val.find_first_not_of(L" \t");
                    if (vs != std::wstring::npos) val = val.substr(vs);
                    bool enabled = (val == L"true");

                    if (key == L"network")          config.allowNetwork = enabled;
                    else if (key == L"localhost")    config.allowLocalhost = enabled;
                    else if (key == L"lan")          config.allowLan = enabled;
                    else if (key == L"system_dirs")  config.allowSystemDirs = enabled;
                }
                continue;
            }

            // [limit] — key = value entries
            if (currentSection == Section::Limit) {
                auto eq = line.find(L'=');
                if (eq != std::wstring::npos) {
                    std::wstring key = line.substr(0, eq);
                    std::wstring val = line.substr(eq + 1);
                    auto kt = key.find_last_not_of(L" \t");
                    if (kt != std::wstring::npos) key.resize(kt + 1);
                    auto vs = val.find_first_not_of(L" \t");
                    if (vs != std::wstring::npos) val = val.substr(vs);

                    if (key == L"timeout")        config.timeoutSeconds = static_cast<DWORD>(_wtoi(val.c_str()));
                    else if (key == L"memory")    config.memoryLimitMB = static_cast<SIZE_T>(_wtoi(val.c_str()));
                    else if (key == L"processes") config.maxProcesses = static_cast<DWORD>(_wtoi(val.c_str()));
                }
                continue;
            }
        }

        return config;
    }

    // -----------------------------------------------------------------------
    // Load config from a TOML file (reads file, then delegates to ParseConfig)
    // -----------------------------------------------------------------------
    inline SandboxConfig LoadConfig(const std::wstring& configPath)
    {
        HANDLE hFile = CreateFileW(configPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE)
            return SandboxConfig{};

        DWORD fileSize = GetFileSize(hFile, nullptr);
        if (fileSize == 0 || fileSize == INVALID_FILE_SIZE) {
            CloseHandle(hFile);
            return SandboxConfig{};
        }

        std::string buf(fileSize, '\0');
        DWORD bytesRead = 0;
        if (!ReadFile(hFile, &buf[0], fileSize, &bytesRead, nullptr) || bytesRead == 0) {
            CloseHandle(hFile);
            return SandboxConfig{};
        }
        CloseHandle(hFile);

        int wideLen = MultiByteToWideChar(CP_UTF8, 0, buf.c_str(), static_cast<int>(bytesRead), nullptr, 0);
        std::wstring content(wideLen, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, buf.c_str(), static_cast<int>(bytesRead), &content[0], wideLen);

        return ParseConfig(content);
    }

    // -----------------------------------------------------------------------
    // Grant folder access with specific permissions
    // -----------------------------------------------------------------------
    inline bool GrantFolderAccess(PSID pSid, const std::wstring& folder, AccessLevel level)
    {
        DWORD permissions = 0;
        switch (level) {
        case AccessLevel::Read:
            permissions = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
            break;
        case AccessLevel::Write:
            permissions = FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
            break;
        case AccessLevel::ReadWrite:
            permissions = FILE_ALL_ACCESS;
            break;
        }

        EXPLICIT_ACCESSW ea{};
        ea.grfAccessPermissions = permissions;
        ea.grfAccessMode = SET_ACCESS;
        ea.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(pSid);

        PACL pOldDacl = nullptr;
        PSECURITY_DESCRIPTOR pSD = nullptr;
        DWORD rc = GetNamedSecurityInfoW(
            folder.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, &pOldDacl, nullptr, &pSD);
        if (rc != ERROR_SUCCESS)
            return false;

        PACL pNewDacl = nullptr;
        rc = SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl);
        LocalFree(pSD);
        if (rc != ERROR_SUCCESS)
            return false;

        rc = SetNamedSecurityInfoW(
            const_cast<LPWSTR>(folder.c_str()), SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION, nullptr, nullptr, pNewDacl, nullptr);
        LocalFree(pNewDacl);
        return rc == ERROR_SUCCESS;
    }

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
    // Launch an executable inside an AppContainer sandbox.
    // All behavior is controlled by the SandboxConfig.
    // -----------------------------------------------------------------------
    inline int RunSandboxed(const SandboxConfig& config,
                            const std::wstring& exePath,
                            const std::wstring& exeArgs)
    {
        // --- Create or open the AppContainer profile ---
        PSID pContainerSid = nullptr;
        HRESULT hr = CreateAppContainerProfile(
            kContainerName, L"Sandy Sandbox",
            L"Sandboxed environment for running executables",
            nullptr, 0, &pContainerSid);

        if (HRESULT_CODE(hr) == ERROR_ALREADY_EXISTS)
            hr = DeriveAppContainerSidFromAppContainerName(kContainerName, &pContainerSid);

        if (FAILED(hr) || !pContainerSid) {
            fprintf(stderr, "[Error] Could not create AppContainer (0x%08X).\n", hr);
            return 1;
        }

        // --- Determine working directory (folder containing sandy.exe) ---
        std::wstring exeFolder = GetExeFolder();
        if (exeFolder.empty()) {
            FreeSid(pContainerSid);
            return 1;
        }

        // --- Grant configured folder access ---
        bool grantFailed = false;
        for (const auto& entry : config.folders) {
            if (!GrantFolderAccess(pContainerSid, entry.path, entry.access)) {
                fprintf(stderr, "[Warning] Could not grant access to: %ls\n", entry.path.c_str());
                grantFailed = true;
            }
        }
        if (grantFailed)
            fprintf(stderr, "          Run as Administrator to modify folder ACLs.\n");

        // --- Enable loopback (localhost) if requested ---
        if (config.allowLocalhost) {
            if (!EnableLoopback()) {
                fprintf(stderr, "[Warning] Could not enable localhost access.\n");
                fprintf(stderr, "          Loopback exemption requires Administrator.\n");
            }
        }

        // --- Print config summary (to stderr, keeping stdout clean) ---
        if (!config.quiet) {
        fprintf(stderr, "Sandy - AppContainer Sandbox\n");
        fprintf(stderr, "Executable: %ls\n", exePath.c_str());
        if (!exeArgs.empty())
            fprintf(stderr, "Arguments:  %ls\n", exeArgs.c_str());
        fprintf(stderr, "Folders:    %zu configured\n", config.folders.size());
        for (const auto& e : config.folders) {
            const char* tag = "[RW]";
            if (e.access == AccessLevel::Read) tag = "[R] ";
            else if (e.access == AccessLevel::Write) tag = "[W] ";
            fprintf(stderr, "  %s %ls\n", tag, e.path.c_str());
        }
        fprintf(stderr, "---\n");
        if (!config.allowSystemDirs)
            fprintf(stderr, "System:     STRICT (system folders blocked)\n");
        fprintf(stderr, "Network:    %s\n", config.allowNetwork ? "INTERNET" :
                                            config.allowLan     ? "LAN ONLY" : "BLOCKED");
        if (config.allowLocalhost)
            fprintf(stderr, "Localhost:  ALLOWED\n");
        if (config.timeoutSeconds > 0)
            fprintf(stderr, "Timeout:    %lu seconds\n", config.timeoutSeconds);
        if (config.memoryLimitMB > 0)
            fprintf(stderr, "Memory:     %zu MB\n", config.memoryLimitMB);
        if (config.maxProcesses > 0)
            fprintf(stderr, "Processes:  %lu max\n", config.maxProcesses);
        }

        // --- Prepare capabilities ---
        SID_AND_ATTRIBUTES caps[2] = {};
        DWORD capCount = 0;
        PSID pNetSid = nullptr;
        PSID pLanSid = nullptr;

        if (config.allowNetwork) {
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
            }
        }

        if (config.allowLan) {
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
            }
        }

        // --- Helper: free all SIDs on exit ---
        auto cleanup = [&]() {
            FreeSid(pContainerSid);
            if (pNetSid) FreeSid(pNetSid);
            if (pLanSid) FreeSid(pLanSid);
        };

        SECURITY_CAPABILITIES sc{};
        sc.AppContainerSid = pContainerSid;
        sc.Capabilities = capCount > 0 ? caps : nullptr;
        sc.CapabilityCount = capCount;

        // --- Build STARTUPINFOEX with the container attribute ---
        bool strictIsolation = !config.allowSystemDirs;
        DWORD attrCount = strictIsolation ? 2 : 1;
        SIZE_T attrSize = 0;
        InitializeProcThreadAttributeList(nullptr, attrCount, 0, &attrSize);
        std::vector<BYTE> attrBuf(attrSize);
        auto pAttrList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrBuf.data());
        if (!InitializeProcThreadAttributeList(pAttrList, attrCount, 0, &attrSize)) {
            fprintf(stderr, "[Error] InitializeProcThreadAttributeList failed.\n");
            cleanup();
            return 1;
        }

        if (!UpdateProcThreadAttribute(pAttrList, 0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            &sc, sizeof(sc), nullptr, nullptr))
        {
            fprintf(stderr, "[Error] UpdateProcThreadAttribute (security) failed.\n");
            DeleteProcThreadAttributeList(pAttrList);
            cleanup();
            return 1;
        }

        // When strict: opt out of ALL_APPLICATION_PACKAGES to block system folder reads
        DWORD allAppPackagesPolicy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
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
        }

        // --- Create pipes for child stdout/stderr ---
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = TRUE;

        HANDLE hReadPipe = nullptr, hWritePipe = nullptr;
        if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
            fprintf(stderr, "[Error] Could not create output pipe.\n");
            DeleteProcThreadAttributeList(pAttrList);
            cleanup();
            return 1;
        }
        SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

        STARTUPINFOEXW siex{};
        siex.StartupInfo.cb = sizeof(siex);
        siex.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        siex.StartupInfo.hStdOutput = hWritePipe;
        siex.StartupInfo.hStdError  = hWritePipe;
        siex.StartupInfo.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
        siex.lpAttributeList = pAttrList;

        // --- Build command line ---
        std::wstring cmdLine = L"\"" + exePath + L"\"";
        if (!exeArgs.empty())
            cmdLine += L" " + exeArgs;

        // --- Start logger before launching ---
        if (!config.logPath.empty()) {
            g_logger.Start(config.logPath);
        }

        // --- Launch the target executable ---
        PROCESS_INFORMATION pi{};
        BOOL created = CreateProcessW(
            nullptr, &cmdLine[0], nullptr, nullptr, TRUE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            nullptr, exeFolder.c_str(), &siex.StartupInfo, &pi);

        // Close write end in parent so ReadFile gets EOF when child exits
        CloseHandle(hWritePipe);
        DeleteProcThreadAttributeList(pAttrList);

        if (!created) {
            DWORD err = GetLastError();
            fprintf(stderr, "[Error] Could not launch: %ls (error %lu)\n", exePath.c_str(), err);
            if (g_logger.active) {
                wchar_t msg[512];
                swprintf(msg, 512, L"LAUNCH_FAILED: %s (error %lu)", exePath.c_str(), err);
                g_logger.Log(msg);
                g_logger.LogSummary(err, false, 0);
                g_logger.Stop();
            }
            CloseHandle(hReadPipe);
            cleanup();
            return 1;
        }

        // Log configuration and PID
        if (g_logger.active) {
            g_logger.LogConfig(config, exePath, exeArgs);
            wchar_t pidMsg[128];
            swprintf(pidMsg, 128, L"PID: %lu", pi.dwProcessId);
            g_logger.Log(pidMsg);
        }

        CloseHandle(pi.hThread);

        // --- Assign to Job Object for resource limits ---
        HANDLE hJob = nullptr;
        if (config.memoryLimitMB > 0 || config.maxProcesses > 0) {
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
                AssignProcessToJobObject(hJob, pi.hProcess);
            }
        }

        // --- Start timeout watchdog thread ---
        TimeoutContext timeoutCtx = { pi.hProcess, config.timeoutSeconds, false };
        HANDLE hTimeoutThread = nullptr;
        if (config.timeoutSeconds > 0) {
            hTimeoutThread = CreateThread(nullptr, 0, TimeoutThread, &timeoutCtx, 0, nullptr);
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
        if (g_logger.active) {
            g_logger.LogSummary(exitCode, timeoutCtx.timedOut, config.timeoutSeconds);
            g_logger.Stop();
        }

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
