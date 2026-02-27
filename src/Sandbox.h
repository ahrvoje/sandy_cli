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
    enum class AccessLevel { Read, Write, Execute, Append, Delete, All };

    struct FolderEntry {
        std::wstring path;
        AccessLevel  access;
    };

    // Human-readable tag for an access level
    inline const wchar_t* AccessTag(AccessLevel level) {
        switch (level) {
        case AccessLevel::Read:    return L"R";
        case AccessLevel::Write:   return L"W";
        case AccessLevel::Execute: return L"X";
        case AccessLevel::Append:  return L"A";
        case AccessLevel::Delete:  return L"D";
        case AccessLevel::All:     return L"ALL";
        default:                   return L"?";
        }
    }

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

        bool allowStdin      = true;   // default: inherit stdin

        // [environment] — env block control
        bool envInherit = true;
        std::vector<std::wstring> envPass;

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
                fwprintf(f, L"[%s]   [%s]  %s\n", ts.c_str(), AccessTag(entry.access), entry.path.c_str());
            }

            if (config.allowSystemDirs) fwprintf(f, L"[%s] System dirs: allowed\n", ts.c_str());
            if (config.allowNetwork)    fwprintf(f, L"[%s] Network:     allowed\n", ts.c_str());
            if (config.allowLocalhost)  fwprintf(f, L"[%s] Localhost:   allowed\n", ts.c_str());
            if (config.allowLan)        fwprintf(f, L"[%s] LAN:         allowed\n", ts.c_str());

            if (!config.allowStdin)     fwprintf(f, L"[%s] Stdin:       blocked\n", ts.c_str());
            if (!config.envInherit)     fwprintf(f, L"[%s] Env:         filtered (%zu pass vars)\n", ts.c_str(), config.envPass.size());
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
    // Helper: parse 'key = value' from a TOML line
    // -----------------------------------------------------------------------
    struct KeyValue { std::wstring key, val; bool ok; };
    inline KeyValue ParseKeyValue(const std::wstring& line) {
        auto eq = line.find(L'=');
        if (eq == std::wstring::npos) return { {}, {}, false };
        std::wstring key = line.substr(0, eq);
        std::wstring val = line.substr(eq + 1);
        auto kt = key.find_last_not_of(L" \t");
        if (kt != std::wstring::npos) key.resize(kt + 1);
        auto vs = val.find_first_not_of(L" \t");
        if (vs != std::wstring::npos) val = val.substr(vs);
        return { key, val, true };
    }

    // -----------------------------------------------------------------------
    // Parse TOML configuration string
    //
    //   [access]      read / write / execute / append / delete / all
    //   [allow]       opt-in permissions
    //   [environment] env block control
    //   [limit]       resource constraints
    // -----------------------------------------------------------------------
    inline SandboxConfig ParseConfig(const std::wstring& content)
    {
        SandboxConfig config;
        enum class Section { None, Folders, Allow, Limit, Environment };
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

            // Strip inline comments — skip '#' inside quoted strings
            if (line.front() != L'"' && line.front() != L'\'') {
                bool inQuote = false;
                wchar_t quoteChar = 0;
                for (size_t ci = 0; ci < line.size(); ci++) {
                    if (!inQuote && (line[ci] == L'\'' || line[ci] == L'"')) {
                        inQuote = true;
                        quoteChar = line[ci];
                    } else if (inQuote && line[ci] == quoteChar) {
                        inQuote = false;
                    } else if (!inQuote && line[ci] == L'#') {
                        line = line.substr(0, ci);
                        end = line.find_last_not_of(L" \t");
                        if (end != std::wstring::npos) line.resize(end + 1);
                        else { line.clear(); break; }
                        break;
                    }
                }
                if (line.empty()) continue;
            }

            // Section headers
            if (line == L"[access]")      { currentSection = Section::Folders;     continue; }
            if (line == L"[allow]")       { currentSection = Section::Allow;       continue; }
            if (line == L"[limit]")       { currentSection = Section::Limit;       continue; }
            if (line == L"[environment]") { currentSection = Section::Environment; continue; }

            // [access] — key = [ 'path', ... ] arrays
            if (currentSection == Section::Folders) {
                // Detect which access level from key prefix
                AccessLevel level = AccessLevel::All;
                if (line.find(L"execute") == 0)  level = AccessLevel::Execute;
                else if (line.find(L"append") == 0)   level = AccessLevel::Append;
                else if (line.find(L"delete") == 0)   level = AccessLevel::Delete;
                else if (line.find(L"all") == 0)      level = AccessLevel::All;
                else if (line.find(L"read") == 0)     level = AccessLevel::Read;
                else if (line.find(L"write") == 0)    level = AccessLevel::Write;

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
                auto kv = ParseKeyValue(line);
                if (kv.ok) {
                    bool enabled = (kv.val == L"true");
                    if (kv.key == L"network")          config.allowNetwork = enabled;
                    else if (kv.key == L"localhost")    config.allowLocalhost = enabled;
                    else if (kv.key == L"lan")          config.allowLan = enabled;
                    else if (kv.key == L"system_dirs")  config.allowSystemDirs = enabled;
                    else if (kv.key == L"stdin")        config.allowStdin = enabled;
                }
                continue;
            }

            // [environment] — inherit and pass entries
            if (currentSection == Section::Environment) {
                auto kv = ParseKeyValue(line);
                if (kv.ok) {
                    if (kv.key == L"inherit") {
                        config.envInherit = (kv.val == L"true");
                    }
                    else if (kv.key == L"pass") {
                        // Extract quoted var names from array
                        size_t pos = 0;
                        while (pos < kv.val.size()) {
                            auto sq = kv.val.find(L'\'', pos);
                            auto dq = kv.val.find(L'"', pos);
                            if (sq == std::wstring::npos && dq == std::wstring::npos) break;
                            bool isSingle = (sq != std::wstring::npos && (dq == std::wstring::npos || sq < dq));
                            wchar_t quote = isSingle ? L'\'' : L'"';
                            size_t qstart = isSingle ? sq : dq;
                            auto qend = kv.val.find(quote, qstart + 1);
                            if (qend == std::wstring::npos) break;
                            std::wstring varName = kv.val.substr(qstart + 1, qend - qstart - 1);
                            if (!varName.empty())
                                config.envPass.push_back(varName);
                            pos = qend + 1;
                        }
                    }
                }
                continue;
            }

            // [limit] — key = value entries
            if (currentSection == Section::Limit) {
                auto kv = ParseKeyValue(line);
                if (kv.ok) {
                    int parsed = _wtoi(kv.val.c_str());
                    if (parsed <= 0 && kv.val != L"0") {
                        fprintf(stderr, "[Warning] Invalid limit value: %ls = %ls\n",
                                kv.key.c_str(), kv.val.c_str());
                    } else {
                        if (kv.key == L"timeout")        config.timeoutSeconds = static_cast<DWORD>(parsed);
                        else if (kv.key == L"memory")    config.memoryLimitMB = static_cast<SIZE_T>(parsed);
                        else if (kv.key == L"processes") config.maxProcesses = static_cast<DWORD>(parsed);
                    }
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
        case AccessLevel::Execute:
            permissions = FILE_GENERIC_EXECUTE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
            break;
        case AccessLevel::Append:
            permissions = FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
            break;
        case AccessLevel::Delete:
            permissions = DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
            break;
        case AccessLevel::All:
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

        // Log SDDL of the resulting DACL for forensic analysis
        if (rc == ERROR_SUCCESS) {
            PACL pResultDacl = nullptr;
            PSECURITY_DESCRIPTOR pResultSD = nullptr;
            if (GetNamedSecurityInfoW(folder.c_str(), SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION, nullptr, nullptr,
                    &pResultDacl, nullptr, &pResultSD) == ERROR_SUCCESS) {
                LPWSTR sddl = nullptr;
                if (ConvertSecurityDescriptorToStringSecurityDescriptorW(
                        pResultSD, SDDL_REVISION_1, DACL_SECURITY_INFORMATION,
                        &sddl, nullptr)) {
                    std::wstring logMsg = L"GRANT_SDDL: " + folder + L" -> " + sddl;
                    g_logger.Log(logMsg.c_str());
                    LocalFree(sddl);
                }
                LocalFree(pResultSD);
            }
        }

        return rc == ERROR_SUCCESS;
    }

    // -----------------------------------------------------------------------
    // Get the permission mask for an access level (for forensic logging)
    // -----------------------------------------------------------------------
    inline DWORD AccessMask(AccessLevel level) {
        switch (level) {
        case AccessLevel::Read:    return FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
        case AccessLevel::Write:   return FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        case AccessLevel::Execute: return FILE_GENERIC_EXECUTE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        case AccessLevel::Append:  return FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        case AccessLevel::Delete:  return DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        case AccessLevel::All:     return FILE_ALL_ACCESS;
        default:                   return 0;
        }
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

        bool containerCreated = true;
        if (HRESULT_CODE(hr) == ERROR_ALREADY_EXISTS) {
            hr = DeriveAppContainerSidFromAppContainerName(kContainerName, &pContainerSid);
            containerCreated = false;
        }

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

        // --- Start logger early for forensic logging ---
        if (!config.logPath.empty()) {
            g_logger.Start(config.logPath);
        }

        // --- Forensic: Sandy identity ---
        {
            wchar_t msg[512];
            swprintf(msg, 512, L"SANDY: PID %lu", GetCurrentProcessId());
            g_logger.Log(msg);

            // Determine integrity level
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

        // --- Forensic: container and working directory ---
        {
            wchar_t msg[512];
            swprintf(msg, 512, L"CONTAINER: %s", containerCreated ? L"created" : L"reused existing");
            g_logger.Log(msg);

            // Log container SID string for ETW correlation
            LPWSTR sidStr = nullptr;
            if (ConvertSidToStringSidW(pContainerSid, &sidStr)) {
                swprintf(msg, 512, L"CONTAINER_SID: %s", sidStr);
                g_logger.Log(msg);
                LocalFree(sidStr);
            }

            swprintf(msg, 512, L"WORKDIR: %s", exeFolder.c_str());
            g_logger.Log(msg);
        }

        // --- Grant configured folder access ---
        bool grantFailed = false;
        for (const auto& entry : config.folders) {
            bool ok = GrantFolderAccess(pContainerSid, entry.path, entry.access);
            if (!ok) {
                fprintf(stderr, "[Warning] Could not grant access to: %ls\n", entry.path.c_str());
                grantFailed = true;
            }
            // Forensic log each grant with permission mask
            wchar_t msg[512];
            swprintf(msg, 512, L"GRANT: [%s] %s -> %s (mask=0x%08X)",
                     AccessTag(entry.access), entry.path.c_str(),
                     ok ? L"OK" : L"FAILED", AccessMask(entry.access));
            g_logger.Log(msg);
        }
        if (grantFailed)
            fprintf(stderr, "          Run as Administrator to modify folder ACLs.\n");

        // --- Enable loopback (localhost) if requested ---
        if (config.allowLocalhost) {
            bool ok = EnableLoopback();
            if (!ok) {
                fprintf(stderr, "[Warning] Could not enable localhost access.\n");
                fprintf(stderr, "          Loopback exemption requires Administrator.\n");
            }
            g_logger.Log(ok ? L"LOOPBACK: enabled" : L"LOOPBACK: FAILED");
        }

        // --- Print config summary (to stderr, keeping stdout clean) ---
        if (!config.quiet) {
        fprintf(stderr, "Sandy - AppContainer Sandbox\n");
        fprintf(stderr, "Executable: %ls\n", exePath.c_str());
        if (!exeArgs.empty())
            fprintf(stderr, "Arguments:  %ls\n", exeArgs.c_str());
        fprintf(stderr, "Folders:    %zu configured\n", config.folders.size());
        for (const auto& e : config.folders) {
            fprintf(stderr, "  [%ls] %ls\n", AccessTag(e.access), e.path.c_str());
        }
        fprintf(stderr, "---\n");
        if (!config.allowSystemDirs)
            fprintf(stderr, "System:     STRICT (system folders blocked)\n");
        fprintf(stderr, "Network:    %s\n", config.allowNetwork ? "INTERNET" :
                                            config.allowLan     ? "LAN ONLY" : "BLOCKED");
        if (config.allowLocalhost)
            fprintf(stderr, "Localhost:  ALLOWED\n");
        if (!config.allowStdin)
            fprintf(stderr, "Stdin:      BLOCKED\n");
        if (!config.envInherit)
            fprintf(stderr, "Env:        filtered (%zu pass vars)\n", config.envPass.size());
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
                // Log capability SID for ETW correlation
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
            g_logger.Log(L"ISOLATION: strict (ALL_APPLICATION_PACKAGES opt-out)");
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

            // Log individual filtered env var names (not values) for forensic analysis
            if (!config.envInherit) {
                // Log essential vars that are always passed
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
            DeleteProcThreadAttributeList(pAttrList);
            cleanup();
            return 1;
        }
        SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

        // Log pipe handles for ETW I/O correlation
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
        siex.lpAttributeList = pAttrList;

        // --- Build command line ---
        std::wstring cmdLine = L"\"" + exePath + L"\"";
        if (!exeArgs.empty())
            cmdLine += L" " + exeArgs;


        // --- Launch the target executable ---
        PROCESS_INFORMATION pi{};
        BOOL created = CreateProcessW(
            nullptr, &cmdLine[0], nullptr, nullptr, TRUE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            envBlock.empty() ? nullptr : envBlock.data(),
            exeFolder.c_str(), &siex.StartupInfo, &pi);

        // Close write end in parent so ReadFile gets EOF when child exits
        CloseHandle(hWritePipe);
        DeleteProcThreadAttributeList(pAttrList);
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

                wchar_t msg[256];
                swprintf(msg, 256, L"JOB: memory=%zuMB, processes=%lu",
                         config.memoryLimitMB, config.maxProcesses);
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
