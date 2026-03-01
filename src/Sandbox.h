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
    // Sandbox token mode
    // -----------------------------------------------------------------------
    enum class TokenMode { AppContainer, Restricted };

    // -----------------------------------------------------------------------
    // Integrity level for restricted token
    // -----------------------------------------------------------------------
    enum class IntegrityLevel { Low, Medium };

    // -----------------------------------------------------------------------
    // Full sandbox configuration (parsed from TOML)
    // -----------------------------------------------------------------------
    struct SandboxConfig {
        TokenMode tokenMode = TokenMode::AppContainer;  // [sandbox] token
        IntegrityLevel integrity = IntegrityLevel::Low;   // [sandbox] integrity (restricted only)
        std::vector<FolderEntry> folders;

        // [allow] — opt-in permissions (default: all blocked)
        bool allowNetwork    = false;
        bool allowLocalhost  = false;
        bool allowLan        = false;
        bool allowSystemDirs = false;
        bool allowNamedPipes  = false;  // restricted mode: controls named pipe creation

        bool allowStdin      = true;   // default: inherit stdin

        // [registry] — registry key grants (restricted mode only)
        std::vector<std::wstring> registryRead;
        std::vector<std::wstring> registryWrite;

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

        // Parse error flag (set if unknown section/key encountered)
        bool parseError = false;
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

    // Helper: unescape TOML double-quoted string (\\, \n, \t, \r, \")
    inline std::wstring UnescapeTomlDQ(const std::wstring& s) {
        std::wstring out;
        out.reserve(s.size());
        for (size_t i = 0; i < s.size(); i++) {
            if (s[i] == L'\\' && i + 1 < s.size()) {
                switch (s[i + 1]) {
                    case L'\\': out += L'\\'; i++; break;
                    case L'n':  out += L'\n'; i++; break;
                    case L't':  out += L'\t'; i++; break;
                    case L'r':  out += L'\r'; i++; break;
                    case L'"':  out += L'"';  i++; break;
                    default:    out += s[i]; break;
                }
            } else {
                out += s[i];
            }
        }
        return out;
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
        // Strip surrounding quotes (TOML strings: "value" or 'value')
        if (val.size() >= 2 &&
            ((val.front() == L'"' && val.back() == L'"') ||
             (val.front() == L'\'' && val.back() == L'\'')))
        {
            bool isDQ = (val.front() == L'"');
            val = val.substr(1, val.size() - 2);
            // TOML double-quoted strings: process escape sequences
            if (isDQ) {
                val = UnescapeTomlDQ(val);
            }
        }
        else if (!val.empty() && (val.front() == L'"' || val.front() == L'\'')) {
            // Opening quote with no closing quote
            fprintf(stderr, "Error: Unterminated quote in value for key '%ls'\n", key.c_str());
        }
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
    inline SandboxConfig ParseConfig(const std::wstring& contentRaw)
    {
        // Convert literal \n sequences to real newlines (enables cmd.exe -s usage)
        std::wstring content;
        content.reserve(contentRaw.size());
        for (size_t i = 0; i < contentRaw.size(); i++) {
            if (contentRaw[i] == L'\\' && i + 1 < contentRaw.size() && contentRaw[i + 1] == L'n') {
                content += L'\n';
                i++;
            } else {
                content += contentRaw[i];
            }
        }

        SandboxConfig config;
        enum class Section { None, Sandbox, Folders, Registry, Allow, Limit, Environment };
        Section currentSection = Section::None;
        bool sandboxSeen = false;
        bool registrySeen = false;

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
            if (line == L"[sandbox]")     { currentSection = Section::Sandbox; sandboxSeen = true; continue; }
            if (line == L"[access]")      { currentSection = Section::Folders;     continue; }
            if (line == L"[registry]")    { currentSection = Section::Registry; registrySeen = true; continue; }
            if (line == L"[allow]")       { currentSection = Section::Allow;       continue; }
            if (line == L"[limit]")       { currentSection = Section::Limit;       continue; }
            if (line == L"[environment]") { currentSection = Section::Environment; continue; }

            // Unknown section header
            if (line.front() == L'[' && line.back() == L']') {
                fprintf(stderr, "Error: Unknown config section: %ls\n", line.c_str());
                config.parseError = true;
                continue;
            }

            // [sandbox] — token mode
            if (currentSection == Section::Sandbox) {
                auto kv = ParseKeyValue(line);
                if (kv.ok && kv.key == L"token") {
                    if (kv.val == L"restricted") config.tokenMode = TokenMode::Restricted;
                    else if (kv.val == L"appcontainer") config.tokenMode = TokenMode::AppContainer;
                    else {
                        fprintf(stderr, "Error: Unknown token mode: %ls\n", kv.val.c_str());
                        config.parseError = true;
                    }
                } else if (kv.ok && kv.key == L"integrity") {
                    if (kv.val == L"low") config.integrity = IntegrityLevel::Low;
                    else if (kv.val == L"medium") config.integrity = IntegrityLevel::Medium;
                    else {
                        fprintf(stderr, "Error: Unknown integrity level: %ls (expected 'low' or 'medium')\n", kv.val.c_str());
                        config.parseError = true;
                    }
                } else if (kv.ok) {
                    fprintf(stderr, "Error: Unknown key in [sandbox]: %ls\n", kv.key.c_str());
                    config.parseError = true;
                }
                continue;
            }

            // [access] — key = [ 'path', ... ] arrays
            if (currentSection == Section::Folders) {
                // Detect which access level from key prefix
                AccessLevel level = AccessLevel::All;
                bool knownKey = true;
                if (line.find(L"execute") == 0)        level = AccessLevel::Execute;
                else if (line.find(L"append") == 0)   level = AccessLevel::Append;
                else if (line.find(L"delete") == 0)   level = AccessLevel::Delete;
                else if (line.find(L"all") == 0)      level = AccessLevel::All;
                else if (line.find(L"read") == 0)     level = AccessLevel::Read;
                else if (line.find(L"write") == 0)    level = AccessLevel::Write;
                else {
                    auto ekv = ParseKeyValue(line);
                    fprintf(stderr, "Error: Unknown key in [access]: %ls\n",
                            ekv.ok ? ekv.key.c_str() : line.c_str());
                    config.parseError = true;
                    knownKey = false;
                }
                if (!knownKey) continue;

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
                        if (!isSingle) path = UnescapeTomlDQ(path);
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

            // [registry] — key = [ 'path', ... ] arrays (restricted mode only)
            if (currentSection == Section::Registry) {
                AccessLevel level = AccessLevel::Read;
                if (line.find(L"write") == 0) level = AccessLevel::Write;
                else if (line.find(L"read") != 0) {
                    auto ekv = ParseKeyValue(line);
                    fprintf(stderr, "Error: Unknown key in [registry]: %ls\n",
                            ekv.ok ? ekv.key.c_str() : line.c_str());
                    config.parseError = true;
                    continue;
                }
                auto extractRegPaths = [&](const std::wstring& text) {
                    size_t pos = 0;
                    while (pos < text.size()) {
                        auto sq = text.find(L'\'', pos);
                        auto dq = text.find(L'"', pos);
                        if (sq == std::wstring::npos && dq == std::wstring::npos) break;
                        bool isSingle = (sq != std::wstring::npos && (dq == std::wstring::npos || sq < dq));
                        wchar_t quote = isSingle ? L'\'' : L'"';
                        size_t qstart = isSingle ? sq : dq;
                        auto qend = text.find(quote, qstart + 1);
                        if (qend == std::wstring::npos) break;
                        std::wstring path = text.substr(qstart + 1, qend - qstart - 1);
                        if (!isSingle) path = UnescapeTomlDQ(path);
                        if (!path.empty()) {
                            if (level == AccessLevel::Read) config.registryRead.push_back(path);
                            else config.registryWrite.push_back(path);
                        }
                        pos = qend + 1;
                    }
                };
                extractRegPaths(line);
                if (line.find(L'[') != std::wstring::npos && line.find(L']') == std::wstring::npos) {
                    std::wstring contLine;
                    while (std::getline(ss, contLine)) {
                        if (!contLine.empty() && contLine.back() == L'\r') contLine.pop_back();
                        auto cs = contLine.find_first_not_of(L" \t");
                        if (cs == std::wstring::npos) continue;
                        contLine = contLine.substr(cs);
                        if (contLine[0] == L'#') continue;
                        extractRegPaths(contLine);
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
                    else if (kv.key == L"named_pipes")  config.allowNamedPipes = enabled;
                    else if (kv.key == L"stdin")        config.allowStdin = enabled;
                    else {
                        fprintf(stderr, "Error: Unknown key in [allow]: %ls\n", kv.key.c_str());
                        config.parseError = true;
                    }
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
                    else {
                        fprintf(stderr, "Error: Unknown key in [environment]: %ls\n", kv.key.c_str());
                        config.parseError = true;
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
                        else {
                            fprintf(stderr, "Error: Unknown key in [limit]: %ls\n", kv.key.c_str());
                            config.parseError = true;
                        }
                    }
                }
                continue;
            }
        }

        // --- Mandatory [sandbox] check ---
        if (!sandboxSeen) {
            fprintf(stderr, "Error: [sandbox] section is required. Add [sandbox] with token = \"appcontainer\" or \"restricted\".\n");
            config.parseError = true;
        }

        // --- Mode-specific validation ---
        if (!config.parseError) {
            bool isAC = (config.tokenMode == TokenMode::AppContainer);
            bool isRT = (config.tokenMode == TokenMode::Restricted);

            // AppContainer-only flags used in Restricted mode
            if (isRT) {
                if (config.allowNetwork)   { fprintf(stderr, "Error: 'network' is not available in restricted mode (network is always unrestricted).\n");   config.parseError = true; }
                if (config.allowLocalhost) { fprintf(stderr, "Error: 'localhost' is not available in restricted mode (network is always unrestricted).\n"); config.parseError = true; }
                if (config.allowLan)       { fprintf(stderr, "Error: 'lan' is not available in restricted mode (network is always unrestricted).\n");       config.parseError = true; }
                if (config.allowSystemDirs){ fprintf(stderr, "Error: 'system_dirs' is not available in restricted mode (system dirs are always readable).\n"); config.parseError = true; }
            }

            // Restricted-only flags used in AppContainer mode
            if (isAC) {
                if (config.allowNamedPipes)          { fprintf(stderr, "Error: 'named_pipes' is not available in appcontainer mode (named pipes are always blocked).\n"); config.parseError = true; }
                if (config.integrity != IntegrityLevel::Low) { fprintf(stderr, "Error: 'integrity' is not available in appcontainer mode (always Low).\n"); config.parseError = true; }
                if (registrySeen)                   { fprintf(stderr, "Error: [registry] section is not available in appcontainer mode.\n"); config.parseError = true; }
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
    // Convert user-friendly registry path to Win32 object path
    // -----------------------------------------------------------------------
    inline std::wstring RegistryToWin32Path(const std::wstring& path)
    {
        if (_wcsnicmp(path.c_str(), L"HKCU\\", 5) == 0) return L"CURRENT_USER\\" + path.substr(5);
        if (_wcsnicmp(path.c_str(), L"HKLM\\", 5) == 0) return L"MACHINE\\" + path.substr(5);
        return path;
    }

    // -----------------------------------------------------------------------
    // Grant access to a file/folder or registry key with specific permissions
    // -----------------------------------------------------------------------
    inline bool GrantObjectAccess(PSID pSid, const std::wstring& path,
                                  AccessLevel level, SE_OBJECT_TYPE objType = SE_FILE_OBJECT)
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
            path.c_str(), objType, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, &pOldDacl, nullptr, &pSD);
        if (rc != ERROR_SUCCESS)
            return false;

        PACL pNewDacl = nullptr;
        rc = SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl);
        LocalFree(pSD);
        if (rc != ERROR_SUCCESS)
            return false;

        rc = SetNamedSecurityInfoW(
            const_cast<LPWSTR>(path.c_str()), objType,
            DACL_SECURITY_INFORMATION, nullptr, nullptr, pNewDacl, nullptr);
        LocalFree(pNewDacl);

        // Log SDDL of the resulting DACL for forensic analysis
        if (rc == ERROR_SUCCESS) {
            PACL pResultDacl = nullptr;
            PSECURITY_DESCRIPTOR pResultSD = nullptr;
            if (GetNamedSecurityInfoW(path.c_str(), objType,
                    DACL_SECURITY_INFORMATION, nullptr, nullptr,
                    &pResultDacl, nullptr, &pResultSD) == ERROR_SUCCESS) {
                LPWSTR sddl = nullptr;
                if (ConvertSecurityDescriptorToStringSecurityDescriptorW(
                        pResultSD, SDDL_REVISION_1, DACL_SECURITY_INFORMATION,
                        &sddl, nullptr)) {
                    std::wstring logMsg = L"GRANT_SDDL: " + path + L" -> " + sddl;
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
    // Create a restricted sandbox token (alternative to AppContainer).
    // Uses restricting SIDs + configurable integrity level.
    // allowNamedPipes: if true, includes Everyone (S-1-1-0) in restricting SIDs,
    //             which allows CreateNamedPipeW to succeed.
    // il: Low = stronger isolation (may break some apps), Medium = wider compat.
    // -----------------------------------------------------------------------
    inline HANDLE CreateRestrictedSandboxToken(bool allowNamedPipes, IntegrityLevel il)
    {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
            return nullptr;

        // --- Enumerate token groups → build deny-only list ---
        DWORD groupSize = 0;
        GetTokenInformation(hToken, TokenGroups, nullptr, 0, &groupSize);
        std::vector<BYTE> groupBuf(groupSize);
        auto* pGroups = reinterpret_cast<TOKEN_GROUPS*>(groupBuf.data());
        if (!GetTokenInformation(hToken, TokenGroups, pGroups, groupSize, &groupSize)) {
            CloseHandle(hToken);
            return nullptr;
        }

        // Get user SID (needed for restricting SIDs)
        DWORD userSize = 0;
        GetTokenInformation(hToken, TokenUser, nullptr, 0, &userSize);
        std::vector<BYTE> userBuf(userSize);
        auto* pUser = reinterpret_cast<TOKEN_USER*>(userBuf.data());
        GetTokenInformation(hToken, TokenUser, pUser, userSize, &userSize);

        // Logon SID — needed for desktop access
        PSID pLogonSid = nullptr;
        for (DWORD i = 0; i < pGroups->GroupCount; i++) {
            if ((pGroups->Groups[i].Attributes & SE_GROUP_LOGON_ID) != 0) {
                pLogonSid = pGroups->Groups[i].Sid;
                break;
            }
        }

        // --- Build restricting SID list ---
        // The dual access check ensures both normal SIDs AND restricting SIDs
        // must allow access. This limits the token's effective access to only
        // resources that have explicit ACEs for the restricting SIDs.
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        PSID pRestrictedSid = nullptr;
        AllocateAndInitializeSid(&ntAuth, 1, SECURITY_RESTRICTED_CODE_RID,
            0, 0, 0, 0, 0, 0, 0, &pRestrictedSid);

        // Everyone (S-1-1-0) — always included because many system objects
        // (DLLs, registry keys, pipe namespace) use Everyone ACEs. Without
        // Everyone in restricting SIDs, the dual access check fails and the
        // process can't even load its initial DLLs.
        SID_IDENTIFIER_AUTHORITY worldAuth = SECURITY_WORLD_SID_AUTHORITY;
        PSID pEveryoneSid = nullptr;
        AllocateAndInitializeSid(&worldAuth, 1, SECURITY_WORLD_RID,
            0, 0, 0, 0, 0, 0, 0, &pEveryoneSid);

        // BUILTIN\Users (S-1-5-32-545) — system directories grant read to Users.
        PSID pUsersSid = nullptr;
        AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_USERS, 0, 0, 0, 0, 0, 0, &pUsersSid);

        std::vector<SID_AND_ATTRIBUTES> restrictSids;
        restrictSids.push_back({ pUser->User.Sid, 0 });
        restrictSids.push_back({ pRestrictedSid, 0 });
        restrictSids.push_back({ pUsersSid, 0 });
        if (pLogonSid) restrictSids.push_back({ pLogonSid, 0 });
        if (pEveryoneSid) restrictSids.push_back({ pEveryoneSid, 0 });

        // Authenticated Users (S-1-5-11) — many system objects (WinSxS
        // manifests, CRT DLLs, API set resolvers) grant access to
        // Authenticated Users. Without this, the DLL loader can fail with
        // STATUS_DLL_NOT_FOUND for complex executables like Python.
        PSID pAuthUsersSid = nullptr;
        AllocateAndInitializeSid(&ntAuth, 1, SECURITY_AUTHENTICATED_USER_RID,
            0, 0, 0, 0, 0, 0, 0, &pAuthUsersSid);
        if (pAuthUsersSid) restrictSids.push_back({ pAuthUsersSid, 0 });

        // --- Enumerate privileges → delete all except SeChangeNotifyPrivilege ---
        DWORD privSize = 0;
        GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &privSize);
        std::vector<BYTE> privBuf(privSize);
        auto* pPrivs = reinterpret_cast<TOKEN_PRIVILEGES*>(privBuf.data());
        GetTokenInformation(hToken, TokenPrivileges, pPrivs, privSize, &privSize);

        LUID changeNotifyLuid;
        LookupPrivilegeValueW(nullptr, SE_CHANGE_NOTIFY_NAME, &changeNotifyLuid);

        std::vector<LUID_AND_ATTRIBUTES> deletePrivs;
        for (DWORD i = 0; i < pPrivs->PrivilegeCount; i++) {
            if (pPrivs->Privileges[i].Luid.LowPart == changeNotifyLuid.LowPart &&
                pPrivs->Privileges[i].Luid.HighPart == changeNotifyLuid.HighPart)
                continue;
            deletePrivs.push_back(pPrivs->Privileges[i]);
        }

        // --- Create restricted token ---
        // No deny-only groups (0 flags) — restricting SIDs + Low integrity
        // provide strong isolation via dual access check.
        HANDLE hRestricted = nullptr;
        BOOL ok = CreateRestrictedToken(
            hToken,
            0,          // no flags — groups stay active, restricting SIDs do the work
            0, nullptr, // no deny-only SIDs
            static_cast<DWORD>(deletePrivs.size()), deletePrivs.data(),
            static_cast<DWORD>(restrictSids.size()), restrictSids.data(),
            &hRestricted);

        // --- Set integrity level ---
        // Low (0x1000): strongest isolation, blocks writes to Medium objects.
        //   May break apps that depend on api-ms-win-core-path API set.
        // Medium: inherits parent's level; relies solely on restricting SIDs.
        if (ok && hRestricted && il == IntegrityLevel::Low) {
            SID_IDENTIFIER_AUTHORITY mlAuth = SECURITY_MANDATORY_LABEL_AUTHORITY;
            PSID pLowSid = nullptr;
            if (AllocateAndInitializeSid(&mlAuth, 1, SECURITY_MANDATORY_LOW_RID,
                    0, 0, 0, 0, 0, 0, 0, &pLowSid)) {
                TOKEN_MANDATORY_LABEL tml = {};
                tml.Label.Sid = pLowSid;
                tml.Label.Attributes = SE_GROUP_INTEGRITY;
                SetTokenInformation(hRestricted, TokenIntegrityLevel,
                    &tml, sizeof(tml) + GetLengthSid(pLowSid));
                FreeSid(pLowSid);
            }
        }

        // Cleanup
        if (pRestrictedSid) FreeSid(pRestrictedSid);
        if (pEveryoneSid) FreeSid(pEveryoneSid);
        if (pUsersSid) FreeSid(pUsersSid);
        CloseHandle(hToken);

        return ok ? hRestricted : nullptr;
    }

    // -----------------------------------------------------------------------
    // Grant a SID access to the current window station and desktop.
    // Required for CreateProcessAsUser — without this, processes using a
    // restricted token get STATUS_ACCESS_DENIED when attaching to the desktop.
    // -----------------------------------------------------------------------
    inline bool GrantDesktopAccess(PSID pSid) {
        auto grantObj = [&](HANDLE hObj) -> bool {
            SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;
            PSECURITY_DESCRIPTOR pSD = nullptr;
            PACL pOldDacl = nullptr;
            if (GetSecurityInfo(hObj, SE_WINDOW_OBJECT, si,
                    nullptr, nullptr, &pOldDacl, nullptr, &pSD) != ERROR_SUCCESS)
                return false;

            EXPLICIT_ACCESS_W ea{};
            ea.grfAccessPermissions = GENERIC_ALL;
            ea.grfAccessMode = SET_ACCESS;
            ea.grfInheritance = NO_INHERITANCE;
            ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
            ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(pSid);

            PACL pNewDacl = nullptr;
            if (SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl) != ERROR_SUCCESS) {
                LocalFree(pSD);
                return false;
            }

            bool ok = SetSecurityInfo(hObj, SE_WINDOW_OBJECT, si,
                          nullptr, nullptr, pNewDacl, nullptr) == ERROR_SUCCESS;
            LocalFree(pNewDacl);
            LocalFree(pSD);
            return ok;
        };

        HWINSTA hWinSta = GetProcessWindowStation();
        HDESK hDesktop = OpenDesktopW(L"Default", 0, FALSE,
            READ_CONTROL | WRITE_DAC | DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS |
            DESKTOP_CREATEWINDOW | DESKTOP_CREATEMENU | DESKTOP_SWITCHDESKTOP);

        bool ok = true;
        if (hWinSta) ok &= grantObj(hWinSta);
        if (hDesktop) {
            ok &= grantObj(hDesktop);
            CloseDesktop(hDesktop);
        }
        return ok;
    }

    // -----------------------------------------------------------------------
    // Launch an executable inside a sandbox.
    // Supports AppContainer (default) and Restricted Token modes.
    // All behavior is controlled by the SandboxConfig.
    // -----------------------------------------------------------------------
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
            hRestrictedToken = CreateRestrictedSandboxToken(config.allowNamedPipes, config.integrity);
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

        if (!isRestricted) {
            sc.AppContainerSid = pContainerSid;
            sc.Capabilities = capCount > 0 ? caps : nullptr;
            sc.CapabilityCount = capCount;
            strictIsolation = !config.allowSystemDirs;
            attrCount = strictIsolation ? 2 : 1;
        }

        SIZE_T attrSize = 0;
        LPPROC_THREAD_ATTRIBUTE_LIST pAttrList = nullptr;
        std::vector<BYTE> attrBuf;

        if (!isRestricted) {
            InitializeProcThreadAttributeList(nullptr, attrCount, 0, &attrSize);
            attrBuf.resize(attrSize);
            pAttrList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrBuf.data());
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
        if (isRestricted) {
            // Restricted token: use CreateProcessAsUser
            // Works for restricted tokens derived from the caller's own token.
            // Requires SE_INCREASE_QUOTA_NAME (available to admins).
            created = CreateProcessAsUser(
                hRestrictedToken, nullptr, &cmdLine[0], nullptr, nullptr, TRUE,
                CREATE_UNICODE_ENVIRONMENT,
                envBlock.empty() ? nullptr : envBlock.data(),
                exeFolder.c_str(), &siex.StartupInfo, &pi);
        } else {
            // AppContainer: use CreateProcessW with EXTENDED_STARTUPINFO_PRESENT
            created = CreateProcessW(
                nullptr, &cmdLine[0], nullptr, nullptr, TRUE,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
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
