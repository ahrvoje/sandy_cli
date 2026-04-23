// =========================================================================
// SandboxTypes.h — Sandbox types, configuration, and session logger
//
// Contains foundational types (AccessLevel, FolderEntry, SandboxConfig)
// and the SandyLogger used for session logging.
// =========================================================================
#pragma once

#include "framework.h"
#include <io.h>
#include <share.h>
#include <string>
#include <vector>
#include <cstdio>

namespace Sandbox {

    // -----------------------------------------------------------------------
    // Sandy exit codes — POSIX high-code convention (125+).
    //
    // Child exit codes 0-124 pass through unchanged with zero ambiguity.
    // Sandy wrapper errors use 125+ following bash/env/timeout/git bisect:
    //   125   = internal error (git bisect convention)
    //   126   = cannot execute (bash/env convention)
    //   127   = command not found (bash/env convention)
    //   128+  = Sandy-specific conditions
    //
    // On Windows, child exit codes > 124 (e.g. 0xC0000005 truncated to
    // 8-bit) may alias Sandy codes — the EXIT_CLASS log line disambiguates.
    // -----------------------------------------------------------------------
    namespace SandyExit {
        constexpr int Success      = 0;    // child exited 0, or info command succeeded
        constexpr int InternalError = 125; // Sandy internal / unspecified error
        constexpr int CannotExec   = 126;  // CreateProcess failed (permission denied, bad format)
        constexpr int NotFound     = 127;  // executable not found on disk
        constexpr int ConfigError  = 128;  // TOML parse/validation error, config file not found
        constexpr int SetupError   = 129;  // sandbox setup failed (token, SID, ACL, pipes)
        constexpr int Timeout      = 130;  // child killed by Sandy's timeout watchdog
        constexpr int ChildCrash   = 131;  // child exited with NTSTATUS crash code
    }

    // Container identity — per-instance UUID for isolation
    constexpr const wchar_t* kContainerPrefix = L"Sandy_";

    // Generate a UUID string for this instance (e.g. "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
    inline std::wstring GenerateInstanceId()
    {
        GUID guid{};
        if (FAILED(CoCreateGuid(&guid)))
            return {};
        wchar_t buf[40];
        swprintf(buf, 40, L"%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                 guid.Data1, guid.Data2, guid.Data3,
                 guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
                 guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
        return buf;
    }

    // Build AppContainer name from instance ID: "Sandy_<uuid>"
    inline std::wstring ContainerNameFromId(const std::wstring& instanceId)
    {
        return kContainerPrefix + instanceId;
    }

    // -----------------------------------------------------------------------
    // Folder access level
    // -----------------------------------------------------------------------
    enum class AccessLevel { Read, Write, Execute, Append, Delete, All, Run, Stat, Touch, Create };

    // -----------------------------------------------------------------------
    // Grant scope — Deep = recursive (OI|CI), This = single object only
    // -----------------------------------------------------------------------
    enum class GrantScope { Deep, This };

    struct FolderEntry {
        std::wstring path;
        AccessLevel  access;
        GrantScope   scope = GrantScope::Deep;
    };

    // Normalize filesystem paths to Sandy's canonical separator style.
    // This keeps config/profile input, grant persistence, overlap checks,
    // and stale cleanup operating on one consistent path representation.
    //
    // P2: Resolves . and .. segments via GetFullPathNameW for absolute
    // filesystem paths.  Without this, PathDepth/IsPathUnder miscalculate
    // depth and ancestry for paths like C:\base\. or C:\base\..\other.
    inline std::wstring NormalizeFsPath(std::wstring path)
    {
        for (auto& ch : path) {
            if (ch == L'/') ch = L'\\';
        }
        // Canonicalize absolute filesystem paths (drive letter or UNC)
        // to resolve . and .. segments.  GetFullPathNameW is purely lexical
        // for absolute paths — no filesystem I/O occurs.  Must handle
        // extended-limit paths (up to ~32K) so PathDepth/IsPathUnder don't
        // operate on un-canonicalized input for long configured paths.
        bool isAbsFs = (path.size() >= 3 && iswalpha(path[0]) && path[1] == L':' && path[2] == L'\\') ||
                       (path.size() >= 2 && path[0] == L'\\' && path[1] == L'\\');
        if (isAbsFs) {
            DWORD needed = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
            if (needed > 0) {
                std::vector<wchar_t> buf(needed);
                DWORD len = GetFullPathNameW(path.c_str(),
                                             static_cast<DWORD>(buf.size()),
                                             buf.data(), nullptr);
                if (len > 0 && len < buf.size())
                    path.assign(buf.data(), len);
            }
        }
        // Strip trailing backslashes — they break IsPathUnder prefix matching.
        // Preserve root paths like "C:\" (3 chars: drive letter + colon + backslash).
        while (path.size() > 3 && path.back() == L'\\')
            path.pop_back();
        return path;
    }

    inline std::wstring NormalizeLookupKey(std::wstring value)
    {
        for (auto& ch : value)
            ch = static_cast<wchar_t>(towlower(ch));
        return value;
    }

    // Check if an exit code looks like a native process crash.
    // Used to classify child termination without owning host-global dump state.
    inline bool IsCrashExitCode(DWORD exitCode)
    {
        if ((exitCode & 0xF0000000) == 0xC0000000) return true;
        if (exitCode == 0x80000003) return true;  // STATUS_BREAKPOINT
        // Software exception codes (0xE0*): CLR (.NET) and MSVC C++ unhandled exceptions
        if ((exitCode & 0xF0000000) == 0xE0000000) return true;
        return false;
    }

    inline bool AppContainerMissing(HRESULT hr)
    {
        DWORD code = HRESULT_CODE(hr);
        return code == ERROR_NOT_FOUND || code == ERROR_FILE_NOT_FOUND;
    }

    // Human-readable tag for an access level
    inline const wchar_t* AccessTag(AccessLevel level) {
        switch (level) {
        case AccessLevel::Read:    return L"READ";
        case AccessLevel::Write:   return L"WRITE";
        case AccessLevel::Execute: return L"EXECUTE";
        case AccessLevel::Append:  return L"APPEND";
        case AccessLevel::Delete:  return L"DELETE";
        case AccessLevel::All:     return L"ALL";
        case AccessLevel::Run:     return L"RUN";
        case AccessLevel::Stat:    return L"STAT";
        case AccessLevel::Touch:   return L"TOUCH";
        case AccessLevel::Create:  return L"CREATE";
        default:                   return L"?";
        }
    }

    // Lowercase access level name (for TOML output, user-facing display)
    inline const wchar_t* AccessLevelName(AccessLevel level) {
        switch (level) {
        case AccessLevel::Read:    return L"read";
        case AccessLevel::Write:   return L"write";
        case AccessLevel::Execute: return L"execute";
        case AccessLevel::Append:  return L"append";
        case AccessLevel::Delete:  return L"delete";
        case AccessLevel::All:     return L"all";
        case AccessLevel::Run:     return L"run";
        case AccessLevel::Stat:    return L"stat";
        case AccessLevel::Touch:   return L"touch";
        case AccessLevel::Create:  return L"create";
        default:                   return L"?";
        }
    }

    // Parse access level from string (case-insensitive, reverse of AccessTag).
    // Returns false if the tag is unrecognized (callers must handle the error).
    inline bool ParseAccessTag(const std::wstring& s, AccessLevel& out) {
        if (_wcsicmp(s.c_str(), L"read")    == 0) { out = AccessLevel::Read;    return true; }
        if (_wcsicmp(s.c_str(), L"write")   == 0) { out = AccessLevel::Write;   return true; }
        if (_wcsicmp(s.c_str(), L"execute") == 0) { out = AccessLevel::Execute; return true; }
        if (_wcsicmp(s.c_str(), L"append")  == 0) { out = AccessLevel::Append;  return true; }
        if (_wcsicmp(s.c_str(), L"delete")  == 0) { out = AccessLevel::Delete;  return true; }
        if (_wcsicmp(s.c_str(), L"all")     == 0) { out = AccessLevel::All;     return true; }
        if (_wcsicmp(s.c_str(), L"run")     == 0) { out = AccessLevel::Run;     return true; }
        if (_wcsicmp(s.c_str(), L"stat")    == 0) { out = AccessLevel::Stat;    return true; }
        if (_wcsicmp(s.c_str(), L"touch")   == 0) { out = AccessLevel::Touch;   return true; }
        if (_wcsicmp(s.c_str(), L"create")  == 0) { out = AccessLevel::Create;  return true; }
        return false;  // unknown tag — fail closed
    }

    // -----------------------------------------------------------------------
    // AllocateInstanceSid — generate a unique per-instance SID (S-1-9-<uuid>).
    //
    // Uses SECURITY_RESOURCE_MANAGER_AUTHORITY — the Microsoft-designated
    // authority for third-party resource managers.  Each call returns a new
    // SID derived from a fresh GUID so ACEs are distinguishable per instance.
    // Caller must FreeSid() on success.  Returns nullptr on failure.
    // -----------------------------------------------------------------------
    inline PSID AllocateInstanceSid()
    {
        GUID sidGuid{};
        if (FAILED(CoCreateGuid(&sidGuid)))
            return nullptr;
        SID_IDENTIFIER_AUTHORITY rmAuth = { {0, 0, 0, 0, 0, 9} };
        PSID pSid = nullptr;
        if (!AllocateAndInitializeSid(&rmAuth, 4,
                sidGuid.Data1,
                static_cast<DWORD>(sidGuid.Data2 | (sidGuid.Data3 << 16)),
                static_cast<DWORD>(sidGuid.Data4[0] | (sidGuid.Data4[1] << 8) |
                                   (sidGuid.Data4[2] << 16) | (sidGuid.Data4[3] << 24)),
                static_cast<DWORD>(sidGuid.Data4[4] | (sidGuid.Data4[5] << 8) |
                                   (sidGuid.Data4[6] << 16) | (sidGuid.Data4[7] << 24)),
                0, 0, 0, 0, &pSid))
            return nullptr;
        return pSid;
    }

    // -----------------------------------------------------------------------
    // Win32 error code → human-readable string (via FormatMessageW)
    //
    // Returns e.g. "Access is denied" for ERROR_ACCESS_DENIED (5).
    // Falls back to "Unknown error" if FormatMessage fails.
    // -----------------------------------------------------------------------
    inline std::wstring GetSystemErrorMessage(DWORD errCode)
    {
        wchar_t* pMsg = nullptr;
        DWORD len = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
            nullptr, errCode, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&pMsg), 0, nullptr);
        if (len > 0 && pMsg) {
            // Trim trailing whitespace/period
            while (len > 0 && (pMsg[len - 1] == L' ' || pMsg[len - 1] == L'.'
                            || pMsg[len - 1] == L'\r' || pMsg[len - 1] == L'\n'))
                len--;
            std::wstring result(pMsg, len);
            LocalFree(pMsg);
            return result;
        }
        if (pMsg) LocalFree(pMsg);
        return L"Unknown error";
    }

    // -----------------------------------------------------------------------
    // Sandbox token mode
    // -----------------------------------------------------------------------
    enum class TokenMode { AppContainer, LPAC, Restricted };

    inline bool IsRestrictedTokenMode(TokenMode mode)
    {
        return mode == TokenMode::Restricted;
    }

    inline bool IsAppContainerFamilyTokenMode(TokenMode mode)
    {
        return !IsRestrictedTokenMode(mode);
    }

    inline const wchar_t* TokenModeName(TokenMode mode)
    {
        switch (mode) {
        case TokenMode::Restricted:   return L"restricted";
        case TokenMode::LPAC:         return L"lpac";
        case TokenMode::AppContainer:
        default:                      return L"appcontainer";
        }
    }

    inline const char* TokenModeSummaryLabel(TokenMode mode)
    {
        switch (mode) {
        case TokenMode::Restricted:   return "Restricted Token";
        case TokenMode::LPAC:         return "LPAC Sandbox";
        case TokenMode::AppContainer:
        default:                      return "AppContainer";
        }
    }

    inline bool TryParseTokenMode(const std::wstring& value, TokenMode& out)
    {
        if (value == L"restricted")   { out = TokenMode::Restricted; return true; }
        if (value == L"lpac")         { out = TokenMode::LPAC; return true; }
        if (value == L"appcontainer") { out = TokenMode::AppContainer; return true; }
        return false;
    }

    // -----------------------------------------------------------------------
    // Integrity level for restricted token
    // -----------------------------------------------------------------------
    enum class IntegrityLevel { Low, Medium };

    // -----------------------------------------------------------------------
    // LAN mode — three valid states for private-network + loopback access.
    //
    // Windows AppContainer requires PRIVATE_NETWORK_CLIENT_SERVER capability
    // for both LAN and loopback.  Loopback additionally requires a
    // CheckNetIsolation exemption.  There is no localhost-only capability
    // SID — loopback always implies LAN access.
    // -----------------------------------------------------------------------
    enum class LanMode { Off, WithoutLocalhost, WithLocalhost };

    inline const wchar_t* LanModeRegistryName(LanMode mode)
    {
        switch (mode) {
        case LanMode::WithLocalhost:    return L"with_localhost";
        case LanMode::WithoutLocalhost: return L"without_localhost";
        case LanMode::Off:
        default:                        return L"off";
        }
    }

    inline const wchar_t* LanModePhrase(LanMode mode)
    {
        switch (mode) {
        case LanMode::WithLocalhost:    return L"with localhost";
        case LanMode::WithoutLocalhost: return L"without localhost";
        case LanMode::Off:
        default:                        return L"false";
        }
    }

    inline const wchar_t* LanModeTomlDisplayValue(LanMode mode)
    {
        switch (mode) {
        case LanMode::WithLocalhost:    return L"'with localhost'";
        case LanMode::WithoutLocalhost: return L"'without localhost'";
        case LanMode::Off:
        default:                        return L"false";
        }
    }

    inline bool TryParseLanModeConfigValue(const std::wstring& value, LanMode& out)
    {
        if (value == L"false")             { out = LanMode::Off; return true; }
        if (value == L"with localhost")    { out = LanMode::WithLocalhost; return true; }
        if (value == L"without localhost") { out = LanMode::WithoutLocalhost; return true; }
        return false;
    }

    inline bool TryParseLanModeRegistryValue(const std::wstring& value, LanMode& out)
    {
        if (value == L"off")               { out = LanMode::Off; return true; }
        if (value == L"with_localhost")    { out = LanMode::WithLocalhost; return true; }
        if (value == L"without_localhost") { out = LanMode::WithoutLocalhost; return true; }
        return false;
    }

    // -----------------------------------------------------------------------
    // Full sandbox configuration (parsed from TOML)
    // -----------------------------------------------------------------------
    struct SandboxConfig {
        TokenMode tokenMode = TokenMode::AppContainer;  // [sandbox] token
        IntegrityLevel integrity = IntegrityLevel::Low;   // [sandbox] integrity (restricted only)
        bool strict = false;                               // [sandbox] strict (restricted only)
        std::wstring workdir;                              // [sandbox] workdir (optional)
        std::vector<FolderEntry> folders;
        std::vector<FolderEntry> denyFolders;  // [deny.*] — DENY ACEs

        // [privileges] — sandbox capabilities (optional, defaults shown)
        bool allowNetwork    = false;
        LanMode lanMode      = LanMode::Off;

        bool allowNamedPipes  = false;  // restricted mode: controls named pipe creation
        bool allowDesktop     = true;   // restricted mode: grant WinSta0 + Desktop access (default true)

        // stdin control: "NUL" = disabled, empty/true = inherit, path = file
        std::wstring stdinMode = L"NUL";
        bool allowClipboardRead  = false;
        bool allowClipboardWrite = false;
        bool allowChildProcesses = true;  // default true: most programs spawn child processes

        // [registry] — registry key grants (restricted mode only)
        std::vector<std::wstring> registryRead;
        std::vector<std::wstring> registryWrite;

        // [environment] — env block control
        bool envInherit = false;
        std::vector<std::wstring> envPass;

        // [limit] — resource constraints (0 = unlimited)
        DWORD  timeoutSeconds = 0;
        SIZE_T memoryLimitMB  = 0;
        DWORD  maxProcesses   = 0;

        // Logging (set via -l CLI flag, not TOML)
        std::wstring logPath;

        // Config source (set by CLI for forensic logging)
        std::wstring configSource;

        // Quiet mode (set via -q CLI flag, not TOML)
        bool quiet = false;

        // Parse error flag (set if unknown section/key encountered)
        bool parseError = false;
    };

    // -----------------------------------------------------------------------
    // Sandy Logger — Process output and sandbox event log
    // Logs sandbox configuration, child process output, limit events,
    // and exit code to a file specified by -l <path>.
    // -----------------------------------------------------------------------
    struct SandyLogger {
        std::wstring logFilePath;
        FILE* logFile = nullptr;
        bool active = false;
        int truncatedCount = 0;  // LogFmt truncation counter (reported in Stop)
        SRWLOCK lock = SRWLOCK_INIT;

        // ISO 8601 timestamp with millisecond precision (local time + UTC offset)
        static std::wstring Timestamp() {
            SYSTEMTIME st;
            GetLocalTime(&st);

            // Compute UTC offset in minutes
            TIME_ZONE_INFORMATION tzi;
            DWORD tzResult = GetTimeZoneInformation(&tzi);
            LONG biasMinutes = tzi.Bias;
            if (tzResult == TIME_ZONE_ID_DAYLIGHT)
                biasMinutes += tzi.DaylightBias;
            else if (tzResult == TIME_ZONE_ID_STANDARD)
                biasMinutes += tzi.StandardBias;
            // biasMinutes is minutes WEST of UTC, so negate for ISO offset
            LONG offsetMinutes = -biasMinutes;
            wchar_t sign = (offsetMinutes >= 0) ? L'+' : L'-';
            LONG absOffset = (offsetMinutes >= 0) ? offsetMinutes : -offsetMinutes;

            wchar_t buf[40];
            swprintf(buf, 40, L"%04d-%02d-%02dT%02d:%02d:%02d.%03d%c%02ld:%02ld",
                     st.wYear, st.wMonth, st.wDay,
                     st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                     sign, absOffset / 60, absOffset % 60);
            return buf;
        }

        bool Start(const std::wstring& logPath) {
            AcquireSRWLockExclusive(&lock);

            // Numbered rotation (POSIX style): session.log -> session.log.1 -> session.log.2
            std::wstring finalPath = logPath;
            if (GetFileAttributesW(logPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                for (int n = 1; ; n++) {
                    finalPath = logPath + L"." + std::to_wstring(n);
                    if (GetFileAttributesW(finalPath.c_str()) == INVALID_FILE_ATTRIBUTES)
                        break;
                }
            }

            // Open once with retry, set unbuffered for crash resilience
            FILE* f = nullptr;
            for (int attempt = 0; attempt < 3; attempt++) {
                f = _wfsopen(finalPath.c_str(), L"w, ccs=UTF-8", _SH_DENYWR);
                if (f) break;
                if (attempt < 2) Sleep(50);
            }
            if (!f) {
                ReleaseSRWLockExclusive(&lock);
                fprintf(stderr, "[Warning] Could not create log file: %ls\n", finalPath.c_str());
                return false;
            }
            setvbuf(f, nullptr, _IONBF, 0);  // unbuffered: every write hits OS immediately
            fwprintf(f, L"[%s] === Sandy Log ===\n", Timestamp().c_str());
            _commit(_fileno(f));
            logFile = f;
            logFilePath = finalPath;
            active = true;
            ReleaseSRWLockExclusive(&lock);
            return true;
        }

        void Stop() {
            AcquireSRWLockExclusive(&lock);
            if (logFile) {
                if (truncatedCount > 0) {
                    fwprintf(logFile, L"[%s] LOG_DIAG: %d messages were truncated during this session\n",
                             Timestamp().c_str(), truncatedCount);
                    _commit(_fileno(logFile));
                }
                fclose(logFile);
                logFile = nullptr;
            }
            active = false;
            truncatedCount = 0;
            ReleaseSRWLockExclusive(&lock);
        }

        static const wchar_t* StdinLogValue(const SandboxConfig& config)
        {
            if (config.stdinMode.empty())
                return L"inherit";
            if (_wcsicmp(config.stdinMode.c_str(), L"NUL") == 0)
                return L"disabled";
            return config.stdinMode.c_str();
        }

        void WriteConfigHeaderUnlocked(const std::wstring& ts,
                                       const std::wstring& exe,
                                       const std::wstring& args)
        {
            fwprintf(logFile, L"[%s] === Configuration ===\n", ts.c_str());
            fwprintf(logFile, L"[%s] EXEC: %s\n", ts.c_str(), exe.c_str());
            if (!args.empty())
                fwprintf(logFile, L"[%s] ARGS: %s\n", ts.c_str(), args.c_str());
        }

        void WriteAccessSectionUnlocked(const std::wstring& ts,
                                        const wchar_t* sectionName,
                                        const std::vector<FolderEntry>& entries)
        {
            if (entries.empty())
                return;

            fwprintf(logFile, L"[%s] %ls: %zu entries\n", ts.c_str(), sectionName, entries.size());
            for (const auto& entry : entries)
                fwprintf(logFile, L"[%s]     [%-7s] %s\n", ts.c_str(),
                         AccessTag(entry.access), entry.path.c_str());
        }

        void WriteRegistryEntriesUnlocked(const std::wstring& ts,
                                          const wchar_t* tag,
                                          const std::vector<std::wstring>& keys)
        {
            for (const auto& key : keys)
                fwprintf(logFile, L"[%s]     [%-7ls] %s\n", ts.c_str(), tag, key.c_str());
        }

        void WriteRegistrySectionUnlocked(const std::wstring& ts,
                                          const SandboxConfig& config)
        {
            if (config.registryRead.empty() && config.registryWrite.empty())
                return;

            fwprintf(logFile, L"[%s] REGISTRY: %zu keys\n", ts.c_str(),
                     config.registryRead.size() + config.registryWrite.size());
            WriteRegistryEntriesUnlocked(ts, L"READ", config.registryRead);
            WriteRegistryEntriesUnlocked(ts, L"WRITE", config.registryWrite);
        }

        void WritePrivilegesSectionUnlocked(const std::wstring& ts,
                                            const SandboxConfig& config)
        {
            bool isRT = IsRestrictedTokenMode(config.tokenMode);
            fwprintf(logFile, L"[%s] PRIVILEGES:\n", ts.c_str());
            // Mode-specific keys — README defines these per mode.  Logging
            // keys that do not apply to the active mode is misleading when
            // auditing sessions later.
            if (isRT && config.strict)
                fwprintf(logFile, L"[%s]     strict          = yes\n", ts.c_str());
            if (isRT) {
                fwprintf(logFile, L"[%s]     named_pipes     = %s\n", ts.c_str(),
                         config.allowNamedPipes ? L"yes" : L"no");
                fwprintf(logFile, L"[%s]     desktop         = %s\n", ts.c_str(),
                         config.allowDesktop ? L"yes" : L"no");
            }
            fwprintf(logFile, L"[%s]     stdin           = %s\n", ts.c_str(),
                     StdinLogValue(config));
            fwprintf(logFile, L"[%s]     clipboard       = read=%s write=%s\n", ts.c_str(),
                     config.allowClipboardRead ? L"yes" : L"no",
                     config.allowClipboardWrite ? L"yes" : L"no");
            fwprintf(logFile, L"[%s]     child_processes = %s\n", ts.c_str(),
                     config.allowChildProcesses ? L"yes" : L"no");
            fwprintf(logFile, L"[%s]     environment     = %s\n", ts.c_str(),
                     config.envInherit ? L"inherit" : L"filtered");

            if (!isRT) {
                fwprintf(logFile, L"[%s]     network         = %s\n", ts.c_str(),
                         config.allowNetwork ? L"yes" : L"no");
                fwprintf(logFile, L"[%s]     lan             = %ls\n", ts.c_str(),
                         LanModePhrase(config.lanMode));
            }
        }

        void WriteLimitsSectionUnlocked(const std::wstring& ts,
                                        const SandboxConfig& config)
        {
            if (!config.timeoutSeconds && !config.memoryLimitMB && !config.maxProcesses)
                return;

            fwprintf(logFile, L"[%s] LIMITS:\n", ts.c_str());
            if (config.timeoutSeconds)
                fwprintf(logFile, L"[%s]     timeout         = %lu sec\n", ts.c_str(),
                         config.timeoutSeconds);
            if (config.memoryLimitMB)
                fwprintf(logFile, L"[%s]     memory          = %zu MB\n", ts.c_str(),
                         config.memoryLimitMB);
            if (config.maxProcesses)
                fwprintf(logFile, L"[%s]     processes       = %lu max\n", ts.c_str(),
                         config.maxProcesses);
        }

        void LogConfig(const SandboxConfig& config, const std::wstring& exe,
                       const std::wstring& args) {
            AcquireSRWLockExclusive(&lock);
            if (!active) { ReleaseSRWLockExclusive(&lock); return; }
            auto ts = Timestamp();
            WriteConfigHeaderUnlocked(ts, exe, args);
            WriteAccessSectionUnlocked(ts, L"ALLOW", config.folders);
            WriteAccessSectionUnlocked(ts, L"DENY", config.denyFolders);
            WriteRegistrySectionUnlocked(ts, config);
            WritePrivilegesSectionUnlocked(ts, config);
            WriteLimitsSectionUnlocked(ts, config);

            _commit(_fileno(logFile));
            ReleaseSRWLockExclusive(&lock);
        }

        // (LogOutput removed — console passthrough: no pipe to capture from)

        void WriteLogLineUnlocked(const wchar_t* msg)
        {
            fwprintf(logFile, L"[%s] %s\n", Timestamp().c_str(), msg);
            _commit(_fileno(logFile));
        }

        void RecordFormattingDiagnostic(const wchar_t* msg)
        {
            AcquireSRWLockExclusive(&lock);
            if (!active) { ReleaseSRWLockExclusive(&lock); return; }
            truncatedCount++;
            WriteLogLineUnlocked(msg);
            ReleaseSRWLockExclusive(&lock);
        }

        bool TryFormatLogMessage(const wchar_t* fmt,
                                 va_list& args,
                                 std::wstring& message,
                                 const wchar_t*& diagnostic)
        {
            wchar_t stackBuf[1024];
            va_list measureArgs;
            va_copy(measureArgs, args);
            int needed = _vscwprintf(fmt, measureArgs);
            va_end(measureArgs);

            if (needed < 0) {
                diagnostic = L"LOG_DIAG: formatting failure in LogFmt";
                return false;
            }

            const size_t required = static_cast<size_t>(needed) + 1;
            if (required <= _countof(stackBuf)) {
                int written = _vsnwprintf_s(stackBuf, _countof(stackBuf), _TRUNCATE, fmt, args);
                if (written < 0) {
                    diagnostic = L"LOG_DIAG: stack formatting truncated unexpectedly";
                    return false;
                }
                stackBuf[_countof(stackBuf) - 1] = L'\0';
                message = stackBuf;
                return true;
            }

            std::vector<wchar_t> dynamicBuf(required);
            int written = _vsnwprintf_s(dynamicBuf.data(), dynamicBuf.size(), _TRUNCATE, fmt, args);
            if (written < 0) {
                diagnostic = L"LOG_DIAG: dynamic formatting truncated unexpectedly";
                return false;
            }
            dynamicBuf.back() = L'\0';
            message.assign(dynamicBuf.data());
            return true;
        }

        void Log(const wchar_t* msg) {
            AcquireSRWLockExclusive(&lock);
            if (!active) { ReleaseSRWLockExclusive(&lock); return; }
            WriteLogLineUnlocked(msg);
            ReleaseSRWLockExclusive(&lock);
        }

        // Formatted log — dynamically sizes the buffer when needed.
        // Falls back to a fixed stack buffer for the common case, but avoids
        // silent detail loss for larger diagnostics.
        //
        // No outer `active` gate: Log()/RecordFormattingDiagnostic re-check
        // under the lock and are no-ops when inactive.  The vformat cost is
        // bounded and far cheaper than the redundant lock + unlock + relock
        // the previous gate incurred.
        void LogFmt(const wchar_t* fmt, ...) {
            va_list args;
            va_start(args, fmt);
            std::wstring message;
            const wchar_t* diagnostic = nullptr;
            bool ok = TryFormatLogMessage(fmt, args, message, diagnostic);
            va_end(args);

            if (!ok) {
                RecordFormattingDiagnostic(diagnostic);
                return;
            }

            Log(message.c_str());
        }

        void LogSummary(DWORD exitCode, bool timedOut, DWORD timeoutSec) {
            AcquireSRWLockExclusive(&lock);
            if (!active) { ReleaseSRWLockExclusive(&lock); return; }
            auto ts = Timestamp();
            fwprintf(logFile, L"[%s] --- Process Exit ---\n", ts.c_str());
            if (timedOut)
                fwprintf(logFile, L"[%s] TIMEOUT: killed after %lu seconds\n", ts.c_str(), timeoutSec);
            fwprintf(logFile, L"[%s] Exit code: %ld (0x%08X)\n", ts.c_str(), (long)exitCode, exitCode);
            fwprintf(logFile, L"[%s] === Log end ===\n", ts.c_str());
            _commit(_fileno(logFile));  // ensure summary is on disk
            ReleaseSRWLockExclusive(&lock);
        }

        bool IsActive() const { return active; }
        ~SandyLogger() { Stop(); }
    };

    inline SandyLogger g_logger;

} // namespace Sandbox
