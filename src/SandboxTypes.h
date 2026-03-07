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
        CoCreateGuid(&guid);
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
        std::wstring workdir;                              // [sandbox] workdir (optional)
        std::vector<FolderEntry> folders;
        std::vector<FolderEntry> denyFolders;  // [deny] — DENY ACEs

        // [privileges] — sandbox capabilities (all keys mandatory per mode)
        bool allowNetwork    = false;
        bool allowLocalhost  = false;
        bool allowLan        = false;
        bool allowSystemDirs = false;
        bool allowNamedPipes  = false;  // restricted mode: controls named pipe creation

        // stdin control: "NUL" = disabled, empty/true = inherit, path = file
        std::wstring stdinMode = L"NUL";
        bool allowClipboardRead  = false;
        bool allowClipboardWrite = false;
        bool allowChildProcesses = false;

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
                f = _wfsopen(finalPath.c_str(), L"w", _SH_DENYWR);
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

        void LogConfig(const SandboxConfig& config, const std::wstring& exe,
                       const std::wstring& args) {
            if (!active) return;
            AcquireSRWLockExclusive(&lock);
            auto ts = Timestamp();
            fwprintf(logFile, L"[%s] --- Configuration ---\n", ts.c_str());
            fwprintf(logFile, L"[%s] Executable: %s\n", ts.c_str(), exe.c_str());
            if (!args.empty())
                fwprintf(logFile, L"[%s] Arguments:  %s\n", ts.c_str(), args.c_str());

            fwprintf(logFile, L"[%s] Folders:    %zu configured\n", ts.c_str(), config.folders.size());
            for (size_t i = 0; i < config.folders.size(); i++) {
                fwprintf(logFile, L"[%s]   [%s]  %s\n", ts.c_str(),
                         AccessTag(config.folders[i].access), config.folders[i].path.c_str());
            }

            if (config.allowSystemDirs) fwprintf(logFile, L"[%s] System dirs: allowed\n", ts.c_str());
            if (config.allowNetwork)    fwprintf(logFile, L"[%s] Network:     allowed\n", ts.c_str());
            if (config.allowLocalhost)  fwprintf(logFile, L"[%s] Localhost:   allowed\n", ts.c_str());
            if (config.allowLan)        fwprintf(logFile, L"[%s] LAN:         allowed\n", ts.c_str());

            if (!config.stdinMode.empty()) {
                if (_wcsicmp(config.stdinMode.c_str(), L"NUL") == 0)
                    fwprintf(logFile, L"[%s] Stdin:       disabled (NUL)\n", ts.c_str());
                else
                    fwprintf(logFile, L"[%s] Stdin:       %s\n", ts.c_str(), config.stdinMode.c_str());
            }
            if (!config.envInherit)     fwprintf(logFile, L"[%s] Env:         filtered (%zu pass vars)\n", ts.c_str(), config.envPass.size());
            if (config.allowNamedPipes) fwprintf(logFile, L"[%s] Named Pipes: allowed\n", ts.c_str());
            fwprintf(logFile, L"[%s] Clipboard:   read=%s write=%s\n", ts.c_str(),
                     config.allowClipboardRead ? L"yes" : L"no",
                     config.allowClipboardWrite ? L"yes" : L"no");
            fwprintf(logFile, L"[%s] Children:    %s\n", ts.c_str(),
                     config.allowChildProcesses ? L"allowed" : L"blocked");
            if (!config.denyFolders.empty()) {
                fwprintf(logFile, L"[%s] Deny:        %zu configured\n", ts.c_str(), config.denyFolders.size());
                for (const auto& d : config.denyFolders)
                    fwprintf(logFile, L"[%s]   [%s]  %s\n", ts.c_str(), AccessTag(d.access), d.path.c_str());
            }
            if (!config.registryRead.empty() || !config.registryWrite.empty()) {
                fwprintf(logFile, L"[%s] Registry:    %zu keys\n", ts.c_str(),
                         config.registryRead.size() + config.registryWrite.size());
                for (const auto& k : config.registryRead)
                    fwprintf(logFile, L"[%s]   [R]  %s\n", ts.c_str(), k.c_str());
                for (const auto& k : config.registryWrite)
                    fwprintf(logFile, L"[%s]   [W]  %s\n", ts.c_str(), k.c_str());
            }
            if (config.timeoutSeconds)  fwprintf(logFile, L"[%s] Timeout:     %lu seconds\n", ts.c_str(), config.timeoutSeconds);
            if (config.memoryLimitMB)   fwprintf(logFile, L"[%s] Memory:      %zu MB\n", ts.c_str(), config.memoryLimitMB);
            if (config.maxProcesses)    fwprintf(logFile, L"[%s] Processes:   %lu max\n", ts.c_str(), config.maxProcesses);

            fwprintf(logFile, L"[%s] --- Process Output ---\n", ts.c_str());
            _commit(_fileno(logFile));
            ReleaseSRWLockExclusive(&lock);
        }

        void LogOutput(const char* data, DWORD len) {
            if (!active || !data || len == 0) return;
            AcquireSRWLockExclusive(&lock);
            fwrite(data, 1, len, logFile);
            _commit(_fileno(logFile));  // fsync: flush OS cache to disk (power-loss safe)
            ReleaseSRWLockExclusive(&lock);
        }

        void Log(const wchar_t* msg) {
            if (!active) return;
            AcquireSRWLockExclusive(&lock);
            fwprintf(logFile, L"[%s] %s\n", Timestamp().c_str(), msg);
            _commit(_fileno(logFile));
            ReleaseSRWLockExclusive(&lock);
        }

        // Formatted log — dynamically sizes the buffer when needed.
        // Falls back to a fixed stack buffer for the common case, but avoids
        // silent detail loss for larger diagnostics.
        void LogFmt(const wchar_t* fmt, ...) {
            if (!active) return;

            wchar_t stackBuf[1024];
            va_list args;
            va_start(args, fmt);
            va_list argsCopy;
            va_copy(argsCopy, args);

            int needed = _vscwprintf(fmt, argsCopy);
            va_end(argsCopy);

            if (needed < 0) {
                va_end(args);
                truncatedCount++;
                Log(L"LOG_DIAG: formatting failure in LogFmt");
                return;
            }

            const size_t required = static_cast<size_t>(needed) + 1;
            if (required <= _countof(stackBuf)) {
                _vsnwprintf_s(stackBuf, _countof(stackBuf), _TRUNCATE, fmt, args);
                stackBuf[_countof(stackBuf) - 1] = L'\0';
                va_end(args);
                Log(stackBuf);
                return;
            }

            std::vector<wchar_t> dynamicBuf(required);
            int written = _vsnwprintf_s(dynamicBuf.data(), dynamicBuf.size(), _TRUNCATE, fmt, args);
            va_end(args);
            if (written < 0) {
                truncatedCount++;
                Log(L"LOG_DIAG: dynamic formatting truncated unexpectedly");
                return;
            }
            dynamicBuf.back() = L'\0';
            Log(dynamicBuf.data());
        }

        void LogSummary(DWORD exitCode, bool timedOut, DWORD timeoutSec) {
            if (!active) return;
            AcquireSRWLockExclusive(&lock);
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
