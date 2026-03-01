// =========================================================================
// SandboxTypes.h — Sandbox types, configuration, and session logger
//
// Contains foundational types (AccessLevel, FolderEntry, SandboxConfig)
// and the SandyLogger used for session logging.
// =========================================================================
#pragma once

#include "framework.h"
#include <string>
#include <vector>
#include <cstdio>

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
        bool allowClipboardRead  = true;   // default: allow clipboard reading
        bool allowClipboardWrite = true;   // default: allow clipboard writing
        bool allowChildProcesses = true;   // default: allow child process creation

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
            for (size_t i = 0; i < config.folders.size(); i++) {
                fwprintf(f, L"[%s]   [%s]  %s\n", ts.c_str(),
                         AccessTag(config.folders[i].access), config.folders[i].path.c_str());
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

} // namespace Sandbox
