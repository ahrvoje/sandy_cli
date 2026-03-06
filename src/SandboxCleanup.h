// =========================================================================
// SandboxCleanup.h — Loopback, scheduled task, and stale state recovery
//
// Self-contained utilities for managing sandbox lifecycle: loopback
// exemptions, crash-resilience tasks, stale state detection and cleanup.
// Each function is an independently testable semantic unit.
// =========================================================================
#pragma once

#include "SandboxTypes.h"
#include "SandboxProcess.h"

namespace Sandbox {

    // Track loopback state for cleanup
    inline bool g_loopbackGranted = false;

    // -----------------------------------------------------------------------
    // Startup task — safety net for crash/power-loss scenarios.
    // Each instance creates its own task: SandyCleanup_<uuid>.
    // Deleted on clean exit; stale tasks cleaned by --cleanup.
    // -----------------------------------------------------------------------
    constexpr const wchar_t* kCleanupTaskPrefix = L"SandyCleanup_";

    inline std::wstring CleanupTaskName(const std::wstring& instanceId)
    {
        return kCleanupTaskPrefix + instanceId;
    }

    // -----------------------------------------------------------------------
    // CreateCleanupTask — register a per-instance scheduled task.
    //
    // Inputs:  instanceId — this instance's UUID
    // Effect:  creates SandyCleanup_<uuid> logon task
    // -----------------------------------------------------------------------
    inline void CreateCleanupTask(const std::wstring& instanceId)
    {
        wchar_t exePath[MAX_PATH];
        if (!GetModuleFileNameW(nullptr, exePath, MAX_PATH)) return;

        std::wstring taskName = CleanupTaskName(instanceId);
        std::wstring args = L"/Create /TN \"";
        args += taskName;
        args += L"\" /TR \"\\\"";
        args += exePath;
        args += L"\\\" --cleanup\" /SC ONLOGON /F /RL HIGHEST";

        if (RunSchtasks(args) == 0) {
            g_logger.Log((L"SCHTASK: created " + taskName).c_str());
        }
    }

    // -----------------------------------------------------------------------
    // DeleteCleanupTask — remove this instance's scheduled task.
    //
    // Inputs:  instanceId — this instance's UUID
    // Effect:  deletes SandyCleanup_<uuid> unconditionally
    // -----------------------------------------------------------------------
    inline void DeleteCleanupTask(const std::wstring& instanceId)
    {
        std::wstring taskName = CleanupTaskName(instanceId);
        std::wstring args = L"/Delete /TN \"";
        args += taskName;
        args += L"\" /F";

        if (RunSchtasks(args) == 0) {
            g_logger.Log((L"SCHTASK: deleted " + taskName).c_str());
        }
    }

    // -----------------------------------------------------------------------
    // DeleteStaleCleanupTasks — remove tasks from dead instances.
    //
    // Lists all SandyCleanup_* tasks via schtasks, extracts instance IDs,
    // and deletes tasks whose instance has no live grants registry entry.
    // Called by --cleanup and RestoreStaleGrants.
    // -----------------------------------------------------------------------
    inline void DeleteStaleCleanupTasks()
    {
        // Query all tasks matching our prefix
        // schtasks /Query /FO CSV /NH gives: "TaskName","Next Run Time","Status"
        std::wstring cmd = L"schtasks.exe /Query /FO CSV /NH";
        HANDLE hRead = nullptr, hWrite = nullptr;
        SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
        if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return;

        STARTUPINFOW si = { sizeof(si) };
        si.hStdOutput = hWrite;
        si.hStdError = hWrite;
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi{};
        if (!CreateProcessW(nullptr, const_cast<LPWSTR>(cmd.c_str()),
                nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            CloseHandle(hRead);
            CloseHandle(hWrite);
            return;
        }
        CloseHandle(hWrite);

        // Read output
        std::string output;
        char buf[4096];
        DWORD bytesRead;
        while (ReadFile(hRead, buf, sizeof(buf), &bytesRead, nullptr) && bytesRead > 0)
            output.append(buf, bytesRead);
        CloseHandle(hRead);
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        // Parse CSV lines for SandyCleanup_ prefix
        std::wstring prefix = kCleanupTaskPrefix;
        std::istringstream stream(output);
        std::string line;
        while (std::getline(stream, line)) {
            // Find SandyCleanup_ in the line
            // CSV format: "\TaskFolder\SandyCleanup_uuid",...
            std::wstring wline(line.begin(), line.end());
            auto pos = wline.find(prefix);
            if (pos == std::wstring::npos) continue;

            // Extract instance ID: from after prefix to next quote
            auto idStart = pos + prefix.size();
            auto idEnd = wline.find(L'"', idStart);
            if (idEnd == std::wstring::npos) idEnd = wline.size();
            std::wstring instanceId = wline.substr(idStart, idEnd - idStart);
            if (instanceId.empty()) continue;

            // Check if this instance has live grants
            std::wstring regKey = std::wstring(kGrantsParentKey) + L"\\" + instanceId;
            HKEY hKey = nullptr;
            bool isLive = false;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, regKey.c_str(), 0,
                              KEY_READ, &hKey) == ERROR_SUCCESS) {
                DWORD pid = 0; ULONGLONG ctime = 0;
                ReadPidAndCtime(hKey, pid, ctime);
                isLive = IsProcessAlive(pid, ctime);
                RegCloseKey(hKey);
            }

            if (!isLive) {
                std::wstring taskName = prefix + instanceId;
                std::wstring delArgs = L"/Delete /TN \"" + taskName + L"\" /F";
                if (RunSchtasks(delArgs) == 0) {
                    g_logger.Log((L"SCHTASK_STALE: deleted " + taskName).c_str());
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // EnableLoopback — add localhost exemption for AppContainer.
    //
    // Inputs:  (none — uses SandySandbox moniker)
    // Returns: true if exemption was added
    // Verifiable: "CheckNetIsolation LoopbackExempt -s" lists SandySandbox
    // -----------------------------------------------------------------------
    inline bool EnableLoopback()
    {
        DWORD exitCode = RunHiddenProcess(
            L"CheckNetIsolation.exe LoopbackExempt -a -n=SandySandbox");
        g_loopbackGranted = (exitCode == 0);
        return g_loopbackGranted;
    }

    // -----------------------------------------------------------------------
    // DisableLoopback — remove localhost exemption (only if we granted it).
    //
    // Inputs:  (none — checks g_loopbackGranted flag)
    // Effect:  removes SandySandbox from loopback exemption list
    // Verifiable: exemption no longer appears in CheckNetIsolation -s
    // -----------------------------------------------------------------------
    inline void DisableLoopback() {
        if (!g_loopbackGranted) return;
        g_logger.Log(L"LOOPBACK: disabling");
        RunHiddenProcess(L"CheckNetIsolation.exe LoopbackExempt -d -n=SandySandbox");
        g_loopbackGranted = false;
    }

    // -----------------------------------------------------------------------
    // ForceDisableLoopback — unconditional exemption removal for startup.
    //
    // Inputs:  (none)
    // Effect:  removes SandySandbox regardless of g_loopbackGranted state
    // Verifiable: exemption is absent after call
    // -----------------------------------------------------------------------
    inline void ForceDisableLoopback()
    {
        RunHiddenProcess(L"CheckNetIsolation.exe LoopbackExempt -d -n=SandySandbox");
        g_logger.Log(L"LOOPBACK: force-disabled (stale cleanup)");
    }

    // -----------------------------------------------------------------------
    // CleanupStaleStartupState — clear non-instance-specific stale state.
    //
    // Cleans loopback exemptions and stale WER keys for the target exe.
    // Safe to call during concurrent use (does not touch instance grants).
    //
    // Inputs:  exePath — target executable path (for WER key matching)
    // Effect:  loopback exemption removed, stale WER key for target cleaned
    // Verifiable: no stale loopback/WER entries remain for this exe
    // -----------------------------------------------------------------------
    inline void CleanupStaleStartupState(const std::wstring& exePath)
    {
        ForceDisableLoopback();

        // Clean stale WER key for the current target exe if Sandy left it
        auto slash = exePath.find_last_of(L"\\/");
        std::wstring exeBaseName = (slash != std::wstring::npos) ? exePath.substr(slash + 1) : exePath;
        {
            HKEY hWER = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, kWERParentKey, 0,
                              KEY_READ, &hWER) == ERROR_SUCCESS) {
                DWORD valueCount = 0;
                RegQueryInfoKeyW(hWER, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                                 &valueCount, nullptr, nullptr, nullptr, nullptr);
                bool foundStale = false;
                for (DWORD i = 0; i < valueCount && !foundStale; i++) {
                    wchar_t vname[64]; DWORD vnameLen = 64;
                    DWORD dataSize = 0;
                    if (RegEnumValueW(hWER, i, vname, &vnameLen, nullptr, nullptr,
                                      nullptr, &dataSize) == ERROR_SUCCESS) {
                        std::wstring data(dataSize / sizeof(wchar_t), L'\0');
                        vnameLen = 64;
                        if (RegEnumValueW(hWER, i, vname, &vnameLen, nullptr, nullptr,
                                          reinterpret_cast<BYTE*>(&data[0]), &dataSize) == ERROR_SUCCESS) {
                            while (!data.empty() && data.back() == L'\0') data.pop_back();
                            if (_wcsicmp(data.c_str(), exeBaseName.c_str()) == 0)
                                foundStale = true;
                        }
                    }
                }
                RegCloseKey(hWER);
                if (foundStale)
                    DisableCrashDumps(exeBaseName);
            }
        }
        g_logger.Log(L"STARTUP_CLEANUP: cleared stale AppContainer/loopback/WER state");
    }

    // -----------------------------------------------------------------------
    // WarnStaleRegistryEntries — detect and warn about stale registry state.
    //
    // Inputs:  (none — reads HKCU\Software\Sandy\Grants and \WER)
    // Effect:  prints warning to stderr and logs if stale entries found
    // Verifiable: warning printed iff stale keys exist in registry
    // -----------------------------------------------------------------------
    inline void WarnStaleRegistryEntries()
    {
        bool staleGrants = false, staleWER = false;
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kGrantsParentKey, 0,
                          KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD subKeyCount = 0;
            RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, &subKeyCount,
                             nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
            RegCloseKey(hKey);
            if (subKeyCount > 0) staleGrants = true;
        }
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kWERParentKey, 0,
                          KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD valueCount = 0;
            RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                             &valueCount, nullptr, nullptr, nullptr, nullptr);
            RegCloseKey(hKey);
            if (valueCount > 0) staleWER = true;
        }
        if (staleGrants || staleWER) {
            if (!g_logger.IsActive())
                fprintf(stderr,
                    "[Sandy] WARNING: Stale registry entries detected from a previous crashed run.\n"
                    "        Grants: HKCU\\%ls   WER: HKCU\\%ls\n"
                    "        Run 'sandy.exe --cleanup' to restore original state.\n"
                    "        If another sandy instance is running, its entries are expected.\n",
                    kGrantsParentKey, kWERParentKey);
            g_logger.Log(L"STARTUP_WARNING: stale registry entries found (use --cleanup)");
        }
    }

    // -----------------------------------------------------------------------
    // LogSandyIdentity — log the current process PID and integrity level.
    //
    // Inputs:  (none — queries current process token)
    // Effect:  logs PID and integrity level for forensic analysis
    // Verifiable: log contains correct PID and integrity level
    // -----------------------------------------------------------------------
    inline void LogSandyIdentity()
    {
        g_logger.LogFmt(L"SANDY: PID %lu", GetCurrentProcessId());

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
                    g_logger.LogFmt(L"SANDY: integrity=%s (0x%04X)", ilName, il);
                }
            }
            CloseHandle(hToken);
        }
    }

} // namespace Sandbox
