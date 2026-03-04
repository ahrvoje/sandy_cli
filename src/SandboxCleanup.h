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
    // Creates a schtask that runs "sandy.exe" (cleanup-only) at next logon.
    // Deleted on clean exit so it only fires if sandy didn't get to clean up.
    // -----------------------------------------------------------------------
    constexpr const wchar_t* kCleanupTaskName = L"SandyCleanup";

    // -----------------------------------------------------------------------
    // CreateCleanupTask — register a scheduled task for crash recovery.
    //
    // Inputs:  (none — uses current exe path)
    // Effect:  creates SandyCleanup logon task pointing to current exe
    // Verifiable: task appears in "schtasks /Query /TN SandyCleanup"
    // -----------------------------------------------------------------------
    inline void CreateCleanupTask()
    {
        wchar_t exePath[MAX_PATH];
        if (!GetModuleFileNameW(nullptr, exePath, MAX_PATH)) return;

        std::wstring args = L"/Create /TN \"";
        args += kCleanupTaskName;
        args += L"\" /TR \"\\\"";
        args += exePath;
        args += L"\\\" --cleanup\" /SC ONLOGON /F /RL HIGHEST";

        if (RunSchtasks(args) == 0) {
            g_logger.Log(L"SCHTASK: created SandyCleanup (logon trigger)");
        }
    }

    // -----------------------------------------------------------------------
    // DeleteCleanupTask — remove the crash-recovery scheduled task.
    //
    // Inputs:  (none)
    // Effect:  deletes task only if no other instances have pending grants
    // Verifiable: task no longer appears in schtasks /Query
    // -----------------------------------------------------------------------
    inline void DeleteCleanupTask()
    {
        // Only delete the task if no other instances have pending grants.
        HKEY hParent = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kGrantsParentKey, 0,
                          KEY_READ, &hParent) == ERROR_SUCCESS) {
            DWORD subKeyCount = 0;
            RegQueryInfoKeyW(hParent, nullptr, nullptr, nullptr, &subKeyCount,
                             nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
            RegCloseKey(hParent);
            if (subKeyCount > 0) {
                g_logger.Log(L"SCHTASK: kept SandyCleanup (other instances have pending grants)");
                return;
            }
        }

        std::wstring args = L"/Delete /TN \"";
        args += kCleanupTaskName;
        args += L"\" /F";

        if (RunSchtasks(args) == 0) {
            g_logger.Log(L"SCHTASK: deleted SandyCleanup");
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

} // namespace Sandbox
