// =========================================================================
// SandboxCrashDump.h — WER crash dump helpers and stale WER recovery
//
// Configures Windows Error Reporting to write minidumps on crash,
// persists WER state to registry for crash recovery, and detects
// crash exit codes.
// =========================================================================
#pragma once

#pragma warning(push)
#pragma warning(disable: 4996) // _wfopen, etc.

#include "framework.h"
#include "SandboxTypes.h"

namespace Sandbox {

    // -----------------------------------------------------------------------
    // WER crash dump helpers — configures Windows Error Reporting to write
    // a minidump when the sandboxed process crashes.
    // -----------------------------------------------------------------------

    // Enable WER LocalDumps for a specific executable name.
    // Uses the default %LOCALAPPDATA%\CrashDumps folder.
    inline bool EnableCrashDumps(const std::wstring& exeName)
    {
        std::wstring keyPath = L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\" + exeName;
        HKEY hKey = nullptr;
        DWORD disp = 0;
        LONG rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, nullptr,
                                   REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hKey, &disp);
        if (rc != ERROR_SUCCESS) return false;

        // DumpType = 1 (MiniDump with thread/stack info, ~256KB)
        DWORD dumpType = 1;
        RegSetValueExW(hKey, L"DumpType", 0, REG_DWORD, (const BYTE*)&dumpType, sizeof(dumpType));

        // DumpCount = 3
        DWORD dumpCount = 3;
        RegSetValueExW(hKey, L"DumpCount", 0, REG_DWORD, (const BYTE*)&dumpCount, sizeof(dumpCount));

        RegCloseKey(hKey);
        return true;
    }

    // Remove the WER LocalDumps registry key for a specific executable.
    inline void DisableCrashDumps(const std::wstring& exeName)
    {
        std::wstring keyPath = L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\" + exeName;
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, keyPath.c_str());
    }


    // -----------------------------------------------------------------------
    // WER state persistence — allow all cleanup paths to revert WER keys
    // Stores exe basename under HKCU\Software\Sandy\WER (PID as value name)
    // -----------------------------------------------------------------------
    static const wchar_t* kWERParentKey = L"Software\\Sandy\\WER";

    inline void PersistWERExeName(const std::wstring& exeName)
    {
        HKEY hKey = nullptr;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, kWERParentKey, 0, nullptr,
                0, KEY_SET_VALUE, nullptr, &hKey, nullptr) != ERROR_SUCCESS)
            return;
        wchar_t valueName[32];
        swprintf(valueName, 32, L"%lu", GetCurrentProcessId());
        // F5/R8: Persist exeName|ctime for PID-reuse-safe liveness checks
        ULONGLONG ct = GetCurrentProcessCreationTime();
        wchar_t ctBuf[32];
        swprintf(ctBuf, 32, L"%llu", ct);
        std::wstring data = exeName + L"|" + ctBuf;
        RegSetValueExW(hKey, valueName, 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(data.c_str()),
                       static_cast<DWORD>((data.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }

    inline void ClearWERExeName()
    {
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kWERParentKey, 0,
                          KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
            return;
        wchar_t valueName[32];
        swprintf(valueName, 32, L"%lu", GetCurrentProcessId());
        RegDeleteValueW(hKey, valueName);
        RegCloseKey(hKey);
        // Parent key (Software\Sandy\WER) is permanent — never delete it
    }

    // -----------------------------------------------------------------------
    // ParseWEREntry — parse WER value data.
    //
    // F5/R8: Handles both new "exeName|ctime" and legacy "exeName" formats.
    // -----------------------------------------------------------------------
    inline void ParseWEREntry(const std::wstring& data,
                               std::wstring& outExeName, ULONGLONG& outCtime)
    {
        auto pipe = data.find(L'|');
        if (pipe != std::wstring::npos) {
            outExeName = data.substr(0, pipe);
            outCtime = _wcstoui64(data.c_str() + pipe + 1, nullptr, 10);
        } else {
            outExeName = data;
            outCtime = 0;  // legacy entry — no ctime available
        }
    }

    // -----------------------------------------------------------------------
    // CountLiveWERReferences — count how many live Sandy instances are
    // tracking a given executable name under HKCU\Software\Sandy\WER.
    //
    // Used for reference-counted WER cleanup: only delete the shared HKLM
    // LocalDumps key when the last Sandy owner for that exe exits.
    //
    // F5/R8: Uses creation time from value data for PID-reuse-safe checks.
    // excludePid: PID to exclude from the count (typically our own).
    // -----------------------------------------------------------------------
    inline int CountLiveWERReferences(const std::wstring& exeName, DWORD excludePid = 0)
    {
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kWERParentKey, 0,
                          KEY_READ, &hKey) != ERROR_SUCCESS)
            return 0;

        DWORD valueCount = 0;
        RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                         &valueCount, nullptr, nullptr, nullptr, nullptr);

        int count = 0;
        for (DWORD i = 0; i < valueCount; i++) {
            wchar_t name[64]; DWORD nameLen = 64;
            DWORD dataSize = 0;
            if (RegEnumValueW(hKey, i, name, &nameLen, nullptr, nullptr,
                              nullptr, &dataSize) != ERROR_SUCCESS)
                continue;
            DWORD pid = (DWORD)_wtoi(name);
            if (pid == excludePid) continue;

            // Read value data
            std::wstring data(dataSize / sizeof(wchar_t), L'\0');
            nameLen = 64;
            if (RegEnumValueW(hKey, i, name, &nameLen, nullptr, nullptr,
                              reinterpret_cast<BYTE*>(&data[0]), &dataSize) == ERROR_SUCCESS) {
                while (!data.empty() && data.back() == L'\0') data.pop_back();

                // F5/R8: Parse exeName|ctime and use ctime for liveness check
                std::wstring entryExe; ULONGLONG entryCtime = 0;
                ParseWEREntry(data, entryExe, entryCtime);

                if (!IsProcessAlive(pid, entryCtime)) continue;
                if (_wcsicmp(entryExe.c_str(), exeName.c_str()) == 0)
                    count++;
            }
        }
        RegCloseKey(hKey);
        return count;
    }

    // Enumerate persisted WER entries and clean only dead-PID ones.
    // Parent key (Software\Sandy\WER) is permanent — never deleted.
    inline void RestoreStaleWER()
    {
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kWERParentKey, 0,
                          KEY_READ, &hKey) != ERROR_SUCCESS)
            return;

        DWORD valueCount = 0;
        RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                         &valueCount, nullptr, nullptr, nullptr, nullptr);

        // Collect all entries first (value name = PID, data = exe basename|ctime)
        std::vector<std::pair<std::wstring, std::wstring>> entries;
        for (DWORD i = 0; i < valueCount; i++) {
            wchar_t name[64];
            DWORD nameLen = 64;
            DWORD dataSize = 0;
            if (RegEnumValueW(hKey, i, name, &nameLen, nullptr, nullptr, nullptr, &dataSize) == ERROR_SUCCESS) {
                std::wstring data(dataSize / sizeof(wchar_t), L'\0');
                nameLen = 64;  // reset — RegEnumValueW modifies it
                if (RegEnumValueW(hKey, i, name, &nameLen, nullptr, nullptr,
                                  reinterpret_cast<BYTE*>(&data[0]), &dataSize) == ERROR_SUCCESS) {
                    while (!data.empty() && data.back() == L'\0') data.pop_back();
                    entries.push_back({ name, data });
                }
            }
        }
        RegCloseKey(hKey);

        // Collect stale entries and count live references per exe
        // Only delete the HKLM LocalDumps key when no live instance tracks the same exe
        std::vector<std::wstring> toDelete;
        for (const auto& entry : entries) {
            DWORD pid = (DWORD)_wtoi(entry.first.c_str());
            // F5/R8: Parse exeName|ctime from value data
            std::wstring exeName; ULONGLONG entryCtime = 0;
            ParseWEREntry(entry.second, exeName, entryCtime);
            if (IsProcessAlive(pid, entryCtime)) continue;  // skip live instances

            if (!exeName.empty()) {
                // Check if any other live Sandy instance still tracks this exe
                int liveRefs = CountLiveWERReferences(exeName, pid);
                if (liveRefs == 0) {
                    DisableCrashDumps(exeName);
                    g_logger.Log((L"WER_RESTORE: " + exeName + L" (last owner)").c_str());
                } else {
                    g_logger.LogFmt(L"WER_RESTORE: %ls SKIPPED (%d live owner(s) remain)",
                                    exeName.c_str(), liveRefs);
                }
                printf("  [WER]  PID %ls crash dumps for %ls -> cleaned\n",
                       entry.first.c_str(), exeName.c_str());
            }
            toDelete.push_back(entry.first);
        }

        // Delete only stale PID values from the WER key
        if (!toDelete.empty()) {
            if (RegOpenKeyExW(HKEY_CURRENT_USER, kWERParentKey, 0,
                              KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                for (const auto& name : toDelete)
                    RegDeleteValueW(hKey, name.c_str());
                RegCloseKey(hKey);
            }
        }
    }

    // Check if exit code looks like a native crash.
    // Covers NTSTATUS codes (0xC000xxxx) and C runtime abort() (exit code 3).
    inline bool IsCrashExitCode(DWORD exitCode)
    {
        if ((exitCode & 0xF0000000) == 0xC0000000) return true;  // NTSTATUS
        if (exitCode == 3) return true;                           // abort()
        return false;
    }

    // Find a crash dump in %LOCALAPPDATA%\CrashDumps matching exeName.
    // Prefers a PID-specific match (e.g. "python.exe.1234.dmp") to avoid
    // misattribution in concurrent same-exe runs.  Falls back to newest
    // file matching the exe name if no PID-specific dump is found.
    // If auditLogPath is set, copies the dump next to it (audit.log -> audit.dmp).
    inline std::wstring ReportCrashDump(const std::wstring& exeName,
                                         const std::wstring& auditLogPath,
                                         DWORD childPid = 0)
    {
        wchar_t localAppData[MAX_PATH];
        if (!GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH))
            return L"";
        std::wstring dumpDir = std::wstring(localAppData) + L"\\CrashDumps";

        // Search for <exeName>*.dmp (e.g. "python.exe.1234.dmp")
        std::wstring pattern = dumpDir + L"\\" + exeName + L"*.dmp";
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
        if (hFind == INVALID_HANDLE_VALUE) return L"";

        // Build PID-specific substring for priority matching
        std::wstring pidToken;
        if (childPid != 0) {
            wchar_t pidBuf[32];
            swprintf(pidBuf, 32, L".%lu.", childPid);
            pidToken = pidBuf;
        }

        std::wstring pidMatch;     // PID-specific match (preferred)
        std::wstring bestName;     // newest file fallback
        FILETIME bestTime = {};
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

            // Check for PID-specific match first
            if (!pidToken.empty() && pidMatch.empty()) {
                if (wcsstr(fd.cFileName, pidToken.c_str()) != nullptr)
                    pidMatch = fd.cFileName;
            }
            // Track newest file as fallback
            if (CompareFileTime(&fd.ftLastWriteTime, &bestTime) > 0) {
                bestTime = fd.ftLastWriteTime;
                bestName = fd.cFileName;
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);

        // Prefer PID-specific match, fall back to newest
        std::wstring chosen = !pidMatch.empty() ? pidMatch : bestName;
        if (chosen.empty()) return L"";

        std::wstring srcPath = dumpDir + L"\\" + chosen;

        // Copy dump next to the audit log (audit.log -> audit.dmp)
        std::wstring dstPath;
        if (!auditLogPath.empty()) {
            dstPath = auditLogPath;
            auto dot = dstPath.rfind(L'.');
            if (dot != std::wstring::npos)
                dstPath = dstPath.substr(0, dot);
            dstPath += L".dmp";
            CopyFileW(srcPath.c_str(), dstPath.c_str(), FALSE);
        } else {
            dstPath = srcPath;
        }

        return dstPath;
    }

} // namespace Sandbox

#pragma warning(pop)
