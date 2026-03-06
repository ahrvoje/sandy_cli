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
        RegSetValueExW(hKey, valueName, 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(exeName.c_str()),
                       static_cast<DWORD>((exeName.size() + 1) * sizeof(wchar_t)));
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
        // Try to remove parent key if empty
        RegDeleteKeyW(HKEY_CURRENT_USER, kWERParentKey);
    }

    // Enumerate all persisted WER entries and clean them
    inline void RestoreStaleWER()
    {
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kWERParentKey, 0,
                          KEY_READ, &hKey) != ERROR_SUCCESS)
            return;

        DWORD valueCount = 0;
        RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                         &valueCount, nullptr, nullptr, nullptr, nullptr);

        // Collect all entries first (value name = PID, data = exe basename)
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

        // Clean each WER key and delete the registry entry
        for (const auto& entry : entries) {
            if (!entry.second.empty()) {
                DisableCrashDumps(entry.second);
                g_logger.Log((L"WER_RESTORE: " + entry.second).c_str());
            }
        }

        // Delete the entire WER parent key
        RegDeleteKeyW(HKEY_CURRENT_USER, kWERParentKey);
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
    // If auditLogPath is set, copies the dump next to it (audit.log -> audit.dmp).
    inline std::wstring ReportCrashDump(const std::wstring& exeName,
                                         const std::wstring& auditLogPath)
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

        std::wstring bestName;
        FILETIME bestTime = {};
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                if (CompareFileTime(&fd.ftLastWriteTime, &bestTime) > 0) {
                    bestTime = fd.ftLastWriteTime;
                    bestName = fd.cFileName;
                }
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);

        if (bestName.empty()) return L"";

        std::wstring srcPath = dumpDir + L"\\" + bestName;

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
