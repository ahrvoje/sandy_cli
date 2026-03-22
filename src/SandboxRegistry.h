// =========================================================================
// SandboxRegistry.h — Generic registry read/write utilities
//
// Low-level helpers for REG_SZ, REG_DWORD, and enumeration access.
// Shared by grant tracking (SandboxGrants.h) and profile persistence
// (SandboxSavedProfile.h).
// =========================================================================
#pragma once

#include <windows.h>
#include <string>

namespace Sandbox {

    // -----------------------------------------------------------------------
    // REG_SZ helpers
    // -----------------------------------------------------------------------
    inline void WriteRegSz(HKEY hKey, const wchar_t* name, const std::wstring& val)
    {
        RegSetValueExW(hKey, name, 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(val.c_str()),
                       static_cast<DWORD>((val.size() + 1) * sizeof(wchar_t)));
    }

    inline bool TryWriteRegSz(HKEY hKey, const wchar_t* name, const std::wstring& val)
    {
        return RegSetValueExW(hKey, name, 0, REG_SZ,
                              reinterpret_cast<const BYTE*>(val.c_str()),
                              static_cast<DWORD>((val.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
    }

    inline std::wstring ReadRegSz(HKEY hKey, const wchar_t* name)
    {
        DWORD size = 0, type = 0;
        if (RegQueryValueExW(hKey, name, nullptr, &type, nullptr, &size) != ERROR_SUCCESS)
            return {};
        if (type != REG_SZ && type != REG_EXPAND_SZ)
            return {};
        if (size < sizeof(wchar_t))
            return {};
        std::wstring val(size / sizeof(wchar_t), L'\0');
        if (RegQueryValueExW(hKey, name, nullptr, nullptr,
                         reinterpret_cast<BYTE*>(&val[0]), &size) != ERROR_SUCCESS)
            return {};
        while (!val.empty() && val.back() == L'\0') val.pop_back();
        return val;
    }

    // -----------------------------------------------------------------------
    // REG_DWORD helpers
    // -----------------------------------------------------------------------
    inline void WriteRegDword(HKEY hKey, const wchar_t* name, DWORD val)
    {
        RegSetValueExW(hKey, name, 0, REG_DWORD,
                       reinterpret_cast<const BYTE*>(&val), sizeof(DWORD));
    }

    inline bool TryWriteRegDword(HKEY hKey, const wchar_t* name, DWORD val)
    {
        return RegSetValueExW(hKey, name, 0, REG_DWORD,
                              reinterpret_cast<const BYTE*>(&val), sizeof(DWORD)) == ERROR_SUCCESS;
    }

    inline bool TryWriteRegQword(HKEY hKey, const wchar_t* name, ULONGLONG val)
    {
        return RegSetValueExW(hKey, name, 0, REG_QWORD,
                              reinterpret_cast<const BYTE*>(&val), sizeof(ULONGLONG)) == ERROR_SUCCESS;
    }

    inline DWORD ReadRegDword(HKEY hKey, const wchar_t* name, DWORD defaultVal = 0)
    {
        DWORD val = 0, size = sizeof(val), type = 0;
        if (RegQueryValueExW(hKey, name, nullptr, &type,
                             reinterpret_cast<BYTE*>(&val), &size) != ERROR_SUCCESS)
            return defaultVal;
        if (type != REG_DWORD)
            return defaultVal;
        return val;
    }

    inline bool TryReadRegDword(HKEY hKey, const wchar_t* name, DWORD& out)
    {
        DWORD size = sizeof(out), type = 0;
        return RegQueryValueExW(hKey, name, nullptr, &type,
                                reinterpret_cast<BYTE*>(&out), &size) == ERROR_SUCCESS
            && type == REG_DWORD;
    }

    // -----------------------------------------------------------------------
    // REG_SZ enumeration — read value by index, skipping metadata ('_' prefix)
    // -----------------------------------------------------------------------
    inline bool ReadRegSzEnum(HKEY hKey, DWORD index,
                              std::wstring& name, std::wstring& data)
    {
        wchar_t vname[64];
        DWORD vnameLen = 64;
        DWORD dataSize = 0, dataType = 0;
        if (RegEnumValueW(hKey, index, vname, &vnameLen, nullptr, &dataType,
                          nullptr, &dataSize) != ERROR_SUCCESS)
            return false;
        if (vname[0] == L'_' || dataType != REG_SZ) return false;

        data.assign(dataSize / sizeof(wchar_t), L'\0');
        vnameLen = 64;
        if (RegEnumValueW(hKey, index, vname, &vnameLen, nullptr, nullptr,
                          reinterpret_cast<BYTE*>(&data[0]), &dataSize) != ERROR_SUCCESS)
            return false;
        while (!data.empty() && data.back() == L'\0') data.pop_back();
        name = vname;
        return true;
    }

    inline LSTATUS DeleteRegTreeBestEffort(HKEY hRoot, const std::wstring& subKey)
    {
        LSTATUS st = RegDeleteTreeW(hRoot, subKey.c_str());
        if (st == ERROR_SUCCESS || st == ERROR_FILE_NOT_FOUND || st == ERROR_PATH_NOT_FOUND)
            return st;

        LSTATUS fallback = RegDeleteKeyW(hRoot, subKey.c_str());
        if (fallback == ERROR_SUCCESS || fallback == ERROR_FILE_NOT_FOUND || fallback == ERROR_PATH_NOT_FOUND)
            return fallback;

        return fallback;
    }

    inline bool DeleteRegTreeIfExists(HKEY hRoot, const std::wstring& subKey)
    {
        LSTATUS st = DeleteRegTreeBestEffort(hRoot, subKey);
        return st == ERROR_SUCCESS || st == ERROR_FILE_NOT_FOUND || st == ERROR_PATH_NOT_FOUND;
    }

} // namespace Sandbox
