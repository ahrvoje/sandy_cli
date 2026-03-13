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
        DWORD size = 0;
        if (RegQueryValueExW(hKey, name, nullptr, nullptr, nullptr, &size) != ERROR_SUCCESS)
            return {};
        std::wstring val(size / sizeof(wchar_t), L'\0');
        RegQueryValueExW(hKey, name, nullptr, nullptr,
                         reinterpret_cast<BYTE*>(&val[0]), &size);
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
        DWORD val = 0, size = sizeof(val);
        if (RegQueryValueExW(hKey, name, nullptr, nullptr,
                             reinterpret_cast<BYTE*>(&val), &size) != ERROR_SUCCESS)
            return defaultVal;
        return val;
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

} // namespace Sandbox
