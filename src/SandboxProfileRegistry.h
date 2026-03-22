// =========================================================================
// SandboxProfileRegistry.h — Shared saved-profile registry metadata helpers
//
// Provides a low-level, fail-closed view of saved profile registry keys so
// callers can share one interpretation of durable profile metadata.
// =========================================================================
#pragma once

#include "SandboxRegistry.h"
#include <utility>
#include <vector>

namespace Sandbox {

    inline constexpr const wchar_t* kProfilesParentKey = L"Software\\Sandy\\Profiles";

    struct SavedProfileRegistrySummary {
        std::wstring name;
        std::wstring created;
        std::wstring type;
        std::wstring sidString;
        std::wstring containerName;
        std::wstring lanMode;
        bool staging = false;
        bool allowDesktop = false;
    };

    inline bool OpenSavedProfileRegistryKey(const std::wstring& name,
                                            REGSAM samDesired,
                                            HKEY& hKey)
    {
        std::wstring key = std::wstring(kProfilesParentKey) + L"\\" + name;
        return RegOpenKeyExW(HKEY_CURRENT_USER, key.c_str(), 0, samDesired, &hKey) == ERROR_SUCCESS;
    }

    inline void ReadSavedProfileRegistrySummary(HKEY hKey,
                                                const std::wstring& name,
                                                SavedProfileRegistrySummary& out)
    {
        out = {};
        out.name = name;
        out.created = ReadRegSz(hKey, L"_created");
        out.type = ReadRegSz(hKey, L"_type");
        out.sidString = ReadRegSz(hKey, L"_sid");
        out.containerName = ReadRegSz(hKey, L"_container");
        out.lanMode = ReadRegSz(hKey, L"_lan_mode");

        DWORD staging = 0;
        out.staging = TryReadRegDword(hKey, L"_staging", staging) && staging != 0;

        DWORD allowDesktop = 0;
        out.allowDesktop = TryReadRegDword(hKey, L"_allow_desktop", allowDesktop) && allowDesktop != 0;
    }

    inline std::vector<std::wstring> EnumSavedProfileRegistryNames()
    {
        std::vector<std::wstring> names;
        HKEY hParent = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kProfilesParentKey, 0,
                          KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hParent) != ERROR_SUCCESS)
            return names;

        DWORD numKeys = 0;
        RegQueryInfoKeyW(hParent, nullptr, nullptr, nullptr, &numKeys,
                         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
        for (DWORD i = 0; i < numKeys; i++) {
            wchar_t name[256];
            DWORD nameLen = 256;
            if (RegEnumKeyExW(hParent, i, name, &nameLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
                names.push_back(name);
        }
        RegCloseKey(hParent);
        return names;
    }

    inline std::vector<SavedProfileRegistrySummary> EnumSavedProfileRegistrySummaries()
    {
        std::vector<SavedProfileRegistrySummary> summaries;
        for (const auto& name : EnumSavedProfileRegistryNames()) {
            HKEY hKey = nullptr;
            if (!OpenSavedProfileRegistryKey(name, KEY_READ, hKey))
                continue;

            SavedProfileRegistrySummary summary;
            ReadSavedProfileRegistrySummary(hKey, name, summary);
            RegCloseKey(hKey);
            summaries.push_back(std::move(summary));
        }
        return summaries;
    }

} // namespace Sandbox
