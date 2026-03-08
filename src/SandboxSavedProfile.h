// =========================================================================
// SandboxSavedProfile.h — Persistent named sandbox profiles
//
// Creates, loads, deletes, and enumerates named profiles that persist
// SID + ACL grants + TOML config between Sandy runs.  Composes existing
// primitives: ApplyAccessPipeline, SetupAppContainer/SetupRestrictedToken,
// RecordGrant format, RemoveSidFromDacl.
// =========================================================================
#pragma once

#include "Sandbox.h"

namespace Sandbox {

    // Registry parent key for saved profiles
    static const wchar_t* kProfilesParentKey = L"Software\\Sandy\\Profiles";

    // -----------------------------------------------------------------------
    // SavedProfile — in-memory representation of a persisted profile
    // -----------------------------------------------------------------------
    struct SavedProfile {
        std::wstring name;
        std::wstring type;         // "appcontainer" or "restricted"
        std::wstring integrity;    // "low" or "medium" (restricted only)
        std::wstring sidString;
        std::wstring containerName; // AC only: "Sandy_<name>"
        std::wstring created;       // ISO 8601
        std::wstring tomlText;      // raw TOML config
        SandboxConfig config;       // parsed config
    };

    // -----------------------------------------------------------------------
    // ReadTomlFileText — read a TOML file as raw wide string for storage.
    // -----------------------------------------------------------------------
    inline std::wstring ReadTomlFileText(const std::wstring& configPath)
    {
        HANDLE hFile = CreateFileW(configPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return {};

        DWORD fileSize = GetFileSize(hFile, nullptr);
        if (fileSize == 0 || fileSize == INVALID_FILE_SIZE || fileSize > 1024 * 1024) {
            CloseHandle(hFile);
            return {};
        }

        std::string buf(fileSize, '\0');
        DWORD bytesRead = 0;
        if (!ReadFile(hFile, &buf[0], fileSize, &bytesRead, nullptr) || bytesRead == 0) {
            CloseHandle(hFile);
            return {};
        }
        CloseHandle(hFile);

        int wideLen = MultiByteToWideChar(CP_UTF8, 0, buf.c_str(), (int)bytesRead, nullptr, 0);
        std::wstring content(wideLen, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, buf.c_str(), (int)bytesRead, &content[0], wideLen);
        return content;
    }

    // -----------------------------------------------------------------------
    // ProfileExists — check if a named profile exists in the registry.
    // -----------------------------------------------------------------------
    inline bool ProfileExists(const std::wstring& name)
    {
        std::wstring key = std::wstring(kProfilesParentKey) + L"\\" + name;
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, key.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
        return false;
    }

    // -----------------------------------------------------------------------
    // WriteConfigToRegistry — persist every SandboxConfig field as discrete
    // registry values under an open HKEY.  Each value maps 1:1 to a config
    // field so the profile is fully inspectable in regedit and does not
    // depend on the TOML parser at load time.
    //
    // Layout:
    //   _token_mode         REG_SZ   "appcontainer" | "restricted"
    //   _cfg_integrity      REG_SZ   "low" | "medium"
    //   _workdir            REG_SZ   path (may be empty)
    //   _allow_network      REG_DWORD  0 | 1
    //   _allow_localhost     REG_DWORD  0 | 1
    //   _allow_lan           REG_DWORD  0 | 1
    //   _allow_system_dirs   REG_DWORD  0 | 1
    //   _allow_named_pipes   REG_DWORD  0 | 1
    //   _allow_clipboard_r   REG_DWORD  0 | 1
    //   _allow_clipboard_w   REG_DWORD  0 | 1
    //   _allow_child_procs   REG_DWORD  0 | 1
    //   _stdin_mode          REG_SZ   "NUL" | "" | path
    //   _env_inherit         REG_DWORD  0 | 1
    //   _timeout             REG_DWORD  seconds (0 = none)
    //   _memory_limit_mb     REG_DWORD  MB (0 = none)
    //   _max_processes       REG_DWORD  count (0 = none)
    //   _allow_count         REG_DWORD  number of allow entries
    //   _allow_0 .. _allow_N REG_SZ   "access|path"
    //   _deny_count          REG_DWORD  number of deny entries
    //   _deny_0  .. _deny_N  REG_SZ   "access|path"
    //   _reg_read_count      REG_DWORD  count
    //   _reg_read_0 ..       REG_SZ   registry path
    //   _reg_write_count     REG_DWORD  count
    //   _reg_write_0 ..      REG_SZ   registry path
    //   _env_pass_count      REG_DWORD  count
    //   _env_pass_0 ..       REG_SZ   variable name
    // -----------------------------------------------------------------------
    inline void WriteConfigToRegistry(HKEY hKey, const SandboxConfig& cfg)
    {
        // --- Enums ---
        WriteRegSz(hKey, L"_token_mode",
            (cfg.tokenMode == TokenMode::AppContainer) ? L"appcontainer" : L"restricted");
        WriteRegSz(hKey, L"_cfg_integrity",
            (cfg.integrity == IntegrityLevel::Low) ? L"low" : L"medium");

        // --- Strings ---
        WriteRegSz(hKey, L"_workdir", cfg.workdir);
        WriteRegSz(hKey, L"_stdin_mode", cfg.stdinMode);

        // --- Booleans (REG_DWORD 0/1) ---
        WriteRegDword(hKey, L"_allow_network",      cfg.allowNetwork     ? 1 : 0);
        WriteRegDword(hKey, L"_allow_localhost",     cfg.allowLocalhost   ? 1 : 0);
        WriteRegDword(hKey, L"_allow_lan",           cfg.allowLan         ? 1 : 0);
        WriteRegDword(hKey, L"_allow_system_dirs",   cfg.allowSystemDirs  ? 1 : 0);
        WriteRegDword(hKey, L"_allow_named_pipes",   cfg.allowNamedPipes  ? 1 : 0);
        WriteRegDword(hKey, L"_allow_clipboard_r",   cfg.allowClipboardRead  ? 1 : 0);
        WriteRegDword(hKey, L"_allow_clipboard_w",   cfg.allowClipboardWrite ? 1 : 0);
        WriteRegDword(hKey, L"_allow_child_procs",   cfg.allowChildProcesses ? 1 : 0);
        WriteRegDword(hKey, L"_env_inherit",         cfg.envInherit       ? 1 : 0);

        // --- Integers ---
        WriteRegDword(hKey, L"_timeout",         cfg.timeoutSeconds);
        WriteRegDword(hKey, L"_memory_limit_mb", static_cast<DWORD>(cfg.memoryLimitMB));
        WriteRegDword(hKey, L"_max_processes",   cfg.maxProcesses);

        // --- Allow folders: _allow_count + _allow_0, _allow_1, ... ---
        WriteRegDword(hKey, L"_allow_count", static_cast<DWORD>(cfg.folders.size()));
        for (DWORD i = 0; i < cfg.folders.size(); i++) {
            wchar_t name[32];
            swprintf(name, 32, L"_allow_%lu", i);
            WriteRegSz(hKey, name,
                std::wstring(AccessLevelName(cfg.folders[i].access)) + L"|" + cfg.folders[i].path);
        }

        // --- Deny folders: _deny_count + _deny_0, _deny_1, ... ---
        WriteRegDword(hKey, L"_deny_count", static_cast<DWORD>(cfg.denyFolders.size()));
        for (DWORD i = 0; i < cfg.denyFolders.size(); i++) {
            wchar_t name[32];
            swprintf(name, 32, L"_deny_%lu", i);
            WriteRegSz(hKey, name,
                std::wstring(AccessLevelName(cfg.denyFolders[i].access)) + L"|" + cfg.denyFolders[i].path);
        }

        // --- Registry read keys ---
        WriteRegDword(hKey, L"_reg_read_count", static_cast<DWORD>(cfg.registryRead.size()));
        for (DWORD i = 0; i < cfg.registryRead.size(); i++) {
            wchar_t name[32];
            swprintf(name, 32, L"_reg_read_%lu", i);
            WriteRegSz(hKey, name, cfg.registryRead[i]);
        }

        // --- Registry write keys ---
        WriteRegDword(hKey, L"_reg_write_count", static_cast<DWORD>(cfg.registryWrite.size()));
        for (DWORD i = 0; i < cfg.registryWrite.size(); i++) {
            wchar_t name[32];
            swprintf(name, 32, L"_reg_write_%lu", i);
            WriteRegSz(hKey, name, cfg.registryWrite[i]);
        }

        // --- Environment pass-through vars ---
        WriteRegDword(hKey, L"_env_pass_count", static_cast<DWORD>(cfg.envPass.size()));
        for (DWORD i = 0; i < cfg.envPass.size(); i++) {
            wchar_t name[32];
            swprintf(name, 32, L"_env_pass_%lu", i);
            WriteRegSz(hKey, name, cfg.envPass[i]);
        }
    }

    // -----------------------------------------------------------------------
    // ReadConfigFromRegistry — reconstruct SandboxConfig from discrete
    // registry values.  No TOML parsing involved.
    // -----------------------------------------------------------------------
    inline SandboxConfig ReadConfigFromRegistry(HKEY hKey)
    {
        SandboxConfig cfg;

        // --- Enums ---
        std::wstring mode = ReadRegSz(hKey, L"_token_mode");
        cfg.tokenMode = (mode == L"restricted") ? TokenMode::Restricted : TokenMode::AppContainer;

        std::wstring integ = ReadRegSz(hKey, L"_cfg_integrity");
        cfg.integrity = (integ == L"medium") ? IntegrityLevel::Medium : IntegrityLevel::Low;

        // --- Strings ---
        cfg.workdir   = ReadRegSz(hKey, L"_workdir");
        cfg.stdinMode = ReadRegSz(hKey, L"_stdin_mode");
        if (cfg.stdinMode.empty()) cfg.stdinMode = L"NUL";  // default

        // --- Booleans ---
        cfg.allowNetwork        = ReadRegDword(hKey, L"_allow_network")    != 0;
        cfg.allowLocalhost      = ReadRegDword(hKey, L"_allow_localhost")  != 0;
        cfg.allowLan            = ReadRegDword(hKey, L"_allow_lan")        != 0;
        cfg.allowSystemDirs     = ReadRegDword(hKey, L"_allow_system_dirs") != 0;
        cfg.allowNamedPipes     = ReadRegDword(hKey, L"_allow_named_pipes") != 0;
        cfg.allowClipboardRead  = ReadRegDword(hKey, L"_allow_clipboard_r") != 0;
        cfg.allowClipboardWrite = ReadRegDword(hKey, L"_allow_clipboard_w") != 0;
        cfg.allowChildProcesses = ReadRegDword(hKey, L"_allow_child_procs") != 0;
        cfg.envInherit          = ReadRegDword(hKey, L"_env_inherit")       != 0;

        // --- Integers ---
        cfg.timeoutSeconds = ReadRegDword(hKey, L"_timeout");
        cfg.memoryLimitMB  = ReadRegDword(hKey, L"_memory_limit_mb");
        cfg.maxProcesses   = ReadRegDword(hKey, L"_max_processes");

        // --- Allow folders ---
        DWORD allowCount = ReadRegDword(hKey, L"_allow_count");
        for (DWORD i = 0; i < allowCount; i++) {
            wchar_t name[32];
            swprintf(name, 32, L"_allow_%lu", i);
            std::wstring val = ReadRegSz(hKey, name);
            // Format: "access|path"
            size_t sep = val.find(L'|');
            if (sep != std::wstring::npos) {
                FolderEntry entry;
                entry.access = ParseAccessTag(val.substr(0, sep));
                entry.path = val.substr(sep + 1);
                cfg.folders.push_back(std::move(entry));
            }
        }

        // --- Deny folders ---
        DWORD denyCount = ReadRegDword(hKey, L"_deny_count");
        for (DWORD i = 0; i < denyCount; i++) {
            wchar_t name[32];
            swprintf(name, 32, L"_deny_%lu", i);
            std::wstring val = ReadRegSz(hKey, name);
            size_t sep = val.find(L'|');
            if (sep != std::wstring::npos) {
                FolderEntry entry;
                entry.access = ParseAccessTag(val.substr(0, sep));
                entry.path = val.substr(sep + 1);
                cfg.denyFolders.push_back(std::move(entry));
            }
        }

        // --- Registry read keys ---
        DWORD regReadCount = ReadRegDword(hKey, L"_reg_read_count");
        for (DWORD i = 0; i < regReadCount; i++) {
            wchar_t name[32];
            swprintf(name, 32, L"_reg_read_%lu", i);
            std::wstring val = ReadRegSz(hKey, name);
            if (!val.empty()) cfg.registryRead.push_back(std::move(val));
        }

        // --- Registry write keys ---
        DWORD regWriteCount = ReadRegDword(hKey, L"_reg_write_count");
        for (DWORD i = 0; i < regWriteCount; i++) {
            wchar_t name[32];
            swprintf(name, 32, L"_reg_write_%lu", i);
            std::wstring val = ReadRegSz(hKey, name);
            if (!val.empty()) cfg.registryWrite.push_back(std::move(val));
        }

        // --- Environment pass-through ---
        DWORD envPassCount = ReadRegDword(hKey, L"_env_pass_count");
        for (DWORD i = 0; i < envPassCount; i++) {
            wchar_t name[32];
            swprintf(name, 32, L"_env_pass_%lu", i);
            std::wstring val = ReadRegSz(hKey, name);
            if (!val.empty()) cfg.envPass.push_back(std::move(val));
        }

        return cfg;
    }

    // -----------------------------------------------------------------------
    // CreateSavedProfile — create a named profile with persistent SID + ACLs.
    //
    // Steps:
    //   1. Parse TOML config
    //   2. Generate SID (AC: CreateAppContainerProfile, RT: AllocateAndInitializeSid)
    //   3. Apply grants via ApplyAccessPipeline (ACLs stay on disk)
    //   4. Persist metadata + config + grant records to registry
    // -----------------------------------------------------------------------
    inline int HandleCreateProfile(const std::wstring& name, const std::wstring& configPath)
    {
        // Validate name
        if (name.empty()) {
            fprintf(stderr, "Error: profile name cannot be empty.\n");
            return SandyExit::ConfigError;
        }
        // Reject names with backslashes or special chars
        for (wchar_t c : name) {
            if (c == L'\\' || c == L'/' || c == L'|' || c == L'"' || c < 32) {
                fprintf(stderr, "Error: profile name contains invalid characters.\n");
                return SandyExit::ConfigError;
            }
        }
        if (ProfileExists(name)) {
            fprintf(stderr, "Error: profile '%ls' already exists. Use --delete-profile first.\n",
                    name.c_str());
            return SandyExit::ConfigError;
        }

        // Read TOML file as raw text (for storage) and parse config
        std::wstring tomlText = ReadTomlFileText(configPath);
        if (tomlText.empty()) {
            fprintf(stderr, "Error: cannot read config file: %ls\n", configPath.c_str());
            return SandyExit::ConfigError;
        }
        SandboxConfig config = ParseConfig(tomlText);
        if (config.parseError) {
            fprintf(stderr, "Error: config contains unknown sections or keys.\n");
            return SandyExit::ConfigError;
        }

        bool isAppContainer = (config.tokenMode == TokenMode::AppContainer);
        std::wstring sidString;
        std::wstring containerName;
        std::wstring typeStr = isAppContainer ? L"appcontainer" : L"restricted";
        std::wstring integrityStr = (config.integrity == IntegrityLevel::Low) ? L"low" : L"medium";

        // --- Generate SID ---
        PSID pSid = nullptr;
        if (isAppContainer) {
            // Use deterministic container name based on profile name
            containerName = std::wstring(kContainerPrefix) + name;
            PSID pContainerSid = nullptr;
            HRESULT hr = CreateAppContainerProfile(
                containerName.c_str(), L"Sandy Sandbox Profile",
                L"Persistent sandbox profile",
                nullptr, 0, &pContainerSid);
            if (HRESULT_CODE(hr) == ERROR_ALREADY_EXISTS) {
                // Profile exists in Windows but not in our registry — derive SID
                hr = DeriveAppContainerSidFromAppContainerName(
                    containerName.c_str(), &pContainerSid);
            }
            if (FAILED(hr) || !pContainerSid) {
                fprintf(stderr, "Error: AppContainer profile creation failed (0x%08lX).\n",
                        (unsigned long)hr);
                return SandyExit::SetupError;
            }
            pSid = pContainerSid;
        } else {
            // Restricted Token: generate unique SID from GUID
            pSid = AllocateInstanceSid();
            if (!pSid) {
                fprintf(stderr, "Error: SID allocation failed (error %lu).\n", GetLastError());
                return SandyExit::SetupError;
            }
        }

        // Convert SID to string
        LPWSTR pSidStr = nullptr;
        if (ConvertSidToStringSidW(pSid, &pSidStr)) {
            sidString = pSidStr;
            LocalFree(pSidStr);
        } else {
            fprintf(stderr, "Error: SID conversion failed.\n");
            FreeSid(pSid);
            return SandyExit::SetupError;
        }

        // --- Apply grants (persistent — remain on filesystem) ---
        //
        // Suppress RecordGrant's registry writes — we persist grant records
        // to Sandy\Profiles\<name> below, not Sandy\Grants\<instanceId>.
        g_grantPersistence = false;

        printf("Applying grants for profile '%ls'...\n", name.c_str());
        bool grantOk = ApplyAccessPipeline(pSid, config, isAppContainer);
        if (!grantOk) {
            printf("  Warning: some grants failed (may need Administrator).\n");
        }

        g_grantPersistence = true;  // restore for any subsequent operations

        // --- Persist profile metadata to registry ---
        std::wstring regKey = std::wstring(kProfilesParentKey) + L"\\" + name;
        HKEY hKey = nullptr;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, regKey.c_str(), 0, nullptr,
                0, KEY_SET_VALUE | KEY_QUERY_VALUE, nullptr, &hKey, nullptr) != ERROR_SUCCESS) {
            fprintf(stderr, "Error: cannot create registry key for profile.\n");
            FreeSid(pSid);
            return SandyExit::InternalError;
        }

        WriteRegSz(hKey, L"_type", typeStr);
        WriteRegSz(hKey, L"_integrity", integrityStr);
        WriteRegSz(hKey, L"_sid", sidString);
        if (!containerName.empty())
            WriteRegSz(hKey, L"_container", containerName);
        WriteRegSz(hKey, L"_created", SandyLogger::Timestamp());
        WriteRegSz(hKey, L"_toml", tomlText);  // reference only
        WriteConfigToRegistry(hKey, config);

        // Copy grant records to profile key (for --delete-profile cleanup)
        DWORD grantIdx = 0;
        AcquireSRWLockShared(&g_aclGrantsLock);
        for (const auto& g : g_aclGrants) {
            std::wstring typeTag = (g.objType == SE_REGISTRY_KEY) ? L"REG" : L"FILE";
            std::wstring data = typeTag + L"|" + g.path + L"|" + g.sidString;
            if (g.wasDenied) data += L"|DENY:1";
            if (!g.trappedSids.empty()) data += L"|TRAPPED:" + g.trappedSids;
            if (g.wasPeek) data += L"|PEEK:1";

            wchar_t valName[32];
            swprintf(valName, 32, L"%lu", grantIdx++);
            WriteRegSz(hKey, valName, data);
        }
        ReleaseSRWLockShared(&g_aclGrantsLock);

        RegCloseKey(hKey);
        FreeSid(pSid);

        // Clear in-memory grant list (ACLs stay on disk, records are in Profiles)
        AcquireSRWLockExclusive(&g_aclGrantsLock);
        g_aclGrants.clear();
        ReleaseSRWLockExclusive(&g_aclGrantsLock);

        printf("Profile '%ls' created successfully.\n", name.c_str());
        printf("  Type:      %ls\n", typeStr.c_str());
        if (!isAppContainer)
            printf("  Integrity: %ls\n", integrityStr.c_str());
        printf("  SID:       %ls\n", sidString.c_str());
        if (!containerName.empty())
            printf("  Container: %ls\n", containerName.c_str());
        printf("  Grants:    %lu path(s)\n", (unsigned long)grantIdx);
        return 0;
    }

    // -----------------------------------------------------------------------
    // LoadSavedProfile — read a named profile from registry.
    // Returns false if not found.
    // -----------------------------------------------------------------------
    inline bool LoadSavedProfile(const std::wstring& name, SavedProfile& out)
    {
        std::wstring regKey = std::wstring(kProfilesParentKey) + L"\\" + name;
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, regKey.c_str(), 0,
                          KEY_READ, &hKey) != ERROR_SUCCESS)
            return false;

        out.name = name;
        out.type = ReadRegSz(hKey, L"_type");
        out.integrity = ReadRegSz(hKey, L"_integrity");
        out.sidString = ReadRegSz(hKey, L"_sid");
        out.containerName = ReadRegSz(hKey, L"_container");
        out.created = ReadRegSz(hKey, L"_created");
        out.tomlText = ReadRegSz(hKey, L"_toml");

        // Read config from discrete registry values (no TOML parsing)
        out.config = ReadConfigFromRegistry(hKey);
        RegCloseKey(hKey);
        return !out.sidString.empty();
    }

    // -----------------------------------------------------------------------
    // DeleteSavedProfile — remove a profile: revoke ACLs, delete container,
    // delete registry key.
    // -----------------------------------------------------------------------
    inline int HandleDeleteProfile(const std::wstring& name)
    {
        std::wstring regKey = std::wstring(kProfilesParentKey) + L"\\" + name;
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, regKey.c_str(), 0,
                          KEY_READ, &hKey) != ERROR_SUCCESS) {
            fprintf(stderr, "Error: profile '%ls' not found.\n", name.c_str());
            return SandyExit::ConfigError;
        }

        // Read container name for AppContainer cleanup
        std::wstring containerName = ReadRegSz(hKey, L"_container");

        // Revoke all grant ACLs
        printf("Revoking grants for profile '%ls'...\n", name.c_str());
        RestoreGrantsFromKey(hKey);
        RegCloseKey(hKey);

        // Delete AppContainer profile from Windows
        if (!containerName.empty()) {
            HRESULT hr = DeleteAppContainerProfile(containerName.c_str());
            printf("  [CONTAINER] %ls -> %s\n", containerName.c_str(),
                   SUCCEEDED(hr) ? "deleted" : "FAILED (may not exist)");
        }

        // Delete registry key
        LSTATUS st = RegDeleteTreeW(HKEY_CURRENT_USER, regKey.c_str());
        if (st != ERROR_SUCCESS) {
            fprintf(stderr, "Warning: registry key deletion failed (error %lu).\n", st);
        }

        printf("Profile '%ls' deleted.\n", name.c_str());
        return 0;
    }

    // -----------------------------------------------------------------------
    // EnumSavedProfiles — list all saved profile names + creation dates.
    // -----------------------------------------------------------------------
    struct ProfileSummary {
        std::wstring name;
        std::wstring created;
        std::wstring type;
    };

    inline std::vector<ProfileSummary> EnumSavedProfiles()
    {
        std::vector<ProfileSummary> result;
        HKEY hParent = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kProfilesParentKey, 0,
                          KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hParent) != ERROR_SUCCESS)
            return result;

        DWORD numKeys = 0;
        RegQueryInfoKeyW(hParent, nullptr, nullptr, nullptr, &numKeys,
                         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

        for (DWORD i = 0; i < numKeys; i++) {
            wchar_t nm[256]; DWORD nl = 256;
            if (RegEnumKeyExW(hParent, i, nm, &nl, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                continue;

            ProfileSummary ps;
            ps.name = nm;

            // Read creation date and type from subkey
            std::wstring subKey = std::wstring(kProfilesParentKey) + L"\\" + nm;
            HKEY hSub = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, subKey.c_str(), 0,
                              KEY_READ, &hSub) == ERROR_SUCCESS) {
                ps.created = ReadRegSz(hSub, L"_created");
                ps.type = ReadRegSz(hSub, L"_type");
                RegCloseKey(hSub);
            }
            result.push_back(std::move(ps));
        }
        RegCloseKey(hParent);
        return result;
    }

    // -----------------------------------------------------------------------
    // HandleProfileInfo — print detailed info about a saved profile.
    // -----------------------------------------------------------------------
    inline int HandleProfileInfo(const std::wstring& name)
    {
        SavedProfile prof;
        if (!LoadSavedProfile(name, prof)) {
            fprintf(stderr, "Error: profile '%ls' not found.\n", name.c_str());
            return SandyExit::ConfigError;
        }

        printf("=== Profile: %ls ===\n", prof.name.c_str());
        printf("Created:     %ls\n", prof.created.c_str());
        printf("Type:        %ls\n", prof.type.c_str());
        if (prof.type == L"restricted")
            printf("Integrity:   %ls\n", prof.integrity.c_str());
        printf("SID:         %ls\n", prof.sidString.c_str());
        if (!prof.containerName.empty())
            printf("Container:   %ls\n", prof.containerName.c_str());

        // Config summary
        if (!prof.config.parseError) {
            printf("\nConfiguration:\n");
            int allowCount = (int)prof.config.folders.size();
            int denyCount = (int)prof.config.denyFolders.size();
            printf("  Allow paths:  %d\n", allowCount);
            for (const auto& f : prof.config.folders)
                printf("    [%-7ls] %ls\n", AccessTag(f.access), f.path.c_str());
            if (denyCount > 0) {
                printf("  Deny paths:   %d\n", denyCount);
                for (const auto& f : prof.config.denyFolders)
                    printf("    [%-7ls] %ls\n", AccessTag(f.access), f.path.c_str());
            }

            // Privileges
            printf("  Privileges:\n");
            if (prof.type == L"appcontainer") {
                printf("    system_dirs     = %s\n", prof.config.allowSystemDirs ? "true" : "false");
                printf("    network         = %s\n", prof.config.allowNetwork ? "true" : "false");
                printf("    localhost        = %s\n", prof.config.allowLocalhost ? "true" : "false");
                printf("    lan             = %s\n", prof.config.allowLan ? "true" : "false");
            } else {
                printf("    named_pipes     = %s\n", prof.config.allowNamedPipes ? "true" : "false");
            }
            printf("    stdin           = %s\n",
                   prof.config.stdinMode == L"NUL" ? "false" : "true");
            printf("    clipboard_read  = %s\n", prof.config.allowClipboardRead ? "true" : "false");
            printf("    clipboard_write = %s\n", prof.config.allowClipboardWrite ? "true" : "false");
            printf("    child_processes = %s\n", prof.config.allowChildProcesses ? "true" : "false");

            // Limits
            if (prof.config.timeoutSeconds || prof.config.memoryLimitMB || prof.config.maxProcesses) {
                printf("  Limits:\n");
                if (prof.config.timeoutSeconds)
                    printf("    timeout         = %lu sec\n", prof.config.timeoutSeconds);
                if (prof.config.memoryLimitMB)
                    printf("    memory          = %zu MB\n", prof.config.memoryLimitMB);
                if (prof.config.maxProcesses)
                    printf("    processes       = %lu max\n", prof.config.maxProcesses);
            }
        }

        return 0;
    }

    // -----------------------------------------------------------------------
    // RunWithProfile — run a process using a saved profile's SID + config.
    //
    // Reconstructs SID from stored profile, builds a PipelineContext, and
    // delegates to RunPipeline.  Profile mode skips grant application and
    // revocation; desktop and loopback are handled per-run by the pipeline.
    // -----------------------------------------------------------------------
    inline int RunWithProfile(const SavedProfile& prof,
                               const std::wstring& exePath,
                               const std::wstring& exeArgs,
                               const std::wstring& auditLogPath = L"",
                               const std::wstring& dumpPath = L"")
    {
        const SandboxConfig& config = prof.config;
        bool isRestricted = (config.tokenMode == TokenMode::Restricted);
        bool isAppContainer = !isRestricted;

        // Generate instance ID for this run (unique per run, NOT the profile SID)
        g_instanceId = GenerateInstanceId();

        // Working directory
        std::wstring exeFolder = config.workdir.empty() ? GetExeFolder() : config.workdir;
        if (exeFolder.empty())
            return SandyExit::SetupError;

        // Startup housekeeping
        WarnStaleRegistryEntries();
        LogSandyIdentity();
        g_logger.Log((L"INSTANCE: " + g_instanceId).c_str());
        g_logger.Log((L"PROFILE: " + prof.name).c_str());
        g_logger.Log((L"PROFILE_SID: " + prof.sidString).c_str());
        g_logger.Log((L"CONFIG_SOURCE: profile:" + prof.name).c_str());

        // Reconstruct SID from stored profile
        PipelineContext ctx;
        ctx.profileMode = true;

        // SID + token cleanup guard — these must outlive RunPipeline
        PSID pSid = nullptr;
        HANDLE hRestrictedToken = nullptr;

        if (isAppContainer) {
            PSID pContainerSid = nullptr;
            HRESULT hr = DeriveAppContainerSidFromAppContainerName(
                prof.containerName.c_str(), &pContainerSid);
            if (FAILED(hr) || !pContainerSid) {
                g_logger.LogFmt(L"ERROR: cannot derive SID from container '%s' (0x%08X)",
                                prof.containerName.c_str(), hr);
                fprintf(stderr, "Error: cannot derive SID for profile '%ls'. "
                        "Profile may be corrupted — recreate it.\n", prof.name.c_str());
                return SandyExit::SetupError;
            }
            pSid = pContainerSid;
            g_logger.Log(L"MODE: appcontainer (profile)");
        } else {
            PSID pGrantSid = nullptr;
            if (!ConvertStringSidToSidW(prof.sidString.c_str(), &pGrantSid)) {
                g_logger.LogFmt(L"ERROR: cannot convert SID '%s' (error %lu)",
                                prof.sidString.c_str(), GetLastError());
                fprintf(stderr, "Error: cannot reconstruct SID for profile '%ls'.\n",
                        prof.name.c_str());
                return SandyExit::SetupError;
            }
            pSid = pGrantSid;

            hRestrictedToken = CreateRestrictedSandboxToken(config.integrity, pGrantSid);
            if (!hRestrictedToken) {
                g_logger.LogFmt(L"ERROR: restricted token creation failed (error %lu)",
                                GetLastError());
                LocalFree(pGrantSid);
                return SandyExit::SetupError;
            }
            g_logger.Log(config.integrity == IntegrityLevel::Low
                         ? L"MODE: restricted token (Low integrity, profile)"
                         : L"MODE: restricted token (Medium integrity, profile)");
        }

        ctx.pSid = pSid;
        ctx.hToken = hRestrictedToken;

        std::wstring containerName = prof.containerName;

        int result = RunPipeline(config, exePath, exeArgs, containerName,
                                  exeFolder, auditLogPath, dumpPath, ctx);

        // Cleanup SID and token (RunPipeline doesn't own these in profile mode)
        if (hRestrictedToken) CloseHandle(hRestrictedToken);
        if (isAppContainer)
            FreeSid(pSid);
        else
            LocalFree(pSid);

        return result;
    }

} // namespace Sandbox
