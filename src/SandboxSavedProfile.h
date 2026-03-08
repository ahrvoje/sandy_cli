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
    // Helper: write a REG_SZ value
    // -----------------------------------------------------------------------
    inline void WriteRegSz(HKEY hKey, const wchar_t* name, const std::wstring& val)
    {
        RegSetValueExW(hKey, name, 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(val.c_str()),
                       static_cast<DWORD>((val.size() + 1) * sizeof(wchar_t)));
    }

    // -----------------------------------------------------------------------
    // Helper: read a REG_SZ value
    // -----------------------------------------------------------------------
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
    // CreateSavedProfile — create a named profile with persistent SID + ACLs.
    //
    // Steps:
    //   1. Parse TOML config
    //   2. Generate SID (AC: CreateAppContainerProfile, RT: AllocateAndInitializeSid)
    //   3. Apply grants via ApplyAccessPipeline (ACLs stay on disk)
    //   4. Persist metadata + grant records to registry
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
            GUID sidGuid{};
            CoCreateGuid(&sidGuid);
            SID_IDENTIFIER_AUTHORITY rmAuth = { {0, 0, 0, 0, 0, 9} };
            if (!AllocateAndInitializeSid(&rmAuth, 4,
                    sidGuid.Data1,
                    static_cast<DWORD>(sidGuid.Data2 | (sidGuid.Data3 << 16)),
                    static_cast<DWORD>(sidGuid.Data4[0] | (sidGuid.Data4[1] << 8) |
                                       (sidGuid.Data4[2] << 16) | (sidGuid.Data4[3] << 24)),
                    static_cast<DWORD>(sidGuid.Data4[4] | (sidGuid.Data4[5] << 8) |
                                       (sidGuid.Data4[6] << 16) | (sidGuid.Data4[7] << 24)),
                    0, 0, 0, 0, &pSid)) {
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

        // --- Apply grants (persistent — remain on disk) ---
        // Set a temporary instance ID so RecordGrant can work.
        // Profile grants are stored under Profiles\<name>, not Grants\<uuid>.
        // We apply ACLs directly without using the RecordGrant mechanism.
        printf("Applying grants for profile '%ls'...\n", name.c_str());
        bool grantOk = ApplyAccessPipeline(pSid, config, isAppContainer);
        if (!grantOk) {
            printf("  Warning: some grants failed (may need Administrator).\n");
        }

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
        WriteRegSz(hKey, L"_toml", tomlText);

        // Store grant records (same format as instance grants, for --delete-profile cleanup)
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

        // Clear in-memory grant list (don't revoke on exit — they're persistent)
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
        RegCloseKey(hKey);

        // Parse embedded TOML
        if (!out.tomlText.empty()) {
            out.config = ParseConfig(out.tomlText);
        }
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
    // Key differences from RunSandboxed/RunPipeline:
    //   - SID is reconstructed from stored profile (not freshly generated)
    //   - Grant application is SKIPPED (ACLs are persistent from --create-profile)
    //   - Grant cleanup is SKIPPED on exit (grants stay for next run)
    //   - Desktop access is granted/revoked per-run (not persistent)
    //   - Loopback is enabled/disabled per-run (not persistent)
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

        SandboxGuard guard;

        // =================================================================
        // PHASE 1: SETUP — reconstruct SID from stored profile
        // =================================================================
        PSID pSid = nullptr;
        HANDLE hRestrictedToken = nullptr;

        if (isAppContainer) {
            // Derive SID from stored container name
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
            guard.Add([pContainerSid]() { FreeSid(pContainerSid); });
            g_logger.Log(L"MODE: appcontainer (profile)");
        } else {
            // Convert stored SID string back to binary
            PSID pGrantSid = nullptr;
            if (!ConvertStringSidToSidW(prof.sidString.c_str(), &pGrantSid)) {
                g_logger.LogFmt(L"ERROR: cannot convert SID '%s' (error %lu)",
                                prof.sidString.c_str(), GetLastError());
                fprintf(stderr, "Error: cannot reconstruct SID for profile '%ls'.\n",
                        prof.name.c_str());
                return SandyExit::SetupError;
            }
            pSid = pGrantSid;
            guard.Add([pGrantSid]() { LocalFree(pGrantSid); });

            // Create restricted token with the profile's SID
            hRestrictedToken = CreateRestrictedSandboxToken(config.integrity, pGrantSid);
            if (!hRestrictedToken) {
                g_logger.LogFmt(L"ERROR: restricted token creation failed (error %lu)",
                                GetLastError());
                return SandyExit::SetupError;
            }
            guard.Add([&hRestrictedToken]() { if (hRestrictedToken) CloseHandle(hRestrictedToken); });
            g_logger.Log(config.integrity == IntegrityLevel::Low
                         ? L"MODE: restricted token (Low integrity, profile)"
                         : L"MODE: restricted token (Medium integrity, profile)");
        }

        g_logger.LogFmt(L"WORKDIR: %s", exeFolder.c_str());

        // =================================================================
        // PHASE 2: SKIP GRANTS (ACLs are persistent from --create-profile)
        // =================================================================
        g_logger.Log(L"GRANTS: skipped (persistent profile)");

        // [RT] Grant desktop access (per-run, not persistent)
        if (isRestricted) {
            GrantDesktopAccess(pSid);
            g_logger.Log(L"DESKTOP: granted WinSta0 + Default access");
            guard.Add([]() { RevokeDesktopAccess(); });
        }

        // [AC] Enable loopback if requested (per-run, not persistent)
        std::wstring containerName = prof.containerName;
        if (isAppContainer && config.allowLocalhost) {
            bool ok = EnableLoopback(containerName);
            g_logger.Log(ok ? L"LOOPBACK: enabled" : L"LOOPBACK: FAILED (need Administrator)");
            guard.Add([]() { DisableLoopback(); });
        }

        // =================================================================
        // PHASE 3: PREPARE — capabilities, env, pipes
        // =================================================================
        CapabilityState caps = {};
        SECURITY_CAPABILITIES sc{};
        if (isAppContainer) {
            caps = BuildCapabilities(config);
            sc.AppContainerSid = pSid;
            sc.Capabilities = caps.capCount > 0 ? caps.caps : nullptr;
            sc.CapabilityCount = caps.capCount;
            guard.Add([&caps]() { FreeCapabilities(caps); });
        }

        AttributeListState attrs = BuildAttributeList(config,
            isAppContainer ? &sc : nullptr, isRestricted);
        if (!attrs.valid) return SandyExit::SetupError;
        guard.Add([&attrs]() { FreeAttributeList(attrs); });

        LogStdinMode(config.stdinMode);
        std::vector<wchar_t> envBlock = BuildEnvironmentBlock(config);
        LogEnvironmentState(config);
        if (!g_logger.IsActive())
            PrintConfigSummary(config, exePath, exeArgs, isRestricted);

        // Audit and crash dumps
        std::wstring procmonExe;
        bool auditActive = false;
        std::wstring auditPmlPath;
        SetupAudit(auditLogPath, procmonExe, auditActive, auditPmlPath);

        std::wstring crashExeName;
        bool crashDumpsEnabled = false;
        SetupCrashDumps(auditLogPath, dumpPath, exePath, crashExeName, crashDumpsEnabled);

        // Stdin
        HANDLE hStdin = nullptr, hStdinFile = nullptr;
        if (!SetupStdinHandle(config.stdinMode, hStdin, hStdinFile))
            return SandyExit::SetupError;

        // Log config
        g_logger.LogConfig(config, exePath, exeArgs);

        // =================================================================
        // PHASE 4: LAUNCH & RUN
        // =================================================================
        PROCESS_INFORMATION pi{};
        bool launched = LaunchChildProcess(
            isRestricted,
            isRestricted ? hRestrictedToken : nullptr,
            attrs.pAttrList, envBlock, exeFolder, exePath, exeArgs,
            hStdin, pi);

        if (hStdinFile) CloseHandle(hStdinFile);

        if (!launched) {
            DWORD launchErr = GetLastError();
            g_logger.Log(L"LAUNCH: FAILED (profile mode)");
            g_logger.LogSummary(launchErr, false, 0);
            // Do NOT delete AppContainer profile — it's persistent
            guard.RunAll();
            g_logger.Log(L"CLEANUP: complete (launch failure, profile mode)");
            bool notFound = (launchErr == ERROR_FILE_NOT_FOUND ||
                             launchErr == ERROR_PATH_NOT_FOUND);
            return notFound ? SandyExit::NotFound : SandyExit::CannotExec;
        }

        // Job object for resource limits
        HANDLE hJob = AssignJobObject(config, pi.hProcess);
        bool jobNeeded = (config.memoryLimitMB > 0 || config.maxProcesses > 0 ||
                          !config.allowClipboardRead || !config.allowClipboardWrite);
        if (jobNeeded && !hJob) {
            g_logger.Log(L"ERROR: job object failed — aborting (profile mode)");
            TerminateProcess(pi.hProcess, SandyExit::SetupError);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            guard.RunAll();
            return SandyExit::SetupError;
        }

        // Resume and wait
        ResumeThread(pi.hThread);
        g_logger.Log(L"CHILD: resumed (profile mode)");
        CloseHandle(pi.hThread);

        TimeoutContext timeoutCtx = { pi.hProcess, config.timeoutSeconds, false };
        HANDLE hTimeoutThread = StartTimeoutWatchdog(timeoutCtx);

        DWORD exitCode = WaitForChildExit(pi.hProcess,
                                           hTimeoutThread, timeoutCtx,
                                           config.timeoutSeconds);

        // =================================================================
        // PHASE 5: CLEANUP — NO grant revocation (persistent profile)
        // =================================================================
        g_logger.LogSummary(exitCode, timeoutCtx.timedOut, config.timeoutSeconds);
        if (timeoutCtx.timedOut)
            g_logger.Log(L"EXIT_CLASS: TIMEOUT");
        else if (IsCrashExitCode(exitCode))
            g_logger.LogFmt(L"EXIT_CLASS: CRASH (0x%08X)", exitCode);
        else if (exitCode != 0)
            g_logger.LogFmt(L"EXIT_CLASS: ERROR (code=%ld)", (long)exitCode);
        else
            g_logger.Log(L"EXIT_CLASS: CLEAN");
        FinalizeAuditAndDumps(auditActive, procmonExe, auditLogPath, auditPmlPath, dumpPath,
                              crashDumpsEnabled, crashExeName, pi.dwProcessId, exitCode);

        CloseHandle(pi.hProcess);
        if (hJob) CloseHandle(hJob);

        // Desktop/loopback/caps/attrs cleanup via guard (but NOT grants)
        g_logger.Log(L"CLEANUP: starting (profile mode — grants preserved)");
        guard.RunAll();
        g_logger.Log(L"CLEANUP: complete (profile mode)");

        int sandyExit;
        if (timeoutCtx.timedOut)
            sandyExit = SandyExit::Timeout;
        else if (IsCrashExitCode(exitCode))
            sandyExit = SandyExit::ChildCrash;
        else
            sandyExit = static_cast<int>(exitCode);

        return sandyExit;
    }

} // namespace Sandbox
