#pragma once
// Sandbox.h — AppContainer sandbox with TOML config for folder access control.
// Creates an AppContainer, grants folder access per config, and launches a
// target executable inside the sandbox.

#include "framework.h"

namespace Sandbox {

    // -----------------------------------------------------------------------
    // Folder access level
    // -----------------------------------------------------------------------
    enum class AccessLevel { Read, Write, ReadWrite };

    struct FolderEntry {
        std::wstring path;
        AccessLevel  access;
    };

    // -----------------------------------------------------------------------
    // Check if the current process is already running inside an AppContainer
    // -----------------------------------------------------------------------
    inline bool IsRunningInAppContainer()
    {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
            return false;

        DWORD isAppContainer = 0;
        DWORD size = sizeof(isAppContainer);
        BOOL ok = GetTokenInformation(hToken, TokenIsAppContainer, &isAppContainer, size, &size);
        CloseHandle(hToken);

        return ok && isAppContainer != 0;
    }

    // -----------------------------------------------------------------------
    // Get the folder that contains the running exe
    // -----------------------------------------------------------------------
    inline std::wstring GetExeFolder()
    {
        wchar_t path[MAX_PATH]{};
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        std::wstring folder(path);
        auto pos = folder.find_last_of(L"\\/");
        if (pos != std::wstring::npos)
            folder.resize(pos);
        return folder;
    }

    // -----------------------------------------------------------------------
    // Minimal TOML parser for our config format:
    //
    //   [read]
    //   "C:\some\path"
    //   C:\another\path
    //
    //   [write]
    //   "C:\logs"
    //
    //   [readwrite]
    //   "C:\projects"
    //
    // -----------------------------------------------------------------------
    inline std::vector<FolderEntry> LoadConfig(const std::wstring& configPath)
    {
        std::vector<FolderEntry> entries;

        HANDLE hFile = CreateFileW(configPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE)
            return entries;

        // Read entire file
        DWORD fileSize = GetFileSize(hFile, nullptr);
        if (fileSize == 0 || fileSize == INVALID_FILE_SIZE) {
            CloseHandle(hFile);
            return entries;
        }
        std::string buf(fileSize, '\0');
        DWORD bytesRead = 0;
        ReadFile(hFile, &buf[0], fileSize, &bytesRead, nullptr);
        CloseHandle(hFile);

        // Convert UTF-8 to wide
        int wideLen = MultiByteToWideChar(CP_UTF8, 0, buf.c_str(), (int)bytesRead, nullptr, 0);
        std::wstring content(wideLen, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, buf.c_str(), (int)bytesRead, &content[0], wideLen);

        // Parse line by line
        AccessLevel currentLevel = AccessLevel::ReadWrite;
        std::wstringstream ss(content);
        std::wstring line;

        while (std::getline(ss, line)) {
            // Trim \r
            if (!line.empty() && line.back() == L'\r')
                line.pop_back();
            // Trim whitespace
            size_t start = line.find_first_not_of(L" \t");
            if (start == std::wstring::npos)
                continue;
            line = line.substr(start);
            size_t end = line.find_last_not_of(L" \t");
            if (end != std::wstring::npos)
                line.resize(end + 1);

            if (line.empty() || line[0] == L'#')
                continue;

            // Section headers
            if (line == L"[read]") {
                currentLevel = AccessLevel::Read;
                continue;
            }
            if (line == L"[write]") {
                currentLevel = AccessLevel::Write;
                continue;
            }
            if (line == L"[readwrite]") {
                currentLevel = AccessLevel::ReadWrite;
                continue;
            }

            // Strip quotes if present
            if (line.size() >= 2 && line.front() == L'"' && line.back() == L'"')
                line = line.substr(1, line.size() - 2);

            if (!line.empty()) {
                entries.push_back({ line, currentLevel });
            }
        }

        return entries;
    }

    // -----------------------------------------------------------------------
    // Grant folder access with specific permissions
    // -----------------------------------------------------------------------
    inline bool GrantFolderAccess(PSID pSid, const std::wstring& folder, AccessLevel level)
    {
        DWORD permissions = 0;
        switch (level) {
        case AccessLevel::Read:
            permissions = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
            break;
        case AccessLevel::Write:
            permissions = FILE_GENERIC_WRITE;
            break;
        case AccessLevel::ReadWrite:
            permissions = FILE_ALL_ACCESS;
            break;
        }

        EXPLICIT_ACCESSW ea{};
        ea.grfAccessPermissions = permissions;
        ea.grfAccessMode = SET_ACCESS;
        ea.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(pSid);

        PACL pOldDacl = nullptr;
        PSECURITY_DESCRIPTOR pSD = nullptr;
        DWORD rc = GetNamedSecurityInfoW(
            folder.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, &pOldDacl, nullptr, &pSD);
        if (rc != ERROR_SUCCESS)
            return false;

        PACL pNewDacl = nullptr;
        rc = SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl);
        if (pSD) LocalFree(pSD);
        if (rc != ERROR_SUCCESS)
            return false;

        rc = SetNamedSecurityInfoW(
            const_cast<LPWSTR>(folder.c_str()), SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION, nullptr, nullptr, pNewDacl, nullptr);
        LocalFree(pNewDacl);
        return rc == ERROR_SUCCESS;
    }

    // -----------------------------------------------------------------------
    // Launch an executable inside an AppContainer sandbox.
    // Waits for the child to finish, relays its stdout/stderr to our console,
    // and returns the child's exit code.
    // If we are already inside the container, just launch directly.
    // -----------------------------------------------------------------------
    inline int RunSandboxed(const std::wstring& configPath,
                            const std::wstring& exePath,
                            const std::wstring& exeArgs,
                            bool strictIsolation = false,
                            bool allowNetwork = false)
    {
        const wchar_t* kContainerName = L"SandyPythonSandbox";
        const wchar_t* kDisplayName   = L"Sandy Sandbox";
        const wchar_t* kDescription   = L"Sandboxed environment for running executables";

        // --- Create or open the AppContainer profile ---
        PSID pContainerSid = nullptr;
        HRESULT hr = CreateAppContainerProfile(
            kContainerName, kDisplayName, kDescription,
            nullptr, 0, &pContainerSid);

        if (HRESULT_CODE(hr) == ERROR_ALREADY_EXISTS) {
            hr = DeriveAppContainerSidFromAppContainerName(kContainerName, &pContainerSid);
        }
        if (FAILED(hr) || !pContainerSid) {
            fprintf(stderr, "[Error] Could not create AppContainer (0x%08X).\n", hr);
            return 1;
        }

        // --- Grant exe folder READ access to the container ---
        std::wstring exeFolder = GetExeFolder();
        if (!GrantFolderAccess(pContainerSid, exeFolder, AccessLevel::Read)) {
            fprintf(stderr, "[Error] Could not grant access to exe folder: %ls\n", exeFolder.c_str());
            FreeSid(pContainerSid);
            return 1;
        }

        // --- Also grant read access to the directory containing the target executable ---
        std::wstring targetFolder = exePath;
        auto slashPos = targetFolder.find_last_of(L"\\/");
        if (slashPos != std::wstring::npos) {
            targetFolder.resize(slashPos);
            if (targetFolder != exeFolder) {
                if (!GrantFolderAccess(pContainerSid, targetFolder, AccessLevel::Read)) {
                    fprintf(stderr, "[Warning] Could not grant access to: %ls\n", targetFolder.c_str());
                    fprintf(stderr, "          Run as Administrator to modify folder ACLs.\n");
                }
            }
        }

        // --- Grant configured folder access ---
        auto configEntries = LoadConfig(configPath);
        bool grantFailed = false;
        for (auto& entry : configEntries) {
            if (!GrantFolderAccess(pContainerSid, entry.path, entry.access)) {
                fprintf(stderr, "[Warning] Could not grant access to: %ls\n", entry.path.c_str());
                grantFailed = true;
            }
        }
        if (grantFailed) {
            fprintf(stderr, "          Run as Administrator to modify folder ACLs.\n");
        }

        // Print config summary
        printf("Sandy - AppContainer Sandbox\n");
        printf("Config:     %ls\n", configPath.c_str());
        printf("Executable: %ls\n", exePath.c_str());
        if (!exeArgs.empty())
            printf("Arguments:  %ls\n", exeArgs.c_str());
        printf("Folders:    %zu configured\n", configEntries.size());
        for (auto& e : configEntries) {
            const char* tag = "[RW]";
            if (e.access == AccessLevel::Read) tag = "[R] ";
            else if (e.access == AccessLevel::Write) tag = "[W] ";
            printf("  %s %ls\n", tag, e.path.c_str());
        }
        printf("---\n");
        if (strictIsolation)
            printf("Mode:       STRICT (system folders blocked)\n");
        printf("Network:    %s\n", allowNetwork ? "ALLOWED" : "BLOCKED");

        // --- Prepare capabilities ---
        // internetClient capability SID for network access
        SID_AND_ATTRIBUTES caps[1] = {};
        DWORD capCount = 0;
        PSID pNetSid = nullptr;

        if (allowNetwork) {
            SID_IDENTIFIER_AUTHORITY appAuthority = SECURITY_APP_PACKAGE_AUTHORITY;
            if (AllocateAndInitializeSid(&appAuthority, 
                SECURITY_BUILTIN_APP_PACKAGE_RID_COUNT,
                SECURITY_CAPABILITY_BASE_RID,
                SECURITY_CAPABILITY_INTERNET_CLIENT,
                0, 0, 0, 0, 0, 0, &pNetSid))
            {
                caps[0].Sid = pNetSid;
                caps[0].Attributes = SE_GROUP_ENABLED;
                capCount = 1;
            }
        }

        SECURITY_CAPABILITIES sc{};
        sc.AppContainerSid = pContainerSid;
        sc.Capabilities = capCount > 0 ? caps : nullptr;
        sc.CapabilityCount = capCount;

        // --- Build STARTUPINFOEX with the container attribute ---
        // With strict isolation, we need 2 attributes: security capabilities + opt-out
        DWORD attrCount = strictIsolation ? 2 : 1;
        SIZE_T attrSize = 0;
        InitializeProcThreadAttributeList(nullptr, attrCount, 0, &attrSize);
        std::vector<BYTE> attrBuf(attrSize);
        auto pAttrList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrBuf.data());
        if (!InitializeProcThreadAttributeList(pAttrList, attrCount, 0, &attrSize)) {
            fprintf(stderr, "[Error] InitializeProcThreadAttributeList failed.\n");
            FreeSid(pContainerSid);
            return 1;
        }

        if (!UpdateProcThreadAttribute(pAttrList, 0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            &sc, sizeof(sc), nullptr, nullptr))
        {
            fprintf(stderr, "[Error] UpdateProcThreadAttribute (security) failed.\n");
            DeleteProcThreadAttributeList(pAttrList);
            FreeSid(pContainerSid);
            return 1;
        }

        // When strict isolation is enabled, opt out of ALL_APPLICATION_PACKAGES.
        // This prevents the process from matching ACLs that grant read access to
        // all UWP/AppContainer apps (system folders like C:\Windows, Program Files).
        DWORD allAppPackagesPolicy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
        if (strictIsolation) {
            if (!UpdateProcThreadAttribute(pAttrList, 0,
                PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                &allAppPackagesPolicy, sizeof(allAppPackagesPolicy), nullptr, nullptr))
            {
                fprintf(stderr, "[Error] UpdateProcThreadAttribute (isolation policy) failed.\n");
                DeleteProcThreadAttributeList(pAttrList);
                FreeSid(pContainerSid);
                return 1;
            }
        }

        // --- Create pipes for child stdout/stderr ---
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = TRUE;
        sa.lpSecurityDescriptor = nullptr;

        HANDLE hReadPipe = nullptr, hWritePipe = nullptr;
        if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
            fprintf(stderr, "[Error] Could not create output pipe.\n");
            DeleteProcThreadAttributeList(pAttrList);
            FreeSid(pContainerSid);
            return 1;
        }
        SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

        STARTUPINFOEXW siex{};
        siex.StartupInfo.cb = sizeof(siex);
        siex.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        siex.StartupInfo.hStdOutput = hWritePipe;
        siex.StartupInfo.hStdError  = hWritePipe;
        siex.StartupInfo.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
        siex.lpAttributeList = pAttrList;

        // --- Build command line ---
        std::wstring cmdLine = L"\"" + exePath + L"\"";
        if (!exeArgs.empty()) {
            cmdLine += L" " + exeArgs;
        }

        // --- Launch the target executable ---
        PROCESS_INFORMATION pi{};
        BOOL created = CreateProcessW(
            nullptr, &cmdLine[0], nullptr, nullptr, TRUE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            nullptr, exeFolder.c_str(), &siex.StartupInfo, &pi);

        // Close write end in parent so ReadFile gets EOF when child exits
        CloseHandle(hWritePipe);
        DeleteProcThreadAttributeList(pAttrList);

        if (!created) {
            DWORD err = GetLastError();
            fprintf(stderr, "[Error] Could not launch: %ls (error %lu)\n", exePath.c_str(), err);
            CloseHandle(hReadPipe);
            FreeSid(pContainerSid);
            return 1;
        }

        CloseHandle(pi.hThread);

        // --- Read child output and relay to our stdout ---
        char buffer[4096];
        DWORD bytesRead = 0;
        HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);

        while (ReadFile(hReadPipe, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0) {
            DWORD written = 0;
            WriteFile(hStdout, buffer, bytesRead, &written, nullptr);
        }
        CloseHandle(hReadPipe);

        // --- Wait for child and get exit code ---
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);

        FreeSid(pContainerSid);
        if (pNetSid) FreeSid(pNetSid);

        return static_cast<int>(exitCode);
    }

    // -----------------------------------------------------------------------
    // Delete the AppContainer profile (best-effort cleanup)
    // -----------------------------------------------------------------------
    inline void CleanupSandbox()
    {
        DeleteAppContainerProfile(L"SandyPythonSandbox");
    }

} // namespace Sandbox
