// =========================================================================
// SandboxStatus.h — Status, cleanup, and explain command handlers
//
// Implements --status, --cleanup, and --explain CLI commands.
// Extracted from sandy.cpp for readability.
// =========================================================================
#pragma once

#include "SandboxTypes.h"
#include "SandboxGrants.h"
#include "SandboxCleanup.h"
#include "SandboxAudit.h"
#include "SandboxSavedProfile.h"
#include <sstream>

namespace Sandbox {

// EnumSandyProfiles() is defined in SandboxCleanup.h (included above)

// -----------------------------------------------------------------------
// Show active instances and stale state (--status [--json])
// -----------------------------------------------------------------------
inline int HandleStatus(bool json = false)
{
    // --- Collect data ---
    struct Inst { std::wstring uuid; DWORD pid; bool alive; };
    struct Wer  { DWORD pid; std::wstring exe; bool alive; };
    std::vector<Inst> insts;
    std::vector<Wer>  wers;
    std::vector<std::wstring> tasks;
    std::vector<std::wstring> profiles;
    int staleInstances = 0;
    int staleWer = 0;

    // Grants registry
    HKEY hGrants = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, Sandbox::kGrantsParentKey, 0,
                      KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hGrants) == ERROR_SUCCESS) {
        DWORD n = 0;
        RegQueryInfoKeyW(hGrants, 0, 0, 0, &n, 0, 0, 0, 0, 0, 0, 0);
        for (DWORD i = 0; i < n; i++) {
            wchar_t nm[128]; DWORD nl = 128;
            if (RegEnumKeyExW(hGrants, i, nm, &nl, 0, 0, 0, 0) != ERROR_SUCCESS) continue;
            std::wstring fk = std::wstring(Sandbox::kGrantsParentKey) + L"\\" + nm;
            HKEY hS = nullptr; DWORD pid = 0; ULONGLONG ct = 0;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, fk.c_str(), 0, KEY_READ, &hS) == ERROR_SUCCESS) {
                Sandbox::ReadPidAndCtime(hS, pid, ct); RegCloseKey(hS);
            }
            bool alive = Sandbox::IsProcessAlive(pid, ct);
            if (!alive) staleInstances++;
            insts.push_back({ nm, pid, alive });
        }
        RegCloseKey(hGrants);
    }

    // WER registry — F5/R8: uses ParseWEREntry + creation time for safe liveness
    HKEY hWER = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, Sandbox::kWERParentKey, 0,
                      KEY_READ, &hWER) == ERROR_SUCCESS) {
        DWORD vc = 0;
        RegQueryInfoKeyW(hWER, 0, 0, 0, 0, 0, 0, &vc, 0, 0, 0, 0);
        for (DWORD i = 0; i < vc; i++) {
            wchar_t nm[64]; DWORD nl = 64, ds = 0;
            if (RegEnumValueW(hWER, i, nm, &nl, 0, 0, 0, &ds) != ERROR_SUCCESS) continue;
            DWORD pid = (DWORD)_wtoi(nm);
            std::wstring rawData(ds / sizeof(wchar_t), L'\0');
            nl = 64;
            RegEnumValueW(hWER, i, nm, &nl, 0, 0, (BYTE*)&rawData[0], &ds);
            while (!rawData.empty() && rawData.back() == L'\0') rawData.pop_back();
            std::wstring exe; ULONGLONG werCtime = 0;
            Sandbox::ParseWEREntry(rawData, exe, werCtime);
            bool alive = Sandbox::IsProcessAlive(pid, werCtime);
            if (!alive) staleWer++;
            wers.push_back({ pid, exe, alive });
        }
        RegCloseKey(hWER);
    }

    // Scheduled tasks
    {
        std::wstring schtasksExe = GetSystemDirectoryPath() + L"schtasks.exe";
        std::wstring cmd = L"\"" + schtasksExe + L"\" /Query /FO CSV /NH";
        HANDLE hR = 0, hW = 0;
        SECURITY_ATTRIBUTES sa = { sizeof(sa), 0, TRUE };
        if (CreatePipe(&hR, &hW, &sa, 0)) {
            STARTUPINFOW si = { sizeof(si) };
            si.hStdOutput = hW; si.hStdError = hW;
            si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION pi{};
            if (CreateProcessW(schtasksExe.c_str(), (LPWSTR)cmd.c_str(), 0, 0, TRUE,
                               CREATE_NO_WINDOW, 0, 0, &si, &pi)) {
                CloseHandle(hW);
                std::string out; char buf[4096]; DWORD br;
                while (ReadFile(hR, buf, sizeof(buf), &br, 0) && br > 0) out.append(buf, br);
                CloseHandle(hR);
                WaitForSingleObject(pi.hProcess, 5000);
                CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
                std::istringstream ss(out); std::string line;
                while (std::getline(ss, line)) {
                    std::wstring wl(line.begin(), line.end());
                    if (wl.find(Sandbox::kCleanupTaskPrefix) == std::wstring::npos) continue;
                    auto q1 = wl.find(L'"'), q2 = wl.find(L'"', q1 + 1);
                    if (q1 != std::wstring::npos && q2 != std::wstring::npos) {
                        auto tp = wl.substr(q1 + 1, q2 - q1 - 1);
                        auto bs = tp.find_last_of(L'\\');
                        tasks.push_back(bs != std::wstring::npos ? tp.substr(bs + 1) : tp);
                    }
                }
            } else { CloseHandle(hR); CloseHandle(hW); }
        }
    }

    profiles = EnumSandyProfiles();

    // Saved profiles (persistent named profiles)
    auto savedProfiles = EnumSavedProfiles();

    // --- Output ---
    if (json) {
        auto esc = [](const std::wstring& s) {
            std::string r; for (wchar_t c : s) {
                if (c == L'"') r += "\\\""; else if (c == L'\\') r += "\\\\";
                else if (c < 128) r += (char)c;
                else { char b[8]; snprintf(b, 8, "\\u%04X", (unsigned)c); r += b; }
            } return r;
        };
        printf("{\"instances\":[");
        for (size_t i = 0; i < insts.size(); i++)
            printf("%s{\"uuid\":\"%s\",\"pid\":%lu,\"status\":\"%s\"}",
                   i ? "," : "", esc(insts[i].uuid).c_str(),
                   insts[i].pid, insts[i].alive ? "active" : "stale");
        printf("],\"wer\":[");
        for (size_t i = 0; i < wers.size(); i++)
            printf("%s{\"pid\":%lu,\"exe\":\"%s\",\"status\":\"%s\"}",
                   i ? "," : "", wers[i].pid,
                   esc(wers[i].exe).c_str(), wers[i].alive ? "active" : "stale");
        printf("],\"tasks\":[");
        for (size_t i = 0; i < tasks.size(); i++)
            printf("%s\"%s\"", i ? "," : "", esc(tasks[i]).c_str());
        printf("],\"profiles\":[");
        for (size_t i = 0; i < profiles.size(); i++)
            printf("%s\"%s\"", i ? "," : "", esc(profiles[i]).c_str());
        printf("],\"saved_profiles\":[");
        for (size_t i = 0; i < savedProfiles.size(); i++)
            printf("%s{\"name\":\"%s\",\"type\":\"%s\",\"created\":\"%s\"}",
                   i ? "," : "", esc(savedProfiles[i].name).c_str(),
                   esc(savedProfiles[i].type).c_str(),
                   esc(savedProfiles[i].created).c_str());
        printf("],\"summary\":{\"instances\":%zu,\"stale_instances\":%d,\"wer\":%zu,\"stale_wer\":%d,\"tasks\":%zu,\"profiles\":%zu,\"saved_profiles\":%zu}}\n",
               insts.size(), staleInstances, wers.size(), staleWer, tasks.size(), profiles.size(), savedProfiles.size());
    } else {
        bool found = false;
        for (auto& x : insts) {
            printf("  [%s]  PID %-6lu  %ls%s\n",
                   x.alive ? "ACTIVE" : "STALE ", x.pid, x.uuid.c_str(),
                   x.alive ? "" : " (dead process)");
            found = true;
        }
        for (auto& w : wers) {
            printf("  [%s]  PID %-6lu  WER key for %ls%s\n",
                   w.alive ? "ACTIVE" : "STALE ", w.pid, w.exe.c_str(),
                   w.alive ? "" : " (dead process)");
            found = true;
        }
        for (auto& t : tasks) { printf("  [TASK]    %ls scheduled task exists\n", t.c_str()); found = true; }
        for (auto& p : profiles) { printf("  [PROFILE] %ls\n", p.c_str()); found = true; }
        for (auto& sp : savedProfiles) {
            printf("  [SAVED_PROFILE] %ls  (%ls, created: %ls)\n",
                   sp.name.c_str(), sp.type.c_str(), sp.created.c_str());
            found = true;
        }
        if (!found) printf("Sandy - no active instances or stale state.\n");
        else printf("Summary: %zu instance(s), %d stale instance(s), %zu WER entry/entries, %d stale WER, %zu task(s), %zu profile(s), %zu saved profile(s).\n",
                    insts.size(), staleInstances, wers.size(), staleWer, tasks.size(), profiles.size(), savedProfiles.size());
    }
    return 0;
}

// -----------------------------------------------------------------------
// Restore stale state from crashed runs (--cleanup)
// -----------------------------------------------------------------------
inline int HandleCleanup()
{
    // Enumerate all Sandy AppContainer profiles
    auto allProfiles = EnumSandyProfiles();

    // Filter to stale-only: preserve containers whose owning instance is live
    // AND containers belonging to saved profiles (permanent, never cleaned)
    auto liveContainers = Sandbox::GetLiveContainerNames();
    auto savedContainers = Sandbox::GetSavedProfileContainerNames();
    std::vector<std::wstring> staleProfiles;
    for (const auto& m : allProfiles) {
        if (liveContainers.count(m)) {
            printf("  [PROFILE] %ls -> SKIPPED (live instance)\n", m.c_str());
        } else if (savedContainers.count(m)) {
            printf("  [PROFILE] %ls -> SKIPPED (saved profile)\n", m.c_str());
        } else {
            staleProfiles.push_back(m);
        }
    }

    // Remove loopback exemptions for STALE profiles only
    Sandbox::ForceDisableLoopback(staleProfiles);

    Sandbox::RestoreStaleGrants();   // restores DACLs + deletes stale container profiles
    Sandbox::CleanStagingProfiles(); // roll back incomplete --create-profile operations
    Sandbox::RestoreStaleWER();
    Sandbox::DeleteStaleCleanupTasks();

    // Clean orphaned Sandy AppContainer profiles from Windows Mappings
    if (!staleProfiles.empty())
        printf("  Cleaning %zu orphaned AppContainer profile(s)...\n",
                staleProfiles.size());
    for (const auto& m : staleProfiles) {
        HRESULT hr = DeleteAppContainerProfile(m.c_str());
        if (SUCCEEDED(hr))
            printf("  [PROFILE] %ls -> deleted\n", m.c_str());
        else
            fprintf(stderr, "  [PROFILE] %ls -> FAILED\n", m.c_str());
    }

    // Remove test registry tree (tests use Software\Sandy\Test\ instead of
    // production keys so they never interfere with real sandbox state)
    if (RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Sandy\\Test") == ERROR_SUCCESS)
        printf("  [TEST]    Software\\Sandy\\Test -> cleaned\n");

    printf("Sandy - cleanup complete.\n");
    return 0;
}

// -----------------------------------------------------------------------
// Explain an exit code (--explain <code>)
// -----------------------------------------------------------------------
inline int HandleExplain(const wchar_t* codeStr)
{
    // Parse code (decimal, hex, or negative)
    wchar_t* end = nullptr;
    long long code = wcstoll(codeStr, &end, 0);
    if (end == codeStr || *end != L'\0') {
        fprintf(stderr, "Error: '%ls' is not a valid number.\n", codeStr);
        return SandyExit::InternalError;
    }
    DWORD dw = static_cast<DWORD>(code);

    printf("Code: %lld (0x%08X)\n\n", code, dw);

    // Sandy exit codes
    struct { int code; const char* name; const char* desc; } sandyCodes[] = {
        { 0,   "Success",       "Child exited cleanly, or info command succeeded" },
        { 125, "InternalError", "Sandy internal / general error" },
        { 126, "CannotExec",    "CreateProcess failed (permission denied, bad format)" },
        { 127, "NotFound",      "Executable not found on disk" },
        { 128, "ConfigError",   "Configuration error (invalid TOML, wrong-mode keys)" },
        { 129, "SetupError",    "Sandbox setup failed (token, SID, ACL, pipes)" },
        { 130, "Timeout",       "Child killed by Sandy's timeout watchdog" },
        { 131, "ChildCrash",    "Child crashed (NTSTATUS crash code detected)" },
    };
    for (auto& s : sandyCodes) {
        if (s.code == static_cast<int>(code)) {
            printf("Sandy exit code: %s\n  %s\n", s.name, s.desc);
            return 0;
        }
    }

    // Known NTSTATUS crash codes
    struct { DWORD code; const char* name; } crashCodes[] = {
        { 0xC0000005, "STATUS_ACCESS_VIOLATION (SIGSEGV equivalent)" },
        { 0xC00000FD, "STATUS_STACK_OVERFLOW" },
        { 0xC0000409, "STATUS_STACK_BUFFER_OVERRUN (/GS security check failure)" },
        { 0x80000003, "STATUS_BREAKPOINT (INT 3 / debugger break)" },
        { 0xC0000374, "STATUS_HEAP_CORRUPTION" },
        { 0xC0000096, "STATUS_PRIVILEGED_INSTRUCTION" },
        { 0xC000001D, "STATUS_ILLEGAL_INSTRUCTION" },
        { 0xC0000094, "STATUS_INTEGER_DIVIDE_BY_ZERO" },
        { 0xC000008C, "STATUS_ARRAY_BOUNDS_EXCEEDED" },
        { 0xC0000135, "STATUS_DLL_NOT_FOUND" },
        { 0xC0000142, "STATUS_DLL_INIT_FAILED" },
        { 0x40010004, "STATUS_DEBUGGER_INACTIVE (WerFault)" },
    };
    for (auto& c : crashCodes) {
        if (c.code == dw) {
            printf("NTSTATUS: %s\n", c.name);
            return 0;
        }
    }

    // Try FormatMessage for Win32 or NTSTATUS
    wchar_t* msgBuf = nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD len = FormatMessageW(flags, nullptr, dw, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
                               reinterpret_cast<LPWSTR>(&msgBuf), 0, nullptr);
    if (len > 0 && msgBuf) {
        // Strip trailing newline
        while (len > 0 && (msgBuf[len-1] == L'\n' || msgBuf[len-1] == L'\r')) msgBuf[--len] = 0;
        printf("System message: %ls\n", msgBuf);
        LocalFree(msgBuf);
    } else {
        // Try NTSTATUS via ntdll
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            len = FormatMessageW(flags | FORMAT_MESSAGE_FROM_HMODULE, hNtdll, dw,
                                 MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
                                 reinterpret_cast<LPWSTR>(&msgBuf), 0, nullptr);
            if (len > 0 && msgBuf) {
                while (len > 0 && (msgBuf[len-1] == L'\n' || msgBuf[len-1] == L'\r')) msgBuf[--len] = 0;
                printf("NTSTATUS message: %ls\n", msgBuf);
                LocalFree(msgBuf);
            } else {
                printf("Unknown code.\n");
            }
        } else {
            printf("Unknown code.\n");
        }
    }

    // Additional context for NTSTATUS range
    if (dw >= 0x80000000)
        printf("  (NTSTATUS range: 0x8* = warning, 0xC* = error/crash)\n");
    else if (code >= 1 && code <= 124)
        printf("  (In Sandy: this would be the child process's own exit code)\n");

    return 0;
}

} // namespace Sandbox
