// Named-pipe interception payload. Embedded in Sandy; loaded before app entry.
#pragma once

#include "SandboxTypes.h"
#include "Resource.h"
#include "../pipehook/pipehook_protocol.h"
#include <tlhelp32.h>
#include <userenv.h>
#pragma comment(lib, "userenv.lib")

namespace Sandbox {

    inline std::wstring SerializePipeMap(const std::vector<PipeMapEntry>& pipes)
    {
        std::wstring value;
        for (const auto& entry : pipes) {
            if (!value.empty()) value += SANDY_PIPEHOOK_RS;
            value += entry.original;
            value += SANDY_PIPEHOOK_US;
            value += entry.local;
        }
        return value;
    }

    // Each run owns one file, even when several runs share a saved profile.
    inline std::wstring PipeHookPath(const std::wstring& sid, const std::wstring& instanceId)
    {
        PWSTR folder = nullptr;
        HRESULT hr = GetAppContainerFolderPath(sid.c_str(), &folder);
        if (FAILED(hr) || !folder) {
            g_logger.LogFmt(L"PIPEHOOK: GetAppContainerFolderPath failed (hr=0x%08lX)", hr);
            return {};
        }
        std::wstring path = std::wstring(folder) + L"\\sandy_pipe_hook_" + instanceId + L".dll";
        CoTaskMemFree(folder);
        return path;
    }

    // The run ledger records this path BEFORE creation. The container's own
    // folder supplies access; no host directory or system ACL is changed.
    inline bool ExtractEmbeddedHookDll(const std::wstring& path)
    {
        HRSRC res = FindResourceW(nullptr, MAKEINTRESOURCEW(IDR_SANDY_PIPEHOOK), RT_RCDATA);
        HGLOBAL loaded = res ? LoadResource(nullptr, res) : nullptr;
        DWORD size = res ? SizeofResource(nullptr, res) : 0;
        void* data = loaded ? LockResource(loaded) : nullptr;
        if (!data || !size) {
            g_logger.Log(L"PIPEHOOK: embedded DLL resource missing or unreadable");
            return false;
        }
        HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                                  CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            g_logger.LogFmt(L"PIPEHOOK: cannot create %s (error %lu)", path.c_str(), GetLastError());
            return false;
        }
        DWORD written = 0;
        BOOL ok = WriteFile(file, data, size, &written, nullptr);
        DWORD error = ok ? ERROR_WRITE_FAULT : GetLastError();
        CloseHandle(file);
        if (!ok || written != size) {
            g_logger.LogFmt(L"PIPEHOOK: write failed for %s (error %lu)", path.c_str(), error);
            return false;
        }
        g_logger.LogFmt(L"PIPEHOOK: extracted hook DLL -> %s (%lu bytes)", path.c_str(), size);
        return true;
    }

    inline bool ChildArchitectureMismatch(HANDLE process)
    {
        BOOL selfWow = FALSE, childWow = FALSE;
        return !IsWow64Process(GetCurrentProcess(), &selfWow) ||
               !IsWow64Process(process, &childWow) || selfWow != childWow;
    }

    inline bool ChildHasModule(DWORD pid, const std::wstring& path)
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
        if (snap == INVALID_HANDLE_VALUE) return false;
        MODULEENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        bool found = false;
        if (Module32FirstW(snap, &entry)) {
            do {
                if (_wcsicmp(entry.szExePath, path.c_str()) == 0) {
                    found = true;
                    break;
                }
            } while (Module32NextW(snap, &entry));
        }
        CloseHandle(snap);
        return found;
    }

    inline bool InjectHookDll(HANDLE process, DWORD pid, const std::wstring& path)
    {
        if (ChildArchitectureMismatch(process)) {
            g_logger.Log(L"PIPEHOOK: cannot verify matching child architecture");
            return false;
        }
        SIZE_T bytes = (path.size() + 1) * sizeof(wchar_t);
        void* remote = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remote) {
            g_logger.LogFmt(L"PIPEHOOK: VirtualAllocEx failed (error %lu)", GetLastError());
            return false;
        }
        bool ok = false, threadFinished = false;
        HANDLE thread = nullptr;
        do {
            if (!WriteProcessMemory(process, remote, path.c_str(), bytes, nullptr)) {
                g_logger.LogFmt(L"PIPEHOOK: WriteProcessMemory failed (error %lu)", GetLastError());
                break;
            }
            auto loadLibrary = reinterpret_cast<LPTHREAD_START_ROUTINE>(
                GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
            if (!loadLibrary) break;
            thread = CreateRemoteThread(process, nullptr, 0, loadLibrary, remote, 0, nullptr);
            if (!thread) {
                g_logger.LogFmt(L"PIPEHOOK: CreateRemoteThread failed (error %lu)", GetLastError());
                break;
            }
            if (WaitForSingleObject(thread, 15000) != WAIT_OBJECT_0) {
                g_logger.Log(L"PIPEHOOK: remote LoadLibrary did not complete in time");
                break;
            }
            threadFinished = true;
            // HMODULE is pointer-sized; a thread exit DWORD would truncate it.
            // DllMain fails the load if it cannot install the hooks.
            if (!ChildHasModule(pid, path)) {
                DWORD result = 0;
                GetExitCodeThread(thread, &result);
                g_logger.LogFmt(L"PIPEHOOK: load/install failed (thread result 0x%08lX)", result);
                break;
            }
            ok = true;
            g_logger.Log(L"PIPEHOOK: hook DLL injected and imports patched");
        } while (false);

        if (thread) CloseHandle(thread);
        // A timed-out loader may still read its argument. The caller aborts
        // the child, which frees that memory along with the rest of its address space.
        if (!thread || threadFinished) VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        return ok;
    }

} // namespace Sandbox

