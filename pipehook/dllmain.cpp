// =========================================================================
// dllmain.cpp — Sandy named-pipe interception hook (injected payload).
//
// Sandy injects this DLL before resuming the sandbox child's entry point.
// On load it reads the pipe map from the SANDY_PIPEHOOK environment variable
// and rewrites the name argument of the named-pipe APIs: when a program asks
// for a hard-coded "original" pipe, the call is retargeted to the
// container-local "local" pipe.  Both the server end (CreateNamedPipe) and
// the client end (CreateFile / WaitNamedPipe) rewrite identically, so they
// still meet on the same (renamed) object.
//
// Technique: import-address-table (IAT) rewriting by resolved address.  For
// each loaded module we scan the IAT and replace any slot that points at a
// hooked function with our own.  Address matching catches the call however
// the importer named it (kernel32, kernelbase, or an api-set forwarder). The
// scan covers modules loaded at injection time. Later loads, GetProcAddress,
// delay imports and native NT calls are outside this IAT-based contract.
//
// The static CRT avoids a dependency on an installed Visual C++ runtime.
// The payload has no manifest: it needs no side-by-side activation in LPAC.
// =========================================================================

#include <windows.h>
#include <winternl.h>
#include <vector>
#include <string>

#include "pipehook_protocol.h"

namespace {

    // --- The pipe map, parsed once at load ---------------------------------
    struct PipePair {
        std::wstring original;
        std::wstring local;
    };
    std::vector<PipePair> g_pairs;
    HMODULE g_selfModule = nullptr;

    // --- Real function pointers (the un-hooked implementations) ------------
    using CreateNamedPipeW_t = HANDLE (WINAPI*)(LPCWSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
    using CreateFileW_t      = HANDLE (WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    using WaitNamedPipeW_t   = BOOL   (WINAPI*)(LPCWSTR, DWORD);
    using CallNamedPipeW_t   = BOOL   (WINAPI*)(LPCWSTR, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, DWORD);

    CreateNamedPipeW_t g_realCreateNamedPipeW = nullptr;
    CreateFileW_t      g_realCreateFileW      = nullptr;
    WaitNamedPipeW_t   g_realWaitNamedPipeW   = nullptr;
    CallNamedPipeW_t   g_realCallNamedPipeW   = nullptr;

    // One hooked function: the addresses an importer's IAT slot may hold
    // (kernelbase and kernel32 forms) plus the hook that replaces them.
    struct HookTarget {
        void* addrs[2];   // nullptr-terminated set of matchable addresses
        void* hook;
    };
    HookTarget g_targets[4];
    int        g_targetCount = 0;

    // --- Name rewrite ------------------------------------------------------
    // Returns the name to pass to the real API: the mapped local name when
    // `name` matches an original, otherwise `name` unchanged.  The returned
    // pointer is valid for the duration of the call (the local string lives in
    // g_pairs for the process lifetime).
    LPCWSTR Rewrite(LPCWSTR name) {
        if (!name)
            return name;
        for (const auto& pair : g_pairs) {
            if (_wcsicmp(name, pair.original.c_str()) == 0)
                return pair.local.c_str();
        }
        return name;
    }

    // --- Hook implementations ---------------------------------------------
    HANDLE WINAPI HookCreateNamedPipeW(LPCWSTR name, DWORD openMode, DWORD pipeMode,
                                       DWORD maxInstances, DWORD outBuf, DWORD inBuf,
                                       DWORD timeout, LPSECURITY_ATTRIBUTES sa) {
        return g_realCreateNamedPipeW(Rewrite(name), openMode, pipeMode, maxInstances,
                                      outBuf, inBuf, timeout, sa);
    }

    HANDLE WINAPI HookCreateFileW(LPCWSTR name, DWORD access, DWORD share,
                                  LPSECURITY_ATTRIBUTES sa, DWORD disposition,
                                  DWORD flags, HANDLE templ) {
        return g_realCreateFileW(Rewrite(name), access, share, sa, disposition, flags, templ);
    }

    BOOL WINAPI HookWaitNamedPipeW(LPCWSTR name, DWORD timeout) {
        return g_realWaitNamedPipeW(Rewrite(name), timeout);
    }

    BOOL WINAPI HookCallNamedPipeW(LPCWSTR name, LPVOID inBuf, DWORD inSize,
                                   LPVOID outBuf, DWORD outSize, LPDWORD read, DWORD timeout) {
        return g_realCallNamedPipeW(Rewrite(name), inBuf, inSize, outBuf, outSize, read, timeout);
    }

    // --- Parsing -----------------------------------------------------------
    void ParsePipeMap() {
        DWORD needed = GetEnvironmentVariableW(SANDY_PIPEHOOK_ENV, nullptr, 0);
        if (needed == 0)
            return;
        std::wstring value(needed, L'\0');
        DWORD written = GetEnvironmentVariableW(SANDY_PIPEHOOK_ENV, &value[0], needed);
        if (written == 0 || written >= needed)
            return;
        value.resize(written);

        size_t pos = 0;
        while (pos < value.size()) {
            size_t rs = value.find(SANDY_PIPEHOOK_RS, pos);
            std::wstring record = value.substr(pos, rs == std::wstring::npos ? std::wstring::npos : rs - pos);
            size_t us = record.find(SANDY_PIPEHOOK_US);
            if (us != std::wstring::npos && us > 0 && us + 1 < record.size()) {
                g_pairs.push_back({ record.substr(0, us), record.substr(us + 1) });
            }
            if (rs == std::wstring::npos)
                break;
            pos = rs + 1;
        }
    }

    // --- Function resolution ----------------------------------------------
    void AddTarget(const char* name, void* hook, void** realOut) {
        HMODULE kernelbase = GetModuleHandleW(L"kernelbase.dll");
        HMODULE kernel32   = GetModuleHandleW(L"kernel32.dll");
        void* a = kernelbase ? reinterpret_cast<void*>(GetProcAddress(kernelbase, name)) : nullptr;
        void* b = kernel32   ? reinterpret_cast<void*>(GetProcAddress(kernel32, name))   : nullptr;
        void* real = a ? a : b;          // the implementation to call
        if (!real)
            return;
        *realOut = real;
        HookTarget& t = g_targets[g_targetCount++];
        t.addrs[0] = a;
        t.addrs[1] = (b != a) ? b : nullptr;
        t.hook = hook;
    }

    void ResolveTargets() {
        AddTarget("CreateNamedPipeW", &HookCreateNamedPipeW, reinterpret_cast<void**>(&g_realCreateNamedPipeW));
        AddTarget("CreateFileW",      &HookCreateFileW,      reinterpret_cast<void**>(&g_realCreateFileW));
        AddTarget("WaitNamedPipeW",   &HookWaitNamedPipeW,   reinterpret_cast<void**>(&g_realWaitNamedPipeW));
        AddTarget("CallNamedPipeW",   &HookCallNamedPipeW,   reinterpret_cast<void**>(&g_realCallNamedPipeW));
    }

    // --- IAT patching ------------------------------------------------------
    // Replace one IAT slot, restoring the page protection afterwards.
    bool ReplaceSlot(void** slot, void* hook) {
        DWORD prot = 0;
        if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &prot))
            return false;
        InterlockedExchangePointer(slot, hook);
        return VirtualProtect(slot, sizeof(void*), prot, &prot) != 0;
    }

    // Scan one module's import address table and redirect every slot that
    // currently points at a hooked function.
    bool PatchModule(HMODULE module) {
        if (!module || module == g_selfModule)
            return true;

        auto base = reinterpret_cast<BYTE*>(module);
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return false;
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return false;

        IMAGE_DATA_DIRECTORY importDir =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir.VirtualAddress == 0 || importDir.Size == 0)
            return true;

        auto import = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + importDir.VirtualAddress);
        for (; import->Name != 0; ++import) {
            if (import->FirstThunk == 0)
                continue;
            auto thunk = reinterpret_cast<void**>(base + import->FirstThunk);
            for (; *thunk != nullptr; ++thunk) {
                void* current = *thunk;
                for (int i = 0; i < g_targetCount; ++i) {
                    if (current == g_targets[i].addrs[0] ||
                        (g_targets[i].addrs[1] && current == g_targets[i].addrs[1])) {
                        if (!ReplaceSlot(thunk, g_targets[i].hook))
                            return false;
                        break;
                    }
                }
            }
        }
        return true;
    }

    bool PatchAllLoadedModules() {
        PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
        if (!peb || !peb->Ldr)
            return false;
        LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
        for (LIST_ENTRY* cur = head->Flink; cur != head; cur = cur->Flink) {
            auto entry = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            if (!PatchModule(reinterpret_cast<HMODULE>(entry->DllBase)))
                return false;
        }
        return true;
    }

    bool Install() {
        ParsePipeMap();
        if (g_pairs.empty())
            return false;
        ResolveTargets();
        if (g_targetCount != 4)
            return false;
        // DllMain holds the loader lock, so the module list is stable here.
        // LdrDllNotification fires BEFORE import resolution and cannot patch
        // resolved IAT addresses reliably. Do not claim later-load coverage.
        return PatchAllLoadedModules();
    }

} // namespace

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_selfModule = module;
        // Static CRT needs thread notifications. Do not disable them.
        return Install() ? TRUE : FALSE;
    }
    return TRUE;
}
