// =========================================================================
// SandboxProcess.h — Process launch, job objects, and timeout
//
// Self-contained utilities for launching sandboxed child processes,
// enforcing resource limits, and managing timeouts.
// Each function is an independently testable semantic unit.
// =========================================================================
#pragma once

#include "SandboxTypes.h"

namespace Sandbox {

    // -----------------------------------------------------------------------
    // GetSystemDirectoryPath — resolve %SystemRoot%\System32\ safely.
    //
    // Returns: e.g. L"C:\\Windows\\System32\\"  (always trailing backslash)
    // Used to build fully-qualified paths for host-side tool launches,
    // preventing search-order hijacking from CWD or PATH.
    // -----------------------------------------------------------------------
    inline std::wstring GetSystemDirectoryPath()
    {
        wchar_t buf[MAX_PATH];
        UINT len = GetSystemDirectoryW(buf, MAX_PATH);
        if (len == 0 || len >= MAX_PATH) return L"";
        std::wstring dir(buf, len);
        if (dir.back() != L'\\') dir += L'\\';
        return dir;
    }

    // -----------------------------------------------------------------------
    // RunHiddenProcess — run a process with no window and wait for exit.
    //
    // Inputs:  cmdLine     — full command line to execute
    //          timeoutMs   — max wait time in milliseconds
    //          appPath     — fully-qualified exe path for lpApplicationName
    //                        (empty = use cmdLine search order — AVOID for
    //                        system tools to prevent search-order hijacking)
    // Returns: process exit code, or (DWORD)-1 on failure
    // Verifiable: exit code reflects the child's actual result
    // -----------------------------------------------------------------------
    inline DWORD RunHiddenProcess(const std::wstring& cmdLine, DWORD timeoutMs = 5000,
                                  const std::wstring& appPath = L"")
    {
        STARTUPINFOW si = { sizeof(si) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi = {};
        std::wstring cmd = cmdLine;  // CreateProcessW needs mutable buffer
        const wchar_t* app = appPath.empty() ? nullptr : appPath.c_str();
        if (!CreateProcessW(app, &cmd[0], nullptr, nullptr, FALSE,
                           CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
            return (DWORD)-1;
        DWORD exitCode = (DWORD)-1;
        if (WaitForSingleObject(pi.hProcess, timeoutMs) == WAIT_OBJECT_0)
            GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return exitCode;
    }

    // -----------------------------------------------------------------------
    // RunSchtasks — execute a schtasks command silently.
    //
    // Inputs:  args — schtasks arguments (without "schtasks" prefix)
    // Returns: schtasks exit code (0 = success)
    // Verifiable: return value indicates success/failure
    // -----------------------------------------------------------------------
    inline DWORD RunSchtasks(const std::wstring& args)
    {
        std::wstring schtasksExe = GetSystemDirectoryPath() + L"schtasks.exe";
        return RunHiddenProcess(L"\"" + schtasksExe + L"\" " + args, 15000, schtasksExe);
    }

    // -----------------------------------------------------------------------
    // Timeout watchdog — terminates a child process after N seconds.
    // Used as a thread function with CreateThread.
    // -----------------------------------------------------------------------
    struct TimeoutContext {
        HANDLE hProcess;
        DWORD  seconds;
        bool   timedOut;
    };

    static DWORD WINAPI TimeoutThread(LPVOID param)
    {
        auto* ctx = static_cast<TimeoutContext*>(param);
        ctx->timedOut = false;
        if (WaitForSingleObject(ctx->hProcess, ctx->seconds * 1000) == WAIT_TIMEOUT) {
            ctx->timedOut = true;
            TerminateProcess(ctx->hProcess, 1);
        }
        return 0;
    }

    // (SetupOutputPipe removed — console passthrough: child inherits console)

    // -----------------------------------------------------------------------
    // SetupStdinHandle — resolve the stdin handle for the child process.
    //
    // Inputs:  stdinMode — "" (inherit), "NUL" (disable), or file path
    // Outputs: hStdin     — resolved handle for STARTUPINFO.hStdInput
    //          hStdinFile — opened file handle (caller must close), or nullptr
    // Returns: true on success, false if file open failed
    // Verifiable: handle is valid and correctly sourced
    // -----------------------------------------------------------------------
    inline bool SetupStdinHandle(const std::wstring& stdinMode,
                                 HANDLE& hStdin, HANDLE& hStdinFile)
    {
        hStdin = GetStdHandle(STD_INPUT_HANDLE);
        hStdinFile = nullptr;

        if (stdinMode.empty())
            return true;  // inherit parent's stdin

        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = TRUE;

        const wchar_t* stdinTarget = (_wcsicmp(stdinMode.c_str(), L"NUL") == 0)
            ? L"NUL" : stdinMode.c_str();
        hStdinFile = CreateFileW(stdinTarget, GENERIC_READ, FILE_SHARE_READ,
                                &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hStdinFile == INVALID_HANDLE_VALUE) {
            g_logger.Log((L"ERROR: stdin open failed -> " + std::wstring(stdinTarget)).c_str());
            hStdinFile = nullptr;
            return false;
        }
        hStdin = hStdinFile;
        return true;
    }

    // -----------------------------------------------------------------------
    // LaunchChildProcess — create the child process in the sandbox.
    //
    // Console passthrough: stdout/stderr are inherited from the parent so
    // the child sees a real console (TTY).  Only stdin is explicitly set
    // when configured (NUL or file redirect).
    //
    // Inputs:  isRestricted    — true for restricted-token, false for AppContainer
    //          hToken          — restricted token handle (only if isRestricted)
    //          pAttrList       — attribute list (capabilities/child-policy)
    //          envBlock        — environment block (empty = inherit)
    //          workDir         — working directory
    //          exePath/exeArgs — target executable and arguments
    //          hStdin          — stdin handle for the child (nullptr = inherit)
    // Returns: true on success, pi filled in
    // Verifiable: pi.hProcess is valid and pi.dwProcessId > 0 on success
    // -----------------------------------------------------------------------
    inline bool LaunchChildProcess(bool isRestricted, HANDLE hToken,
                                   LPPROC_THREAD_ATTRIBUTE_LIST pAttrList,
                                   std::vector<wchar_t>& envBlock,
                                   const std::wstring& workDir,
                                   const std::wstring& exePath,
                                   const std::wstring& exeArgs,
                                   HANDLE hStdin,
                                   PROCESS_INFORMATION& pi)
    {
        STARTUPINFOEXW siex{};
        siex.StartupInfo.cb = sizeof(siex);

        // Only set STARTF_USESTDHANDLES when stdin is explicitly redirected
        // (NUL or file). When stdin is inherited (hStdin = parent's stdin),
        // we skip the flag entirely so stdout/stderr stay on the console.
        HANDLE hParentStdin = GetStdHandle(STD_INPUT_HANDLE);
        if (hStdin && hStdin != hParentStdin) {
            siex.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            siex.StartupInfo.hStdInput  = hStdin;
            siex.StartupInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
            siex.StartupInfo.hStdError  = GetStdHandle(STD_ERROR_HANDLE);
        }
        if (pAttrList) siex.lpAttributeList = pAttrList;

        std::wstring cmdLine = L"\"" + exePath + L"\"";
        if (!exeArgs.empty())
            cmdLine += L" " + exeArgs;

        DWORD createFlags = CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED;
        if (pAttrList) createFlags |= EXTENDED_STARTUPINFO_PRESENT;

        BOOL created;
        if (isRestricted) {
            created = CreateProcessAsUser(
                hToken, nullptr, &cmdLine[0], nullptr, nullptr, TRUE,
                createFlags,
                envBlock.empty() ? nullptr : envBlock.data(),
                workDir.c_str(),
                pAttrList ? reinterpret_cast<LPSTARTUPINFOW>(&siex) : &siex.StartupInfo,
                &pi);
        } else {
            created = CreateProcessW(
                nullptr, &cmdLine[0], nullptr, nullptr, TRUE,
                createFlags,
                envBlock.empty() ? nullptr : envBlock.data(),
                workDir.c_str(), reinterpret_cast<LPSTARTUPINFOW>(&siex), &pi);
        }

        if (!created) {
            DWORD err = GetLastError();
            g_logger.LogFmt(L"LAUNCH_FAILED: %s (error %lu)", exePath.c_str(), err);
            g_logger.LogFmt(L"LAUNCH_DIAG: cmdline=%zu chars, envBlock=%zu wchars (%s)",
                            cmdLine.size(), envBlock.size(),
                            envBlock.empty() ? L"inherited" : L"custom");
            g_logger.LogFmt(L"LAUNCH_DIAG: workdir=%s", workDir.c_str());
            return false;
        }

        // Forensic: log the launch
        g_logger.LogFmt(L"LAUNCH: PID %lu, cmd=\"%s\"", pi.dwProcessId, cmdLine.c_str());
        return true;
    }

    // -----------------------------------------------------------------------
    // AssignJobObject — create and assign a job object for resource limits.
    //
    // Inputs:  config    — sandbox config with memory/process/clipboard limits
    //          hProcess  — child process handle (suspended)
    // Returns: job object handle (caller owns), or nullptr if no limits needed
    // Verifiable: limits can be queried back from the job object
    // -----------------------------------------------------------------------
    inline HANDLE AssignJobObject(const SandboxConfig& config, HANDLE hProcess)
    {
        bool needJob = (config.memoryLimitMB > 0 || config.maxProcesses > 0 ||
                        !config.allowClipboardRead || !config.allowClipboardWrite);
        if (!needJob) return nullptr;

        HANDLE hJob = CreateJobObjectW(nullptr, nullptr);
        if (!hJob) return nullptr;

        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli{};
        if (config.memoryLimitMB > 0) {
            jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
            jeli.JobMemoryLimit = config.memoryLimitMB * 1024 * 1024;
        }
        if (config.maxProcesses > 0) {
            jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            jeli.BasicLimitInformation.ActiveProcessLimit = config.maxProcesses;
        }
        if (jeli.BasicLimitInformation.LimitFlags != 0) {
            if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli))) {
                g_logger.LogFmt(L"JOB_LIMIT: SetInformationJobObject(Extended) failed (error %lu)", GetLastError());
                CloseHandle(hJob);
                return nullptr;
            }
        }

        // UI restrictions (clipboard blocking)
        DWORD uiFlags = 0;
        if (!config.allowClipboardRead)  uiFlags |= JOB_OBJECT_UILIMIT_READCLIPBOARD;
        if (!config.allowClipboardWrite) uiFlags |= JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
        if (uiFlags) {
            JOBOBJECT_BASIC_UI_RESTRICTIONS uiRestrict{};
            uiRestrict.UIRestrictionsClass = uiFlags;
            if (!SetInformationJobObject(hJob, JobObjectBasicUIRestrictions, &uiRestrict, sizeof(uiRestrict))) {
                g_logger.LogFmt(L"JOB_LIMIT: SetInformationJobObject(UIRestrictions) failed (error %lu)", GetLastError());
                CloseHandle(hJob);
                return nullptr;
            }
            g_logger.Log(L"CLIPBOARD: restricted via job UI limits");
        }

        if (!AssignProcessToJobObject(hJob, hProcess)) {
            g_logger.Log(L"JOB_ASSIGN: FAILED (limits NOT enforced)");
            CloseHandle(hJob);
            return nullptr;
        }

        g_logger.LogFmt(L"JOB: memory=%zuMB, processes=%lu, ui_flags=0x%X",
                        config.memoryLimitMB, config.maxProcesses, uiFlags);

        return hJob;
    }

    // -----------------------------------------------------------------------
    // WaitForChildExit — wait for the child to exit, handle timeout.
    //
    // Console passthrough: Sandy does not interpose on stdout/stderr.
    // The child writes directly to the console (or shell redirect).
    //
    // Inputs:  hProcess       — child process handle
    //          hTimeoutThread — timeout watchdog thread (may be null)
    //          timeoutCtx     — timeout context (for checking timedOut flag)
    //          timeoutSec     — configured timeout value (for reporting)
    // Returns: child exit code
    // Verifiable: exit code matches child's GetExitCodeProcess
    // -----------------------------------------------------------------------
    inline DWORD WaitForChildExit(HANDLE hProcess,
                                   HANDLE hTimeoutThread, TimeoutContext& timeoutCtx,
                                   DWORD timeoutSec)
    {
        WaitForSingleObject(hProcess, INFINITE);
        DWORD exitCode = 0;
        GetExitCodeProcess(hProcess, &exitCode);

        if (hTimeoutThread) {
            WaitForSingleObject(hTimeoutThread, 5000);
            CloseHandle(hTimeoutThread);
            if (timeoutCtx.timedOut)
                g_logger.LogFmt(L"TIMEOUT: killed after %lus", timeoutSec);
        }

        return exitCode;
    }

    // -----------------------------------------------------------------------
    // StartTimeoutWatchdog — arm a watchdog thread to kill the process.
    //
    // Inputs:  ctx — timeout context (hProcess and seconds must be set)
    // Returns: watchdog thread handle, or nullptr if no timeout configured
    // Verifiable: thread handle is valid when seconds > 0
    // -----------------------------------------------------------------------
    inline HANDLE StartTimeoutWatchdog(TimeoutContext& ctx)
    {
        if (ctx.seconds == 0) return nullptr;

        HANDLE hThread = CreateThread(nullptr, 0, TimeoutThread, &ctx, 0, nullptr);
        // F4/R8: Log failure — caller must check for nullptr to fail closed
        if (!hThread)
            g_logger.LogFmt(L"TIMEOUT: CreateThread FAILED (error %lu) — watchdog NOT armed",
                            GetLastError());
        else
            g_logger.LogFmt(L"TIMEOUT: armed %lus", ctx.seconds);
        return hThread;
    }

} // namespace Sandbox
