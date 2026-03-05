// =========================================================================
// SandboxProcess.h — Process launch, IO relay, job objects, and timeout
//
// Self-contained utilities for launching sandboxed child processes,
// capturing output, enforcing resource limits, and managing timeouts.
// Each function is an independently testable semantic unit.
// =========================================================================
#pragma once

#include "SandboxTypes.h"

namespace Sandbox {

    // -----------------------------------------------------------------------
    // RunHiddenProcess — run a process with no window and wait for exit.
    //
    // Inputs:  cmdLine     — full command line to execute
    //          timeoutMs   — max wait time in milliseconds
    // Returns: process exit code, or (DWORD)-1 on failure
    // Verifiable: exit code reflects the child's actual result
    // -----------------------------------------------------------------------
    inline DWORD RunHiddenProcess(const std::wstring& cmdLine, DWORD timeoutMs = 5000)
    {
        STARTUPINFOW si = { sizeof(si) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi = {};
        std::wstring cmd = cmdLine;  // CreateProcessW needs mutable buffer
        if (!CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, FALSE,
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
        return RunHiddenProcess(L"schtasks " + args, 15000);
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

    // -----------------------------------------------------------------------
    // LaunchResult — captures all state from a process launch.
    // Returned by LaunchChildProcess so the caller can inspect, wait, or
    // hand off to RelayOutputAndWait.
    // -----------------------------------------------------------------------
    struct LaunchResult {
        bool              ok = false;       // true if process was created
        PROCESS_INFORMATION pi = {};        // process/thread handles
        HANDLE            hReadPipe = nullptr;  // parent's read end of stdout pipe
        HANDLE            hJob = nullptr;   // job object handle (may be null)
    };

    // -----------------------------------------------------------------------
    // SetupOutputPipe — create an anonymous pipe for child stdout/stderr.
    //
    // Outputs: hRead  — parent's read end (non-inheritable)
    //          hWrite — child's write end (inheritable)
    // Returns: true on success
    // Verifiable: both handles are valid on success
    // -----------------------------------------------------------------------
    inline bool SetupOutputPipe(HANDLE& hRead, HANDLE& hWrite)
    {
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = TRUE;

        if (!CreatePipe(&hRead, &hWrite, &sa, 65536))  // 64KB pipe buffer for crash resilience
            return false;
        SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

        wchar_t msg[256];
        swprintf(msg, 256, L"PIPE: stdout/stderr read=0x%p write=0x%p",
                 (void*)hRead, (void*)hWrite);
        g_logger.Log(msg);
        return true;
    }

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
            fprintf(stderr, "[Error] Could not open stdin source: %ls\n", stdinTarget);
            hStdinFile = nullptr;
            return false;
        }
        hStdin = hStdinFile;
        return true;
    }

    // -----------------------------------------------------------------------
    // LaunchChildProcess — create the child process in the sandbox.
    //
    // Inputs:  isRestricted    — true for restricted-token, false for AppContainer
    //          hToken          — restricted token handle (only if isRestricted)
    //          pAttrList       — attribute list (capabilities/child-policy)
    //          envBlock        — environment block (empty = inherit)
    //          workDir         — working directory
    //          exePath/exeArgs — target executable and arguments
    //          hStdin          — stdin handle for the child
    //          hWritePipe      — child's write end of stdout/stderr pipe
    // Returns: PROCESS_INFORMATION on success, or sets ok=false
    // Verifiable: pi.hProcess is valid and pi.dwProcessId > 0 on success
    // -----------------------------------------------------------------------
    inline bool LaunchChildProcess(bool isRestricted, HANDLE hToken,
                                   LPPROC_THREAD_ATTRIBUTE_LIST pAttrList,
                                   std::vector<wchar_t>& envBlock,
                                   const std::wstring& workDir,
                                   const std::wstring& exePath,
                                   const std::wstring& exeArgs,
                                   HANDLE hStdin, HANDLE hWritePipe,
                                   PROCESS_INFORMATION& pi)
    {
        STARTUPINFOEXW siex{};
        siex.StartupInfo.cb = sizeof(siex);
        siex.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        siex.StartupInfo.hStdOutput = hWritePipe;
        siex.StartupInfo.hStdError  = hWritePipe;
        siex.StartupInfo.hStdInput  = hStdin;
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
            fprintf(stderr, "[Error] Could not launch: %ls (error %lu)\n", exePath.c_str(), err);
            wchar_t msg[1024];
            swprintf(msg, 1024, L"LAUNCH_FAILED: %s (error %lu)", exePath.c_str(), err);
            g_logger.Log(msg);
            swprintf(msg, 1024, L"LAUNCH_DIAG: cmdline=%zu chars, envBlock=%zu wchars (%s)",
                     cmdLine.size(), envBlock.size(),
                     envBlock.empty() ? L"inherited" : L"custom");
            g_logger.Log(msg);
            swprintf(msg, 1024, L"LAUNCH_DIAG: workdir=%s", workDir.c_str());
            g_logger.Log(msg);
            return false;
        }

        // Forensic: log the launch
        {
            wchar_t pidMsg[256];
            swprintf(pidMsg, 256, L"LAUNCH: PID %lu, cmd=\"%s\"", pi.dwProcessId, cmdLine.c_str());
            g_logger.Log(pidMsg);
        }
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
        SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));

        // UI restrictions (clipboard blocking)
        DWORD uiFlags = 0;
        if (!config.allowClipboardRead)  uiFlags |= JOB_OBJECT_UILIMIT_READCLIPBOARD;
        if (!config.allowClipboardWrite) uiFlags |= JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
        if (uiFlags) {
            JOBOBJECT_BASIC_UI_RESTRICTIONS uiRestrict{};
            uiRestrict.UIRestrictionsClass = uiFlags;
            SetInformationJobObject(hJob, JobObjectBasicUIRestrictions, &uiRestrict, sizeof(uiRestrict));
            g_logger.Log(L"CLIPBOARD: restricted via job UI limits");
        }

        if (!AssignProcessToJobObject(hJob, hProcess))
        g_logger.Log(L"JOB_ASSIGN: FAILED (limits NOT enforced)");

        wchar_t msg[256];
        swprintf(msg, 256, L"JOB: memory=%zuMB, processes=%lu, ui_flags=0x%X",
                 config.memoryLimitMB, config.maxProcesses, uiFlags);
        g_logger.Log(msg);

        return hJob;
    }

    // -----------------------------------------------------------------------
    // RelayOutputAndWait — read child stdout/stderr, relay to parent, wait.
    //
    // Inputs:  hProcess      — child process handle
    //          hReadPipe     — parent's read end of the stdout pipe
    //          hTimeoutThread — timeout watchdog thread (may be null)
    //          timeoutCtx    — timeout context (for checking timedOut flag)
    //          timeoutSec    — configured timeout value (for reporting)
    // Returns: child exit code
    // Verifiable: exit code matches child's GetExitCodeProcess
    // -----------------------------------------------------------------------
    inline DWORD RelayOutputAndWait(HANDLE hProcess, HANDLE hReadPipe,
                                    HANDLE hTimeoutThread, TimeoutContext& timeoutCtx,
                                    DWORD timeoutSec)
    {
        char buffer[4096];
        DWORD bytesRead = 0;
        HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);

        while (ReadFile(hReadPipe, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0) {
            DWORD written = 0;
            WriteFile(hStdout, buffer, bytesRead, &written, nullptr);
            g_logger.LogOutput(buffer, bytesRead);
        }

        // Drain any remaining data in the kernel pipe buffer after child exit.
        // When a child crashes, its C runtime may have flushed some data to the
        // pipe that ReadFile didn't pick up before the broken-pipe error.
        for (;;) {
            DWORD avail = 0;
            if (!PeekNamedPipe(hReadPipe, nullptr, 0, nullptr, &avail, nullptr) || avail == 0)
                break;
            if (ReadFile(hReadPipe, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0) {
                DWORD written = 0;
                WriteFile(hStdout, buffer, bytesRead, &written, nullptr);
                g_logger.LogOutput(buffer, bytesRead);
            } else {
                break;
            }
        }
        CloseHandle(hReadPipe);

        WaitForSingleObject(hProcess, INFINITE);
        DWORD exitCode = 0;
        GetExitCodeProcess(hProcess, &exitCode);

        if (hTimeoutThread) {
            WaitForSingleObject(hTimeoutThread, 5000);
            CloseHandle(hTimeoutThread);
            if (timeoutCtx.timedOut)
                fprintf(stderr, "[Sandy] Process killed after %lu second timeout.\n", timeoutSec);
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
        wchar_t msg[128];
        swprintf(msg, 128, L"TIMEOUT: armed %lus", ctx.seconds);
        g_logger.Log(msg);
        return hThread;
    }

} // namespace Sandbox
