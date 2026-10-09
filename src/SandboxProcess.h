// =========================================================================
// SandboxProcess.h — Process launch, job objects, and timeout
//
// Self-contained utilities for launching sandboxed child processes,
// enforcing resource limits, and managing timeouts.
// Each function is an independently testable semantic unit.
// =========================================================================
#pragma once

#include "SandboxTypes.h"
#include <atomic>

namespace Sandbox {

    enum class HiddenProcessStatus {
        Completed,
        LaunchFailed,
        TimedOut,
        WaitFailed
    };

    struct HiddenProcessResult {
        HiddenProcessStatus status = HiddenProcessStatus::LaunchFailed;
        DWORD exitCode = static_cast<DWORD>(-1);
    };

    inline void CloseHandleIfValid(HANDLE& h)
    {
        if (h && h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            h = nullptr;
        }
    }

    // A handle that a child process may inherit: valid, and marked
    // inheritable.  Returns nullptr when the handle is not usable.
    inline HANDLE InheritableHandleOrNull(HANDLE h)
    {
        DWORD flags = 0;
        if (!h || h == INVALID_HANDLE_VALUE || !GetHandleInformation(h, &flags))
            return nullptr;
        if (!(flags & HANDLE_FLAG_INHERIT) &&
            !SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
            return nullptr;
        return h;
    }

    // Forward declaration — defined below, after WaitForSingleObject helpers
    inline bool WaitForJobTreeExit(HANDLE hJob, DWORD timeoutMs);

    inline void AbortLaunchedChild(PROCESS_INFORMATION& pi, HANDLE& hJob,
                                   DWORD terminateCode, DWORD waitMs = 5000)
    {
        if (hJob)
            TerminateJobObject(hJob, terminateCode);
        else if (pi.hProcess)
            TerminateProcess(pi.hProcess, terminateCode);

        if (pi.hProcess)
            WaitForSingleObject(pi.hProcess, waitMs);

        // Wait for the entire job tree to finish dying, not just the root.
        // TerminateJobObject is asynchronous; descendants may still be exiting.
        if (hJob)
            WaitForJobTreeExit(hJob, waitMs);

        CloseHandleIfValid(pi.hThread);
        CloseHandleIfValid(pi.hProcess);
        CloseHandleIfValid(hJob);
    }

    inline void ReleaseLaunchedChildHandles(PROCESS_INFORMATION& pi, HANDLE& hJob)
    {
        CloseHandleIfValid(pi.hThread);
        CloseHandleIfValid(pi.hProcess);
        CloseHandleIfValid(hJob);
    }

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
    struct HiddenProcessHandles {
        HANDLE hJob = nullptr;
        PROCESS_INFORMATION pi{};
    };

    inline const wchar_t* HiddenProcessLogTarget(const std::wstring& cmdLine,
                                                 const std::wstring& appPath)
    {
        return appPath.empty() ? cmdLine.c_str() : appPath.c_str();
    }

    inline void CloseHiddenProcessHandles(HiddenProcessHandles& handles)
    {
        CloseHandleIfValid(handles.hJob);
        CloseHandleIfValid(handles.pi.hProcess);
        CloseHandleIfValid(handles.pi.hThread);
    }

    inline bool LaunchHiddenProcessInstance(const std::wstring& cmdLine,
                                            const std::wstring& appPath,
                                            STARTUPINFOW& si,
                                            HiddenProcessHandles& handles)
    {
        std::wstring cmd = cmdLine;  // CreateProcessW needs mutable buffer
        const wchar_t* app = appPath.empty() ? nullptr : appPath.c_str();
        if (!CreateProcessW(app, &cmd[0], nullptr, nullptr, FALSE,
                            CREATE_NO_WINDOW, nullptr, nullptr, &si, &handles.pi)) {
            g_logger.LogFmt(L"HIDDEN_PROCESS: launch failed for %ls (error %lu)",
                            HiddenProcessLogTarget(cmdLine, appPath), GetLastError());
            return false;
        }

        return true;
    }

    inline void AttachHiddenProcessJob(const wchar_t* logTarget,
                                       HiddenProcessHandles& handles)
    {
        handles.hJob = CreateJobObjectW(nullptr, nullptr);
        if (!handles.hJob)
            return;

        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(handles.hJob, JobObjectExtendedLimitInformation,
                                     &limits, sizeof(limits)) ||
            !AssignProcessToJobObject(handles.hJob, handles.pi.hProcess)) {
            g_logger.LogFmt(L"HIDDEN_PROCESS: helper job setup failed for %ls (error %lu)",
                            logTarget, GetLastError());
            CloseHandleIfValid(handles.hJob);
        }
    }

    inline HiddenProcessStatus WaitForHiddenProcessCompletion(const wchar_t* logTarget,
                                                              DWORD timeoutMs,
                                                              HiddenProcessHandles& handles,
                                                              HiddenProcessResult& result)
    {
        DWORD waitResult = WaitForSingleObject(handles.pi.hProcess, timeoutMs);
        if (waitResult == WAIT_OBJECT_0) {
            GetExitCodeProcess(handles.pi.hProcess, &result.exitCode);
            return HiddenProcessStatus::Completed;
        }
        if (waitResult == WAIT_TIMEOUT)
            return HiddenProcessStatus::TimedOut;

        g_logger.LogFmt(L"HIDDEN_PROCESS: wait failed for %ls (error %lu)",
                        logTarget, GetLastError());
        return HiddenProcessStatus::WaitFailed;
    }

    inline void TerminateHiddenProcessForTimeout(const wchar_t* logTarget,
                                                 DWORD timeoutMs,
                                                 HiddenProcessHandles& handles)
    {
        g_logger.LogFmt(L"HIDDEN_PROCESS: timeout after %lu ms for %ls",
                        timeoutMs, logTarget);
        if (handles.hJob)
            TerminateJobObject(handles.hJob, 1);
        else
            TerminateProcess(handles.pi.hProcess, 1);
        WaitForSingleObject(handles.pi.hProcess, 2000);
    }

    inline HiddenProcessResult RunHiddenProcessDetailed(const std::wstring& cmdLine,
                                                        DWORD timeoutMs = 5000,
                                                        const std::wstring& appPath = L"")
    {
        HiddenProcessResult result{};
        const wchar_t* logTarget = HiddenProcessLogTarget(cmdLine, appPath);

        STARTUPINFOW si = { sizeof(si) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        HiddenProcessHandles handles;

        if (!LaunchHiddenProcessInstance(cmdLine, appPath, si, handles)) {
            CloseHiddenProcessHandles(handles);
            return result;
        }

        AttachHiddenProcessJob(logTarget, handles);

        result.status = WaitForHiddenProcessCompletion(logTarget, timeoutMs, handles, result);
        if (result.status == HiddenProcessStatus::TimedOut)
            TerminateHiddenProcessForTimeout(logTarget, timeoutMs, handles);

        CloseHiddenProcessHandles(handles);
        return result;
    }

    inline DWORD RunHiddenProcess(const std::wstring& cmdLine, DWORD timeoutMs = 5000,
                                  const std::wstring& appPath = L"")
    {
        HiddenProcessResult result = RunHiddenProcessDetailed(cmdLine, timeoutMs, appPath);
        return (result.status == HiddenProcessStatus::Completed)
            ? result.exitCode
            : static_cast<DWORD>(-1);
    }

    // -----------------------------------------------------------------------
    // Timeout watchdog — ends the sandbox run after N seconds.
    // Used as a thread function with CreateThread.
    //
    // The limit covers the whole run: the root process and, when the run
    // waits for the process tree, every descendant.  The watchdog waits on
    // hRunEnded, which the main thread sets when its own wait is over.  A
    // sandboxed program cannot outlive the limit by starting a child and
    // exiting.
    // -----------------------------------------------------------------------
    struct TimeoutContext {
        HANDLE hProcess = nullptr;
        HANDLE hJob = nullptr;
        HANDLE hRunEnded = nullptr;
        DWORD  seconds = 0;
        std::atomic<bool> timedOut{ false };
    };

    static DWORD WINAPI TimeoutThread(LPVOID param)
    {
        auto* ctx = static_cast<TimeoutContext*>(param);
        ULONGLONG ms64 = static_cast<ULONGLONG>(ctx->seconds) * 1000;
        DWORD waitMs = (ms64 > INFINITE - 1) ? (INFINITE - 1) : static_cast<DWORD>(ms64);
        if (WaitForSingleObject(ctx->hRunEnded, waitMs) == WAIT_TIMEOUT) {
            ctx->timedOut = true;
            if (ctx->hJob)
                TerminateJobObject(ctx->hJob, 1);
            else
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
    // Console passthrough: the child gets Sandy's stdout/stderr handles, so
    // it sees a real console (TTY) when Sandy has one.  stdin is the handle
    // that SetupStdinHandle chose (console, NUL or file).
    //
    // The child inherits these standard handles and no other handle: the
    // attribute list carries a handle list (BuildAttributeList), so a handle
    // that is inheritable in Sandy for any other reason never reaches the
    // sandbox.
    //
    // Inputs:  isRestricted    — true for restricted-token, false for AppContainer
    //          hToken          — restricted token handle (only if isRestricted)
    //          pAttrList       — attribute list (capabilities/child-policy/handle list)
    //          stdHandles      — the handles named in the handle list; empty =
    //                            Sandy has no usable standard handle, the child
    //                            inherits nothing
    //          envBlock        — environment block (empty = inherit)
    //          workDir         — working directory
    //          exePath/exeArgs — target executable and arguments
    //          hStdin          — stdin handle for the child
    // Returns: true on success, pi filled in
    // Verifiable: pi.hProcess is valid and pi.dwProcessId > 0 on success
    // -----------------------------------------------------------------------
    inline bool LaunchChildProcess(bool isRestricted, HANDLE hToken,
                                   LPPROC_THREAD_ATTRIBUTE_LIST pAttrList,
                                   const std::vector<HANDLE>& stdHandles,
                                   std::vector<wchar_t>& envBlock,
                                   const std::wstring& workDir,
                                   const std::wstring& exePath,
                                   const std::wstring& exeArgs,
                                   HANDLE hStdin,
                                   PROCESS_INFORMATION& pi)
    {
        STARTUPINFOEXW siex{};
        siex.StartupInfo.cb = sizeof(siex);

        // A standard handle goes to the child only when the handle list
        // names it.
        auto listed = [&stdHandles](HANDLE h) -> HANDLE {
            return std::find(stdHandles.begin(), stdHandles.end(), h) != stdHandles.end() ? h : nullptr;
        };
        const BOOL inheritHandles = stdHandles.empty() ? FALSE : TRUE;
        if (inheritHandles) {
            siex.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            siex.StartupInfo.hStdInput  = listed(hStdin);
            siex.StartupInfo.hStdOutput = listed(GetStdHandle(STD_OUTPUT_HANDLE));
            siex.StartupInfo.hStdError  = listed(GetStdHandle(STD_ERROR_HANDLE));
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
                hToken, nullptr, &cmdLine[0], nullptr, nullptr, inheritHandles,
                createFlags,
                envBlock.empty() ? nullptr : envBlock.data(),
                workDir.c_str(),
                pAttrList ? reinterpret_cast<LPSTARTUPINFOW>(&siex) : &siex.StartupInfo,
                &pi);
        } else {
            created = CreateProcessW(
                nullptr, &cmdLine[0], nullptr, nullptr, inheritHandles,
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
            SetLastError(err);
            return false;
        }

        // Forensic: log the launch
        g_logger.LogFmt(L"LAUNCH: PID %lu, cmd=\"%s\"", pi.dwProcessId, cmdLine.c_str());
        return true;
    }

    inline bool NeedJobTracking(const SandboxConfig& config)
    {
        return config.allowChildProcesses ||
               config.memoryLimitMB > 0 ||
               config.maxProcesses > 0 ||
               !config.allowClipboardRead ||
               !config.allowClipboardWrite ||
               !config.allowDesktop;
    }

    // -----------------------------------------------------------------------
    // WaitForJobTreeExit — wait until the job no longer contains any processes.
    //
    // For runs that allow child processes, the sandbox lifetime is the whole
    // process tree rather than just the root process.  We poll the job's active
    // process count because the job object itself is not an "all descendants
    // exited" event source in this code path.
    // -----------------------------------------------------------------------
    inline bool WaitForJobTreeExit(HANDLE hJob, DWORD timeoutMs)
    {
        if (!hJob) return true;

        DWORD waited = 0;
        const DWORD pollMs = 100;
        for (;;) {
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info{};
            if (!QueryInformationJobObject(hJob, JobObjectBasicAccountingInformation,
                                           &info, sizeof(info), nullptr))
                return false;
            if (info.ActiveProcesses == 0)
                return true;

            if (timeoutMs != INFINITE && waited >= timeoutMs)
                return false;

            Sleep(pollMs);
            if (timeoutMs != INFINITE)
                waited += pollMs;
        }
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
        bool needJob = NeedJobTracking(config);
        if (!needJob) return nullptr;

        HANDLE hJob = CreateJobObjectW(nullptr, nullptr);
        if (!hJob) return nullptr;

        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli{};
        jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
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

        // UI restrictions (clipboard blocking, desktop isolation)
        DWORD uiFlags = 0;
        if (!config.allowClipboardRead)  uiFlags |= JOB_OBJECT_UILIMIT_READCLIPBOARD;
        if (!config.allowClipboardWrite) uiFlags |= JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
        // desktop = false.  The window station and the desktop give full
        // access to RESTRICTED, a SID the sandbox token needs, so no DACL
        // can keep the sandbox off the desktop.  The job can: the sandbox
        // cannot use windows, hooks or atoms of processes outside the job,
        // switch or create desktops, change display or system parameters,
        // or end the session.
        if (!config.allowDesktop)
            uiFlags |= JOB_OBJECT_UILIMIT_HANDLES | JOB_OBJECT_UILIMIT_GLOBALATOMS |
                       JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
                       JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS | JOB_OBJECT_UILIMIT_EXITWINDOWS;
        if (uiFlags) {
            JOBOBJECT_BASIC_UI_RESTRICTIONS uiRestrict{};
            uiRestrict.UIRestrictionsClass = uiFlags;
            if (!SetInformationJobObject(hJob, JobObjectBasicUIRestrictions, &uiRestrict, sizeof(uiRestrict))) {
                g_logger.LogFmt(L"JOB_LIMIT: SetInformationJobObject(UIRestrictions) failed (error %lu)", GetLastError());
                CloseHandle(hJob);
                return nullptr;
            }
            if (!config.allowClipboardRead || !config.allowClipboardWrite)
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
    // WaitForChildExit — wait for the run to end, handle timeout.
    //
    // Console passthrough: Sandy does not interpose on stdout/stderr.
    // The child writes directly to the console (or shell redirect).
    //
    // Inputs:  hProcess       — child process handle
    //          hTimeoutThread — timeout watchdog thread (may be null)
    //          timeoutCtx     — timeout context (for checking timedOut flag)
    //          timeoutSec     — configured timeout value (for reporting)
    // Returns: exit code of the root process
    // Verifiable: exit code matches child's GetExitCodeProcess
    // -----------------------------------------------------------------------
    inline DWORD WaitForChildExit(HANDLE hProcess,
                                   HANDLE hJob,
                                    HANDLE hTimeoutThread, TimeoutContext& timeoutCtx,
                                   DWORD timeoutSec,
                                   bool waitForProcessTree)
    {
        WaitForSingleObject(hProcess, INFINITE);
        DWORD exitCode = 0;
        GetExitCodeProcess(hProcess, &exitCode);

        if (hJob && waitForProcessTree) {
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info{};
            if (QueryInformationJobObject(hJob, JobObjectBasicAccountingInformation,
                                          &info, sizeof(info), nullptr) &&
                info.ActiveProcesses > 0) {
                g_logger.LogFmt(L"JOB_WAIT: root exited, waiting for %lu descendant process(es)",
                                info.ActiveProcesses);
            }
            if (!WaitForJobTreeExit(hJob, INFINITE))
                g_logger.Log(L"JOB_WAIT: FAILED to confirm full process-tree exit");
            else
                g_logger.Log(L"JOB_WAIT: full process tree exited");
        }

        // The run has ended: release the watchdog.  It stays armed until
        // here, so the limit also covers descendants of an exited root.
        if (hTimeoutThread) {
            SetEvent(timeoutCtx.hRunEnded);
            WaitForSingleObject(hTimeoutThread, INFINITE);
            CloseHandle(hTimeoutThread);
            CloseHandle(timeoutCtx.hRunEnded);
            timeoutCtx.hRunEnded = nullptr;
            if (timeoutCtx.timedOut)
                g_logger.LogFmt(L"TIMEOUT: killed after %lus", timeoutSec);
        }

        return exitCode;
    }

    // -----------------------------------------------------------------------
    // StartTimeoutWatchdog — arm a watchdog thread to end the run.
    //
    // Inputs:  ctx — timeout context (hProcess, hJob and seconds must be set)
    // Returns: watchdog thread handle, or nullptr if no timeout configured
    // Verifiable: thread handle is valid when seconds > 0
    // -----------------------------------------------------------------------
    inline HANDLE StartTimeoutWatchdog(TimeoutContext& ctx)
    {
        if (ctx.seconds == 0) return nullptr;

        ctx.hRunEnded = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        HANDLE hThread = ctx.hRunEnded
            ? CreateThread(nullptr, 0, TimeoutThread, &ctx, 0, nullptr)
            : nullptr;
        // F4/R8: Log failure — caller must check for nullptr to fail closed
        if (!hThread) {
            g_logger.LogFmt(L"TIMEOUT: watchdog start FAILED (error %lu) — watchdog NOT armed",
                            GetLastError());
            CloseHandleIfValid(ctx.hRunEnded);
        } else {
            g_logger.LogFmt(L"TIMEOUT: armed %lus", ctx.seconds);
        }
        return hThread;
    }

} // namespace Sandbox
