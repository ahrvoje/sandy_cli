// sandy.cpp — Sandboxed Executable Runner (CLI)
// Launches any executable inside a Windows sandbox (AppContainer or Restricted Token).
// Usage: sandy.exe -c <config.toml> -x <executable> [args...]
//        sandy.exe -s "<toml string>" -x <executable> [args...]

#include "framework.h"
#include "Sandbox.h"
#include "SandboxCLI.h"
#include "SandboxStatus.h"
#include "SandboxDryRun.h"
#include "SandboxSavedProfile.h"

constexpr const char* kVersion = "0.999";
using namespace Sandbox;

// -----------------------------------------------------------------------
// Console control handler — signal-aware cleanup strategy.
//
// CTRL_C / CTRL_BREAK: no OS-imposed deadline → full CleanupSandbox().
//
// CTRL_CLOSE_EVENT: Windows imposes a short timeout (~5 s) before
//   killing the process.  Sandy's full cleanup (child-kill wait + ACL
//   revocation + loopback + container teardown) can exceed this
//   deadline.  We terminate the child process/job (fast, security-
//   critical) but skip the rest.  The per-instance ONLOGON cleanup
//   task (SandyCleanup_<uuid>) is intentionally left in place so it
//   fires on next logon and completes deferred cleanup via --cleanup.
//
// CTRL_LOGOFF / CTRL_SHUTDOWN: unreliable once user32.dll is loaded
//   (MSDN: SetConsoleCtrlHandler is not called for logoff/shutdown
//   after user32 or gdi32 are in the process).  Sandy loads user32
//   implicitly via desktop ACL APIs (GetProcessWindowStation,
//   OpenDesktopW) during restricted-token runs.  If the handler does
//   fire, the same deadline constraint as CTRL_CLOSE applies, so we
//   log only and defer entirely to recovery.
// -----------------------------------------------------------------------
static BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType)
{
    const wchar_t* name = ctrlType == CTRL_C_EVENT ? L"CTRL_C" :
                           ctrlType == CTRL_CLOSE_EVENT ? L"CTRL_CLOSE" :
                           ctrlType == CTRL_BREAK_EVENT ? L"CTRL_BREAK" :
                           ctrlType == CTRL_LOGOFF_EVENT ? L"CTRL_LOGOFF" :
                           ctrlType == CTRL_SHUTDOWN_EVENT ? L"CTRL_SHUTDOWN" : L"UNKNOWN";
    g_logger.LogFmt(L"SIGNAL: %s (code=%lu)", name, ctrlType);

    switch (ctrlType) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
        // No OS deadline — full synchronous cleanup is safe.
        CleanupSandbox();
        break;

    case CTRL_CLOSE_EVENT:
        // Deadline-limited: terminate child (fast), defer rest to recovery.
        // Cleanup task intentionally retained — fires on next logon.
        g_logger.Log(L"SIGNAL: deadline-limited close — terminating child, deferring cleanup to recovery");
        if (HANDLE hJob = g_childJob) {
            TerminateJobObject(hJob, 1);
        } else if (HANDLE hChild = g_childProcess) {
            TerminateProcess(hChild, 1);
        }
        g_logger.Stop();
        break;

    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        // May not fire at all (user32 loaded); if it does, deadline applies.
        // Log only — cleanup task stays, stale recovery handles everything.
        g_logger.Log(L"SIGNAL: logoff/shutdown — deferring cleanup to recovery");
        g_logger.Stop();
        break;

    default:
        break;
    }

    return FALSE;  // let default handler terminate the process
}

struct RunMainOptions
{
    std::wstring configPath;
    std::wstring configString;
    std::wstring logPath;
    std::wstring exePath;
    std::wstring exeArgs;
    std::wstring profileName;
    std::wstring createProfileName;
    bool quiet = false;
    bool logStamp = false;
    bool dryRun = false;
    bool printConfig = false;
};

static bool HandleStandaloneCliAction(const std::wstring& arg, int argc, int& exitCode)
{
    bool isStandalone = (arg == L"-v" || arg == L"--version" ||
                         arg == L"-h" || arg == L"--help" ||
                         arg == L"--cleanup" ||
                         arg == L"--print-container-toml" ||
                         arg == L"--print-restricted-toml");
    if (!isStandalone)
        return false;

    if (argc > 2) {
        fprintf(stderr, "Error: %ls must be used alone, without other options.\n",
                arg.c_str());
        exitCode = SandyExit::InternalError;
        return true;
    }

    if (arg == L"-v" || arg == L"--version") {
        printf("sandy v%s\n", kVersion);
        exitCode = 0;
    } else if (arg == L"-h" || arg == L"--help") {
        PrintUsage(kVersion);
        exitCode = 0;
    } else if (arg == L"--print-container-toml") {
        PrintContainerToml();
        exitCode = 0;
    } else if (arg == L"--print-restricted-toml") {
        PrintRestrictedToml();
        exitCode = 0;
    } else {
        exitCode = HandleCleanup();
    }

    return true;
}

static bool HandleImmediateCliAction(int argc, wchar_t* argv[], int& exitCode)
{
    for (int i = 1; i < argc; i++) {
        std::wstring arg = argv[i];
        if (HandleStandaloneCliAction(arg, argc, exitCode))
            return true;

        if (arg == L"--status") {
            if (argc > 3) {
                fprintf(stderr, "Error: --status only accepts --json as companion.\n");
                exitCode = SandyExit::InternalError;
                return true;
            }

            bool json = false;
            if (argc == 3) {
                int other = (i == 1) ? 2 : 1;
                if (std::wstring(argv[other]) != L"--json") {
                    fprintf(stderr, "Error: --status only accepts --json as companion.\n");
                    exitCode = SandyExit::InternalError;
                    return true;
                }
                json = true;
            }

            exitCode = HandleStatus(json);
            return true;
        }

        if (arg == L"--explain") {
            if (argc != 3 || i + 1 >= argc) {
                fprintf(stderr, "Error: --explain requires exactly one argument.\n");
                exitCode = SandyExit::InternalError;
                return true;
            }

            exitCode = HandleExplain(argv[i + 1]);
            return true;
        }

        if (arg == L"--profile-info") {
            if (argc != 3 || i + 1 >= argc) {
                fprintf(stderr, "Error: --profile-info requires exactly one argument.\n");
                exitCode = SandyExit::InternalError;
                return true;
            }

            exitCode = HandleProfileInfo(argv[i + 1]);
            return true;
        }

        if (arg == L"--delete-profile") {
            if (argc != 3 || i + 1 >= argc) {
                fprintf(stderr, "Error: --delete-profile requires exactly one argument.\n");
                exitCode = SandyExit::InternalError;
                return true;
            }

            exitCode = HandleDeleteProfile(argv[i + 1]);
            return true;
        }
    }

    return false;
}

static bool ParseRunMainOptions(int argc,
                                wchar_t* argv[],
                                RunMainOptions& options,
                                int& exitCode)
{
    for (int i = 1; i < argc; i++) {
        std::wstring arg = argv[i];

        if (arg == L"-q" || arg == L"--quiet") {
            options.quiet = true;
        }
        else if (arg == L"-L" || arg == L"--log-stamp") {
            options.logStamp = true;
        }
        else if (arg == L"--dry-run" || arg == L"--check") {
            options.dryRun = true;
        }
        else if (arg == L"--print-config") {
            options.printConfig = true;
        }
        else if ((arg == L"-c" || arg == L"--config") && i + 1 < argc) {
            options.configPath = argv[++i];
        }
        else if ((arg == L"-s" || arg == L"--string") && i + 1 < argc) {
            options.configString = argv[++i];
        }
        else if ((arg == L"-l" || arg == L"--log") && i + 1 < argc) {
            options.logPath = argv[++i];
        }
        else if ((arg == L"-p" || arg == L"--profile") && i + 1 < argc) {
            options.profileName = argv[++i];
        }
        else if (arg == L"--create-profile" && i + 1 < argc) {
            options.createProfileName = argv[++i];
        }
        else if ((arg == L"-x" || arg == L"--exec") && i + 1 < argc) {
            options.exePath = argv[++i];
            options.exeArgs = CollectArgs(i + 1, argc, argv);
            return true;
        }
        else if (arg == L"--") {
            if (i + 1 < argc) {
                options.exePath = argv[++i];
                options.exeArgs = CollectArgs(i + 1, argc, argv);
            }
            return true;
        }
        else {
            fprintf(stderr, "Unknown option: %ls\n\n", arg.c_str());
            PrintUsage(kVersion);
            exitCode = SandyExit::InternalError;
            return false;
        }
    }

    return true;
}

static int RunCreateProfileMode(const RunMainOptions& options)
{
    if (options.configPath.empty()) {
        fprintf(stderr, "Error: --create-profile requires -c <config.toml>.\n\n");
        PrintUsage(kVersion);
        return SandyExit::InternalError;
    }

    if (!options.logPath.empty())
        g_logger.Start(options.logPath);

    int result = options.dryRun
        ? HandleDryRunCreateProfile(options.createProfileName, options.configPath)
        : HandleCreateProfile(options.createProfileName, options.configPath);
    g_logger.Stop();
    return result;
}

static int RunSavedProfileMode(const RunMainOptions& options)
{
    if (!options.configPath.empty() || !options.configString.empty()) {
        fprintf(stderr, "Error: -p/--profile and -c/--config/-s/--string are mutually exclusive.\n");
        fprintf(stderr, "       Profile already contains its configuration.\n\n");
        return SandyExit::ConfigError;
    }
    if (options.exePath.empty()) {
        fprintf(stderr, "Error: -p/--profile requires -x <executable>.\n\n");
        PrintUsage(kVersion);
        return SandyExit::InternalError;
    }

    SavedProfile profile;
    CleanStagingProfiles();
    SavedProfileLoadStatus loadStatus = LoadSavedProfile(options.profileName, profile);
    if (loadStatus == SavedProfileLoadStatus::NotFound) {
        fprintf(stderr, "Error: profile '%ls' not found.\n", options.profileName.c_str());
        return SandyExit::ConfigError;
    }
    if (loadStatus == SavedProfileLoadStatus::Invalid) {
        fprintf(stderr, "Error: profile '%ls' is corrupted or incomplete. Recreate it or delete it.\n",
                options.profileName.c_str());
        return SandyExit::ConfigError;
    }

    profile.config.logPath = options.logPath;
    profile.config.quiet = options.quiet;
    profile.config.configSource = L"profile:" + options.profileName;
    if (!options.logPath.empty())
        g_logger.Start(options.logPath);

    int result = RunWithProfile(profile, options.exePath, options.exeArgs);
    g_logger.Stop();
    return result;
}

static std::wstring StampLogPath(const std::wstring& path)
{
    if (path.empty())
        return path;

    SYSTEMTIME st;
    GetLocalTime(&st);
    DWORD uid = (GetTickCount() ^ GetCurrentProcessId()) & 0xFFFF;
    wchar_t prefix[32];
    swprintf(prefix, 32, L"%04d%02d%02d_%02d%02d%02d_%04x_",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond, uid);

    size_t slash = path.find_last_of(L"\\/");
    if (slash != std::wstring::npos)
        return path.substr(0, slash + 1) + prefix + path.substr(slash + 1);
    return std::wstring(prefix) + path;
}

static bool LoadConfiguredSandbox(const RunMainOptions& options, SandboxConfig& config)
{
    if (!options.configString.empty()) {
        config = ParseConfig(options.configString);
    } else {
        DWORD attrs = GetFileAttributesW(options.configPath.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            fprintf(stderr, "Error: Config file not found: %ls\n", options.configPath.c_str());
            return false;
        }
        config = LoadConfig(options.configPath);
    }

    if (config.parseError) {
        fprintf(stderr, "Error: Config contains unknown sections or keys. Aborting.\n");
        return false;
    }

    return true;
}

static int RunConfigDrivenMode(RunMainOptions options)
{
    if (options.configPath.empty() && options.configString.empty()) {
        PrintUsage(kVersion);
        return SandyExit::InternalError;
    }
    if (options.exePath.empty() && !options.dryRun && !options.printConfig) {
        fprintf(stderr, "Error: -x <executable> required (or use --dry-run / --print-config).\n\n");
        PrintUsage(kVersion);
        return SandyExit::InternalError;
    }
    if (!options.configPath.empty() && !options.configString.empty()) {
        fprintf(stderr, "Error: -c and -s are mutually exclusive.\n\n");
        PrintUsage(kVersion);
        return SandyExit::InternalError;
    }

    if (options.logStamp)
        options.logPath = StampLogPath(options.logPath);
    if (!options.logPath.empty())
        g_logger.Start(options.logPath);

    SandboxConfig config;
    if (!LoadConfiguredSandbox(options, config))
        return SandyExit::ConfigError;
    if (options.printConfig)
        return HandlePrintConfig(config);
    if (options.dryRun)
        return HandleDryRun(config, options.exePath, options.exeArgs);

    config.logPath = options.logPath;
    config.quiet = options.quiet;
    config.configSource = !options.configPath.empty() ? options.configPath : L"<inline>";
    return RunSandboxed(config, options.exePath, options.exeArgs);
}

// -----------------------------------------------------------------------
// Sandboxed execution (separated for SEH wrapping)
// -----------------------------------------------------------------------
static int RunMain(int argc, wchar_t* argv[])
{
    int exitCode = 0;
    if (HandleImmediateCliAction(argc, argv, exitCode))
        return exitCode;

    RunMainOptions options;
    if (!ParseRunMainOptions(argc, argv, options, exitCode))
        return exitCode;
    if (!options.createProfileName.empty())
        return RunCreateProfileMode(options);
    if (!options.profileName.empty())
        return RunSavedProfileMode(options);
    return RunConfigDrivenMode(options);
}

// -----------------------------------------------------------------------
// Entry point — SEH wrapper for crash resilience
// -----------------------------------------------------------------------
int wmain(int argc, wchar_t* argv[])
{
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    __try {
        return RunMain(argc, argv);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD code = GetExceptionCode();
        g_logger.LogFmt(L"FATAL_EXCEPTION: 0x%08X", code);
        CleanupSandbox();
        return SandyExit::InternalError;
    }
}
