// sandy.cpp — Sandboxed Executable Runner (CLI)
// Launches any executable inside a Windows sandbox (AppContainer or Restricted Token).
// Usage: sandy.exe -c <config.toml> -x <executable> [args...]
//        sandy.exe -s "<toml string>" -x <executable> [args...]

#include "framework.h"
#include "Sandbox.h"
#include "SandboxCLI.h"
#include "SandboxStatus.h"
#include "SandboxDryRun.h"

constexpr const char* kVersion = "0.97";
using namespace Sandbox;

// -----------------------------------------------------------------------
// Console control handler — cleanup on Ctrl+C, Ctrl+Break, window close
// -----------------------------------------------------------------------
static BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType)
{
    const wchar_t* name = ctrlType == CTRL_C_EVENT ? L"CTRL_C" :
                           ctrlType == CTRL_CLOSE_EVENT ? L"CTRL_CLOSE" :
                           ctrlType == CTRL_BREAK_EVENT ? L"CTRL_BREAK" :
                           ctrlType == CTRL_LOGOFF_EVENT ? L"CTRL_LOGOFF" :
                           ctrlType == CTRL_SHUTDOWN_EVENT ? L"CTRL_SHUTDOWN" : L"UNKNOWN";
    g_logger.LogFmt(L"SIGNAL: %s (code=%lu)", name, ctrlType);
    CleanupSandbox();
    return FALSE;  // let default handler terminate the process
}

// -----------------------------------------------------------------------
// Sandboxed execution (separated for SEH wrapping)
// -----------------------------------------------------------------------
static int RunMain(int argc, wchar_t* argv[])
{
    std::wstring configPath;
    std::wstring configString;
    std::wstring logPath;
    std::wstring auditLogPath;
    std::wstring profilePath;
    std::wstring dumpPath;
    std::wstring exePath;
    std::wstring exeArgs;
    bool quiet = false;
    bool logStamp = false;
    bool dryRun = false;
    bool printConfig = false;
    bool jsonOutput = false;

    // --- Pre-scan for isolated flags ---
    // These flags must appear alone (or with a minimal companion like --json).
    for (int i = 1; i < argc; i++) {
        std::wstring arg = argv[i];
        bool isIsolated = (arg == L"-v" || arg == L"--version" ||
                           arg == L"-h" || arg == L"--help" ||
                           arg == L"--cleanup" ||
                           arg == L"--print-container-toml" ||
                           arg == L"--print-restricted-toml");
        if (isIsolated) {
            if (argc > 2) {
                fprintf(stderr, "Error: %ls must be used alone, without other options.\n",
                        arg.c_str());
                return SandyExit::InternalError;
            }
            if (arg == L"-v" || arg == L"--version") {
                printf("sandy v%s\n", kVersion);
                return 0;
            }
            if (arg == L"-h" || arg == L"--help") {
                PrintUsage(kVersion);
                return 0;
            }
            if (arg == L"--print-container-toml") {
                PrintContainerToml();
                return 0;
            }
            if (arg == L"--print-restricted-toml") {
                PrintRestrictedToml();
                return 0;
            }
            if (arg == L"--cleanup") {
                return HandleCleanup();
            }
        }

        // --status [--json] — exactly 2 or 3 args total
        if (arg == L"--status") {
            if (argc > 3) {
                fprintf(stderr, "Error: --status only accepts --json as companion.\n");
                return SandyExit::InternalError;
            }
            bool json = false;
            if (argc == 3) {
                // The other arg (whichever position it's in) must be --json
                int other = (i == 1) ? 2 : 1;
                if (std::wstring(argv[other]) != L"--json") {
                    fprintf(stderr, "Error: --status only accepts --json as companion.\n");
                    return SandyExit::InternalError;
                }
                json = true;
            }
            return HandleStatus(json);
        }

        // --explain <code> — exactly 2 args
        if (arg == L"--explain") {
            if (argc != 3 || i + 1 >= argc) {
                fprintf(stderr, "Error: --explain requires exactly one argument.\n");
                return SandyExit::InternalError;
            }
            return HandleExplain(argv[i + 1]);
        }
    }

    // --- Parse command-line arguments ---
    for (int i = 1; i < argc; i++) {
        std::wstring arg = argv[i];

        if (arg == L"-q" || arg == L"--quiet") {
            quiet = true;
        }
        else if (arg == L"-L" || arg == L"--log-stamp") {
            logStamp = true;
        }
        else if (arg == L"--dry-run" || arg == L"--check") {
            dryRun = true;
        }
        else if (arg == L"--print-config") {
            printConfig = true;
        }
        else if ((arg == L"-c" || arg == L"--config") && i + 1 < argc) {
            configPath = argv[++i];
        }
        else if ((arg == L"-s" || arg == L"--string") && i + 1 < argc) {
            configString = argv[++i];
        }
        else if ((arg == L"-l" || arg == L"--log") && i + 1 < argc) {
            logPath = argv[++i];
        }
        else if ((arg == L"-a" || arg == L"--audit") && i + 1 < argc) {
            auditLogPath = argv[++i];
        }
        else if ((arg == L"-p" || arg == L"--profile") && i + 1 < argc) {
            profilePath = argv[++i];
        }
        else if ((arg == L"-d" || arg == L"--dump") && i + 1 < argc) {
            dumpPath = argv[++i];
        }
        else if ((arg == L"-x" || arg == L"--exec") && i + 1 < argc) {
            exePath = argv[++i];
            exeArgs = CollectArgs(i + 1, argc, argv);
            break; // -x/--exec consumes all remaining args
        }
        else if (arg == L"--") {
            // End of options: next arg is exe, rest are its arguments
            if (i + 1 < argc) {
                exePath = argv[++i];
                exeArgs = CollectArgs(i + 1, argc, argv);
            }
            break;
        }
        else {
            fprintf(stderr, "Unknown option: %ls\n\n", arg.c_str());
            PrintUsage(kVersion);
            return SandyExit::InternalError;
        }
    }

    // --- Profile mode (no config needed) ---
    if (!profilePath.empty()) {
        if (exePath.empty()) {
            fprintf(stderr, "Error: -p requires -x <executable>.\n\n");
            PrintUsage(kVersion);
            return SandyExit::InternalError;
        }
        return RunProfile(exePath, exeArgs, profilePath);
    }

    // --- No config/exec provided ---
    if (configPath.empty() && configString.empty()) {
        PrintUsage(kVersion);
        return SandyExit::InternalError;
    }
    if (exePath.empty() && !dryRun && !printConfig) {
        fprintf(stderr, "Error: -x <executable> required (or use --dry-run / --print-config).\n\n");
        PrintUsage(kVersion);
        return SandyExit::InternalError;
    }

    if (!configPath.empty() && !configString.empty()) {
        fprintf(stderr, "Error: -c and -s are mutually exclusive.\n\n");
        PrintUsage(kVersion);
        return SandyExit::InternalError;
    }

    // --- Load configuration ---
    SandboxConfig config;
    if (!configString.empty()) {
        config = ParseConfig(configString);
    } else {
        DWORD attrs = GetFileAttributesW(configPath.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            fprintf(stderr, "Error: Config file not found: %ls\n", configPath.c_str());
            return SandyExit::ConfigError;
        }
        config = LoadConfig(configPath);
    }
    if (config.parseError) {
        fprintf(stderr, "Error: Config contains unknown sections or keys. Aborting.\n");
        return SandyExit::ConfigError;
    }

    // --- Config-only modes (no -x needed) ---
    if (printConfig)
        return HandlePrintConfig(config);
    if (dryRun)
        return HandleDryRun(config, exePath, exeArgs);

    // --- Apply timestamp + UID prefix to log filenames if --log-stamp ---
    if (logStamp) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        DWORD uid = (GetTickCount() ^ GetCurrentProcessId()) & 0xFFFF;
        wchar_t prefix[32];
        swprintf(prefix, 32, L"%04d%02d%02d_%02d%02d%02d_%04x_",
                 st.wYear, st.wMonth, st.wDay,
                 st.wHour, st.wMinute, st.wSecond, uid);
        auto stampPath = [&](const std::wstring& path) -> std::wstring {
            if (path.empty()) return path;
            auto slash = path.find_last_of(L"\\/");
            if (slash != std::wstring::npos)
                return path.substr(0, slash + 1) + prefix + path.substr(slash + 1);
            return std::wstring(prefix) + path;
        };
        logPath = stampPath(logPath);
        auditLogPath = stampPath(auditLogPath);
        dumpPath = stampPath(dumpPath);
    }

    config.logPath = logPath;
    config.quiet = quiet;
    config.configSource = !configPath.empty() ? configPath : L"<inline>";

    // --- Run sandboxed ---
    // cleanup() inside RunSandboxed handles ACL restore, loopback, AppContainer.
    // CleanupSandbox() remains as safety net for CTRL+C / SEH crash paths only.
    return RunSandboxed(config, exePath, exeArgs, auditLogPath, dumpPath);
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
