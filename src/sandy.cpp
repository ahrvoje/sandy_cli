// sandy.cpp — Sandboxed Executable Runner (CLI)
// Launches any executable inside a Windows AppContainer sandbox.
// Usage: sandy.exe -c <config.toml> -x <executable> [args...]

#include "framework.h"
#include "Sandbox.h"

// -----------------------------------------------------------------------
// Print usage help
// -----------------------------------------------------------------------
static void PrintUsage()
{
    printf(
        "Sandy - AppContainer Sandbox Runner\n"
        "\n"
        "Usage:\n"
        "  sandy.exe -c <config.toml> [-l <logfile>] -x <executable> [args...]\n"
        "\n"
        "Options:\n"
        "  -c <path>   Path to TOML config file (access, permissions, limits)\n"
        "  -l <path>   Log file for access denials, limits, and exit code (admin for ETW)\n"
        "  -x <path>   Path to executable to run sandboxed (.exe, .bat, etc.)\n"
        "\n"
        "Any arguments after the executable path are forwarded to it.\n"
        "\n"
        "Config file sections:\n"
        "  [access]    read / write / readwrite arrays for file and folder access\n"
        "  [allow]     Opt-in permissions (network, localhost, system_dirs, etc.)\n"
        "  [limit]     Resource limits (timeout, memory, processes)\n"
        "\n"
        "See sandy_config.toml for all available options.\n"
    );
}

// -----------------------------------------------------------------------
// Entry point
// -----------------------------------------------------------------------
int wmain(int argc, wchar_t* argv[])
{
    std::wstring configPath;
    std::wstring logPath;
    std::wstring exePath;
    std::wstring exeArgs;

    // --- Parse command-line arguments ---
    for (int i = 1; i < argc; i++) {
        std::wstring arg = argv[i];

        if (arg == L"-c" && i + 1 < argc) {
            configPath = argv[++i];
        }
        else if (arg == L"-l" && i + 1 < argc) {
            logPath = argv[++i];
        }
        else if (arg == L"-x" && i + 1 < argc) {
            exePath = argv[++i];
            // Everything after -x <exe> is forwarded as arguments
            for (int j = i + 1; j < argc; j++) {
                if (!exeArgs.empty()) exeArgs += L" ";
                // Quote arguments that contain spaces
                std::wstring a = argv[j];
                if (a.find(L' ') != std::wstring::npos && a.front() != L'"') {
                    exeArgs += L"\"" + a + L"\"";
                } else {
                    exeArgs += a;
                }
            }
            break; // -x consumes all remaining args
        }
        else {
            fprintf(stderr, "Unknown option: %ls\n\n", arg.c_str());
            PrintUsage();
            return 1;
        }
    }

    // --- Validate required options ---
    if (configPath.empty() || exePath.empty()) {
        if (argc > 1)
            fprintf(stderr, "Error: Both -c and -x are required.\n\n");
        PrintUsage();
        return 1;
    }

    // --- Verify config file exists ---
    DWORD attrs = GetFileAttributesW(configPath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "Error: Config file not found: %ls\n", configPath.c_str());
        return 1;
    }

    // --- Load configuration ---
    auto config = Sandbox::LoadConfig(configPath);
    config.logPath = logPath;

    // --- Run sandboxed ---
    int exitCode = Sandbox::RunSandboxed(config, exePath, exeArgs);

    Sandbox::CleanupSandbox();

    return exitCode;
}
