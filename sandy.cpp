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
        "  sandy.exe -c <config.toml> -x <executable> [args...]\n"
        "\n"
        "Options:\n"
        "  -c <path>   Path to TOML config file defining folder access grants\n"
        "  -x <path>   Path to executable to run sandboxed (.exe, .bat, etc.)\n"
        "  -s          Strict isolation: also block system folder reads\n"
        "              (C:\\Windows, C:\\Program Files, etc.)\n"
        "  -n          Allow network access (outbound connections)\n"
        "\n"
        "Any arguments after the executable path are forwarded to it.\n"
        "\n"
        "Config file format:\n"
        "  [read]\n"
        "  \"C:\\path\\to\\folder\"\n"
        "\n"
        "  [write]\n"
        "  \"C:\\path\\to\\folder\"\n"
        "\n"
        "  [readwrite]\n"
        "  \"C:\\path\\to\\folder\"\n"
    );
}

// -----------------------------------------------------------------------
// Entry point
// -----------------------------------------------------------------------
int wmain(int argc, wchar_t* argv[])
{
    std::wstring configPath;
    std::wstring exePath;
    std::wstring exeArgs;
    bool strictIsolation = false;
    bool allowNetwork = false;

    // --- Parse command-line arguments ---
    for (int i = 1; i < argc; i++) {
        std::wstring arg = argv[i];

        if (arg == L"-c" && i + 1 < argc) {
            configPath = argv[++i];
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
        else if (arg == L"-s") {
            strictIsolation = true;
        }
        else if (arg == L"-n") {
            allowNetwork = true;
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

    // --- Run sandboxed ---
    int exitCode = Sandbox::RunSandboxed(configPath, exePath, exeArgs, strictIsolation, allowNetwork);

    Sandbox::CleanupSandbox();

    return exitCode;
}
