// A normal Win32 pipe app, based on ideas/lpac_named_pipe/pipe_app.c.
// It has no knowledge of Sandy's pipe map and never adds LOCAL to a name.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

static int Fail(const char* operation)
{
    DWORD error = GetLastError();
    printf("%s_ERROR:%lu\n", operation, error);
    return error ? static_cast<int>(error) : 1;
}

struct ClientArgs {
    const wchar_t* name;
    bool call;
};

static DWORD WINAPI Client(void* parameter)
{
    auto& args = *static_cast<ClientArgs*>(parameter);
    char request[] = "native-client";
    char reply[64]{};
    DWORD count = 0;
    if (args.call) {
        if (!CallNamedPipeW(args.name, request, sizeof(request) - 1,
                            reply, sizeof(reply), &count, 5000))
            return Fail("CALL");
    } else {
        if (!WaitNamedPipeW(args.name, 5000))
            return Fail("WAIT");
        HANDLE pipe = CreateFileW(args.name, GENERIC_READ | GENERIC_WRITE, 0,
                                   nullptr, OPEN_EXISTING, 0, nullptr);
        if (pipe == INVALID_HANDLE_VALUE)
            return Fail("OPEN");
        BOOL ok = WriteFile(pipe, request, sizeof(request) - 1, &count, nullptr) &&
                  count == sizeof(request) - 1 &&
                  ReadFile(pipe, reply, sizeof(reply), &count, nullptr);
        DWORD error = ok ? 0 : GetLastError();
        CloseHandle(pipe);
        if (!ok) return error ? error : 1;
    }
    return count == 18 && memcmp(reply, "echo:native-client", 18) == 0 ? 0 : 1;
}

int wmain(int argc, wchar_t** argv)
{
    const wchar_t* name = argc > 1 ? argv[1] : L"\\\\.\\pipe\\sandy-pipe-test";
    printf("REQUEST:%ls PID:%lu\n", name, GetCurrentProcessId());
    HANDLE pipe = CreateNamedPipeW(name,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, 4096, 4096, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE)
        return Fail("CREATE");
    printf("READY\n");
    fflush(stdout);
    ClientArgs clientArgs{ name, argc > 2 && wcscmp(argv[2], L"--client-call") == 0 };
    HANDLE client = argc > 2 ? CreateThread(nullptr, 0, Client, &clientArgs, 0, nullptr) : nullptr;
    if (argc > 2 && !client) return Fail("THREAD");
    if (!ConnectNamedPipe(pipe, nullptr) && GetLastError() != ERROR_PIPE_CONNECTED)
        return Fail("CONNECT");
    char request[1024], response[1029] = "echo:";
    DWORD received = 0, sent = 0;
    if (!ReadFile(pipe, request, sizeof(request), &received, nullptr))
        return Fail("READ");
    memcpy(response + 5, request, received);
    if (!WriteFile(pipe, response, received + 5, &sent, nullptr))
        return Fail("WRITE");
    if (sent != received + 5)
        return 1;
    if (!FlushFileBuffers(pipe))
        return Fail("FLUSH");
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
    if (client) {
        if (WaitForSingleObject(client, 5000) != WAIT_OBJECT_0) return 1;
        DWORD result = 1;
        GetExitCodeThread(client, &result);
        CloseHandle(client);
        if (result) return static_cast<int>(result);
    }
    puts("IPC_OK");
    return 0;
}
