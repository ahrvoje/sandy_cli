// =========================================================================
// pipehook_protocol.h — the contract between sandy.exe and the injected
// pipe-hook DLL.  Both sides include this one file, so the wire format
// cannot drift between the producer (SandboxPipeHook.h) and the consumer
// (pipehook/dllmain.cpp).
//
// Transport: a single environment variable the child inherits.  Its value is
// a list of (original, local) named-pipe name pairs:
//
//     original <US> local <RS> original <US> local <RS> ...
//
// RS (0x1E) separates pairs, US (0x1F) separates the two names of a pair.
// Configuration rejects control characters, including these separators.
// No escaping is needed; names may contain '|', ':' etc.
// =========================================================================
#pragma once

#define SANDY_PIPEHOOK_ENV      L"SANDY_PIPEHOOK"
#define SANDY_PIPEHOOK_RS       L'\x1e'   // record (pair) separator
#define SANDY_PIPEHOOK_US       L'\x1f'   // field (name) separator
#define SANDY_PIPEHOOK_MAX_VALUE 32766   // Windows environment value, excluding NUL
