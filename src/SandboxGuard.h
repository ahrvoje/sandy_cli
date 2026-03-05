// =========================================================================
// SandboxGuard.h — RAII cleanup guard
//
// Accumulates cleanup actions during the pipeline and runs them in
// reverse order on destruction.  Eliminates manual cleanup on every
// error-return path.
// =========================================================================
#pragma once

#include <vector>
#include <functional>

namespace Sandbox {

    struct SandboxGuard {
        std::vector<std::function<void()>> cleanups;

        void Add(std::function<void()> fn) { cleanups.push_back(std::move(fn)); }

        void RunAll() {
            for (auto it = cleanups.rbegin(); it != cleanups.rend(); ++it)
                (*it)();
            cleanups.clear();
        }

        ~SandboxGuard() { RunAll(); }

        // Non-copyable
        SandboxGuard() = default;
        SandboxGuard(const SandboxGuard&) = delete;
        SandboxGuard& operator=(const SandboxGuard&) = delete;
    };

} // namespace Sandbox
