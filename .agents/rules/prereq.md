---
trigger: always_on
---

# Prerequisite Reading

Before modifying any Sandy source code, read these reference documents:

// turbo
1. Read `.agents/guidelines.md` — coding style, build commands, architecture rules
// turbo
2. Read `.agents/acl_design.md` — ACL grant/deny design, mask math, PROTECTED_DACL, multi-owner safety
// turbo
3. Read `.agents/resilience.md` — cleanup, crash recovery, durable metadata, power-loss handling

These contain **verified conclusions from previous work**. Decisions documented there are settled facts, not suggestions.

Current architectural lens:
- profiles are first-class durable identities
- transient runs are the one-shot variant of the same pipeline
- Procmon-backed audit/trace is removed and should not be treated as active product surface

# Agent Autonomy — Standing Permissions

The following actions are **pre-approved** and must never prompt for user confirmation:

// turbo
1. **Build/compile** — run the MSBuild command whenever needed (after edits, before verification, etc.)
// turbo
2. **Temp folder operations** — create files in `C:\tmp\` or system temp for scripts, scratch data, etc.
// turbo
3. **Editing/reformatting scripts** — create and run Python/PowerShell scripts that modify source, config, or doc files
