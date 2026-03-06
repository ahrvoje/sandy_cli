---
trigger: always_on
---

# Prerequisite Reading

Before modifying any Sandy source code, read these reference documents:

// turbo
1. Read `.agents/guidelines.md` — coding style, build commands, architecture rules
// turbo
2. Read `.agents/acl_design.md` — ACL grant/deny design, mask math, PROTECTED_DACL, multi-instance safety
// turbo
3. Read `.agents/resilience.md` — cleanup, crash recovery, signal handling, registry persistence

These contain **verified conclusions from previous work**. Decisions documented there are settled facts, not suggestions.
