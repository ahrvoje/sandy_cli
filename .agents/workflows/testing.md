---
description: Rules for running Sandy test suite
---

// turbo-all

# Running Tests

1. **NEVER auto-run `test_all.bat`, `run_all_tests.bat` or any test suite under ANY circumstances** unless the user explicitly and directly asks you to run the tests in their prompt.
   It takes 10+ minutes and may require UAC elevation for filesystem and ACL scenarios.
   DO NOT proactively run these to "verify" changes. Wait for the user to tell you to run them.

2. Individual test scripts (`test_*.bat`) may be run when debugging a specific
   test, but prefer the smallest scope possible.

3. When a feature is removed, replace legacy scenario tests with rejection/help-surface coverage so the CLI contract cannot silently regress.