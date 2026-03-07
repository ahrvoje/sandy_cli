---
description: Rules for running Sandy test suite
---

// turbo-all

# Running Tests

1. **Do NOT auto-run `run_all_tests.bat`** unless the user explicitly asks.
   It takes 10+ minutes and requires UAC elevation for audit tests.
   When prompted by the user, you may run it.

2. Individual test scripts (`test_*.bat`) may be run when debugging a specific
   test, but prefer the smallest scope possible.
