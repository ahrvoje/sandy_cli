---
description: "Use when working in the sandy_cli workspace; before each response, check `.agents/rules/*` for always-on repo rules and follow them."
applyTo: "**"
---

# Sandy repo rule check

Before every response in this workspace:

1. Read all files in `.agents/rules/*`.
2. Treat files marked `trigger: always_on` as mandatory instructions.
3. If a rule refers to additional `.agents/*.md` reference docs needed for code changes, read those before editing code.
4. Keep `README.md` and help text in `src/sandy.cpp` aligned whenever a rule requires documentation consistency.

Do not skip the `.agents/rules/*` check, even for short prompts.
