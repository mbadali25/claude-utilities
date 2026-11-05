---
paths:
  - "internal/logx/**"
---
<!-- crew:generated source=.crew/codemap/logx.md sha256=430db4b3e6550d15 -- do not hand-edit; regenerate with crew_instructions.py rules -->
# logx
Code map anchor `0cef554`; if it is behind HEAD, re-check with `git diff --name-only 0cef554..HEAD -- <cited paths>`.
## Landmines
- logx must never import proto (proto imports logx; cycle).
- Allowlist, not denylist: a new log field needs its key in `allowed` or `Allow`, else it logs as `[dropped]`.
- Groups (`WithGroup`, nested attrs) are always dropped.
- A bare `code`/`key` in free text is deliberately not masked (collides with "exit code=1").
- Tests: `internal/logx/logx_test.go`, `logx_review_test.go`, `logx_allowlist_test.go`.
Full note: `.crew/codemap/logx.md`.
