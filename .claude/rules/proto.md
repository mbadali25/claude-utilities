---
paths:
  - "internal/proto/**"
---
<!-- crew:generated source=.crew/codemap/proto.md sha256=31a4e304f74419cd -- do not hand-edit; regenerate with crew_instructions.py rules -->
# proto
Code map anchor `0cef554`; if it is behind HEAD, re-check with `git diff --name-only 0cef554..HEAD -- <cited paths>`.
## Landmines
- `Hello.Token`, `ExportRes.Block`, `SwapReq.Block` carry secrets: String/GoString/LogValue must keep masking them when fields are added.
- `Decode` does not check `ID`; dispatchers must reject an empty ID on export/swap req/res.
- `ExportRes.Err` and `SwapRes.Reason` go on the wire as-is; callers must `logx.Redact` first.
- A swap block must be only the `claudeAiOauth` block (project rule; enforced by callers, not here).
- Tests: `internal/proto/proto_test.go`, `internal/proto/swapres_test.go`.
Full note: `.crew/codemap/proto.md`.
