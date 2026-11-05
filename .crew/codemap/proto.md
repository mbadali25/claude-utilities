# proto
anchor: claude-utilities@0cef554
verified: 2026-11-04

## Does
Wire envelope and message bodies exchanged between the LAN server and per-host agents (hello, heartbeat, report, export, swap). Credential-bearing types never print their secrets via fmt or slog.

## Entry points
- `internal/proto/proto.go:132` — `Encode(typ, id, body)` builds a versioned envelope for sending.
- `internal/proto/proto.go:150` — `Decode(b)` parses a frame; rejects over 1 MiB, wrong version, empty type.
- `internal/proto/proto.go:19` — `Type*` constants name the seven message types.
- `internal/proto/proto.go:70` — `Report.MarshalJSON` emits `[]` not `null` for no sessions.

## Owns data
- none (pure types; no storage)

## Calls out to
- `internal/logx` `Redact` at `internal/proto/proto.go:84` (and the other String/LogValue methods).

## Landmines
- `Hello.Token`, `ExportRes.Block`, `SwapReq.Block` carry secrets: String/GoString/LogValue must keep masking them when fields are added. `internal/proto/proto.go:92`
- `Decode` does not check `ID`; dispatchers must reject an empty ID on export/swap req/res. `internal/proto/proto.go:147`
- `ExportRes.Err` and `SwapRes.Reason` go on the wire as-is; callers must `logx.Redact` first. `internal/proto/proto.go:60`
- A swap block must be only the `claudeAiOauth` block (project rule; enforced by callers, not here).
- Tests: `internal/proto/proto_test.go`, `internal/proto/swapres_test.go`.

## Unverified
- No dispatcher exists yet (`cmd/` and server/agent packages absent at this anchor), so who calls Encode/Decode is unconfirmed.
- Tests were read for existence only, not run in this phase.
