# logx
anchor: claude-utilities@0cef554
verified: 2026-11-04

## Does
JSON slog logger that writes only allowlisted attribute keys and redacts secret-looking substrings from messages and string values. Everything else is replaced by `[dropped]`; strings are capped at 256 bytes.

## Entry points
- `internal/logx/logx.go:304` — `New(w)` builds the sanitising slog logger; every host binary logs through it.
- `internal/logx/logx.go:158` — `Redact(s)` masks PEM, URL userinfo, vendor tokens, bearer, JWT, emails, key/value and JSON secrets; called by `internal/proto` String/LogValue methods.
- `internal/logx/logx.go:85` — `Err(err)` is the only supported way to log an error (error values are dropped).
- `internal/logx/logx.go:56` — `Allow(keys...)` registers extra keys at init time; panics on secret-looking keys.

## Owns data
- none (stateless; the allowlist is an in-memory map guarded by a RWMutex, `internal/logx/logx.go:36`)

## Calls out to
- stdlib only (`log/slog`, `regexp`); no network, no files.

## Landmines
- logx must never import proto (proto imports logx; cycle). `internal/logx/logx.go:11`
- Allowlist, not denylist: a new log field needs its key in `allowed` or `Allow`, else it logs as `[dropped]`. `internal/logx/logx.go:346`
- Groups (`WithGroup`, nested attrs) are always dropped. `internal/logx/logx.go:327`
- A bare `code`/`key` in free text is deliberately not masked (collides with "exit code=1"). `internal/logx/logx.go:184`
- Tests: `internal/logx/logx_test.go`, `logx_review_test.go`, `logx_allowlist_test.go`.

## Unverified
- Redaction completeness against real Claude credential formats; only the unit tests were read, not run in this phase.
- Graph (graphify, 16 communities for 136 nodes) was built but this note was written from the source directly, not from community queries.
