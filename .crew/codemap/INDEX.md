# codemap index
- logx — allowlist JSON slog logger with secret redaction — claude-utilities@0cef554
- proto — wire envelope and message bodies for server/agent — claude-utilities@0cef554

Unmapped: `cmd/server`, `cmd/agent` and other `internal/*` packages do not exist yet (plan tasks 2-11 in flight). Re-run `/crew:onboard --refresh <subsystem>` once they land.
Freshness: before relying on a note, `git diff --name-only <anchor>..HEAD -- <paths>`. Code wins over notes.
