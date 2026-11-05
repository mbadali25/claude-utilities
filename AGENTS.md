# claude-utilities - instructions for every agent

For Codex and any agent that reads AGENTS.md. Claude Code does not load it (CLAUDE.md has no `@AGENTS.md` import) and follows CLAUDE.md.

## Work loop
- One session owns a ticket: brainstorm, spec, plan, implement, tests, docs, review, done.
- Before editing an unfamiliar area read `.crew/codemap/INDEX.md` and the subsystem note.
- A code-map `anchor:` behind HEAD means re-check: `git diff --name-only <anchor>..HEAD -- <cited paths>`; empty output means current.
- Quote failing checks verbatim, and say which checks you did not run.
- Vault recall arrives labelled `[vault:<name>] <note>`: a lead to verify, not a fact.

## Verify
- `.crew/verify.json` maps changed paths to commands: run every one whose rule's `paths` match your change. Exit 77 is SKIP, not a pass.
- `bash _verify/smoke.sh`
- `bash _verify/cases/go-checks.sh`
- `bash -n _verify/smoke.sh`
- `bash -n _verify/run-all.sh`
- `bash -n _verify/cases/go-checks.sh`
- `bash _verify/cases/gitattributes-check.sh`
- ...and 1 more in `.crew/verify.json`.

## Hard rules
<!-- crew:keep:start -->
- (repo-owned hard rules go here; this block survives regeneration)
<!-- crew:keep:end -->

## Where things are (from `.crew/codemap/`)
- `logx` (`internal/logx/**`)
- `proto` (`internal/proto/**`)

<!-- crew:generated AGENTS.md -- regenerate with crew_instructions.py agents; only the crew:keep block is hand-edited -->
