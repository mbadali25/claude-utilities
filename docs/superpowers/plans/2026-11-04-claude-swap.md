# claude-swap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A LAN-only Go web server plus a Go agent per host that holds Matthew's Claude Ultra accounts, shows usage left and reset date, lists hosts and sessions, and swaps a host's login on demand.

**Architecture:** One Go module, two binaries (`cmd/server`, `cmd/agent`). Each agent dials out to the server over a WebSocket (TLS, pinned certificate). The server owns idle accounts' tokens in an encrypted file and polls their usage; the host that last swapped an account in owns it while active. A swap writes the host's live `claudeAiOauth` block back to the server, then replaces only that block in the host's credentials file, with backup and rollback.

**Tech Stack:** Go 1.27, `log/slog` (JSON), `github.com/coder/websocket`, `golang.org/x/crypto` (argon2id), stdlib `crypto/aes` GCM, `net/http` + `embed` for a plain-HTML UI. No front-end framework.

**Spec:** `docs/superpowers/specs/2026-11-04-claude-swap-design.md` (read it with this plan; decisions 1-11 are Matthew's, the rest are marked Claude's calls).

## Global Constraints

Copied from the spec; every task includes them.

- LAN only; Windows and Linux hosts; no macOS in v1; agents need no inbound ports.
- Single static Go binary per OS. Go 1.27 on Matthew's Windows machine; Linux builds via `GOOS=linux go build`; WSL has no Go and needs none.
- The agent runs as the host user (the login belongs to that user).
- Credentials file: Windows `%USERPROFILE%\.claude\.credentials.json`; Linux `~/.claude/.credentials.json`, mode 0600; WSL has its own separate `~/.claude`. `CLAUDE_CONFIG_DIR` relocates it.
- Top-level keys `claudeAiOauth` and `mcpOAuth`. `claudeAiOauth` keys: `accessToken`, `refreshToken`, `expiresAt`, `refreshTokenExpiresAt`, `scopes`, `subscriptionType`, `subscriptionTypeSource`, `rateLimitTier`.
- A swap replaces only `claudeAiOauth`. `mcpOAuth` is preserved exactly (byte-identical value) and never swapped.
- Every swap writes a backup of the previous block first. Atomic write: temp file, fsync, rename; restore on failure.
- Manual swap only. No auto-swap, no multi-user, one owner.
- Usage source: `GET https://api.anthropic.com/api/oauth/usage` with the OAuth bearer token (undocumented). Back off on HTTP 429; show last known with a timestamp; a schema change is a visible error, not a crash.
- Account tokens at rest: encrypted file, key from an environment variable at start.
- One account may be active on several hosts. Exactly one token owner per account: the server, or the host that most recently swapped it in. Other hosts are "shared".
- After a swap, mark that host's running sessions "needs reload" (user runs `/reload-plugins` or restarts the session).
- Never log or show tokens, emails or refresh tokens: not in logs, UI, errors or process arguments.
- Day-one hosts: `dadeush-desktop` (Windows) and the Linux laptop; each WSL install is its own host.

## Claude's calls in this plan (not decided by Matthew)

Module name `claude-utilities`; WebSocket library; TLS on by default with a self-signed cert and an agent-pinned fingerprint (tokens must not cross the LAN in clear); admin login by one password from an environment variable; agent runs as a Windows scheduled task at logon (not a SYSTEM service, so it runs as the user) and a systemd **user** unit on Linux; heartbeat 15 s, host offline after 45 s; usage poll every 5 min; keep the last 5 backups; swap journal on the agent.

## Review Focus

Most likely to bite first; each has a test in the owning task.

1. Claude Code rewrites `.credentials.json` (its own refresh) while a swap is in flight: the swap must not clobber it (Task 2).
2. The host's live account is unknown to the server (Matthew logged in by hand): refuse and offer import, never overwrite (Task 7).
3. The incoming block's `refreshTokenExpiresAt` is in the past: refuse with a stated reason (Task 8).
4. The agent or host dies mid-swap: on restart the agent finishes or rolls back from its journal (Task 8).
5. One account's token is revoked or the usage endpoint returns 429 or a changed schema: other accounts' usage still updates (Task 6).

---

## Phase 0

### Task 0: Spike (throwaway)

Verify the unverified calls before building around them. Code lives in `spike/` and is deleted at the end; no tests required. Never write token or email values into any file.

**Files:**
- Create: `spike/*` (throwaway), `docs/superpowers/spike-results.md`

**Interfaces:**
- Produces: `spike-results.md` with one row per question: `question | result (works / fails / partial) | evidence (command and non-secret output) | tasks affected`.

- [ ] **Step 1: S1 web login.** Determine whether a server-run OAuth login can yield a `claudeAiOauth` block (authorization URL, redirect handling, client id source). Record the exact flow or "not possible from a web page".
- [ ] **Step 2: S2 rotation and refresh.** On a throwaway copy of a credentials file, refresh once; record whether `refreshToken` changes, the refresh endpoint, and whether the old copy still works. Never touch the live file.
- [ ] **Step 3: S3 process scan.** On Windows, WSL and the Linux laptop, list running `claude` processes with working folder and session id using only an outside process. Record what each OS exposes (`/proc`, WMI/CIM, `~/.claude/projects` and `sessions` files).
- [ ] **Step 4: S4 canary.** Start a throwaway `claude` session under a temp `CLAUDE_CONFIG_DIR`, swap its credentials file to a second account's block, and record whether the running session uses the new login without restart.
- [ ] **Step 5: S5 identity.** Record which field in `~/.claude.json` (`oauthAccount`) identifies the account, and the usage endpoint's response field names and types for a real account (shape only, no values).
- [ ] **Step 6: S6 Linux.** Confirm on the Linux laptop the login path, mode, key names, and that a systemd user unit can run an agent. Include `srl-lin`'s reply if it has arrived.
- [ ] **Step 7: Decide.** Fill the "tasks affected" column. Defaults: if S1 fails, Task 9 ships import-only; if S2 shows rotation, keep Task 4 as written; if S2 shows no rotation, ownership still ships (cheap insurance); if S3 gives no session id on an OS, sessions show folder and PID only; if S4 shows a re-read, the badge text becomes "may need reload". Delete `spike/` and commit `spike-results.md`.

Commit: `git add docs/superpowers/spike-results.md && git commit -m "docs: spike results for claude-swap"`

---

## Phase 1: Independent building blocks

### Task 1: Module, protocol types and log redaction

**Files:**
- Create: `go.mod` (`module claude-utilities`), `internal/proto/proto.go`, `internal/proto/proto_test.go`, `internal/logx/logx.go`, `internal/logx/logx_test.go`

**Interfaces:**
- Produces (`proto`): `const Version = 1`; `type Envelope struct{ V int; Type string; ID string; Body json.RawMessage }`; message type constants `TypeHello`, `TypeHeartbeat`, `TypeReport`, `TypeExportReq`, `TypeExportRes`, `TypeSwapReq`, `TypeSwapRes`; body structs `Hello{Token, HostName, OS string}`, `Report{HostID, ActiveIdentity string; Sessions []Session; CredsPresent bool}`, `Session{PID int; ID, Cwd string; StartedAt time.Time}`, `ExportRes{Block json.RawMessage; Identity string; Err string}`, `SwapReq{Block json.RawMessage; Account string}`, `SwapRes{OK bool; Reason string}`; `func Encode(typ, id string, body any) ([]byte, error)`; `func Decode(b []byte) (Envelope, error)` (rejects `V != Version`).
- Produces (`logx`): `func New(w io.Writer) *slog.Logger` (JSON handler that replaces the value of attributes named `accessToken`, `refreshToken`, `token`, `code`, `key`, `password`, `email` with `"[redacted]"`); `func Redact(s string) string` (masks bearer-token-looking substrings).

- [ ] **Step 1: Write failing tests.** `TestEncodeDecodeRoundTrip`, `TestDecodeRejectsWrongVersion`, `TestDecodeRejectsMalformedJSON`, `TestSwapResNeverCarriesBlock`, `TestLoggerRedactsSecretAttrs` (log `accessToken=sk-ant-oat01-abc`; assert output lacks `abc`), `TestRedactMasksBearer`.
- [ ] **Step 2: Run `go test ./internal/proto ./internal/logx`; expect FAIL (undefined).**
- [ ] **Step 3: Implement** the signatures above. `go mod init claude-utilities` first.
- [ ] **Step 4: Run the same command; expect PASS.**
- [ ] **Step 5: Commit** `feat: protocol envelope and log redaction`.

### Task 2: credfile (read, replace, backup, rollback)

**Files:**
- Create: `internal/credfile/credfile.go`, `internal/credfile/path_windows.go`, `internal/credfile/path_unix.go`, `internal/credfile/credfile_test.go`

**Interfaces:**
- Consumes: none.
- Produces: `func ResolvePath() (string, error)` (honours `CLAUDE_CONFIG_DIR`, else `<home>/.claude/.credentials.json`); `func ReadBlock(path string) (json.RawMessage, error)` (returns `ErrNoBlock` if absent); `func ValidateBlock(b json.RawMessage) error` (requires the 8 keys listed in Global Constraints, and `refreshTokenExpiresAt` in the future → `ErrRefreshExpired`); `func Replace(path string, block json.RawMessage) (backup string, err error)`; `func Restore(path, backup string) error`; `var ErrBusy, ErrNoBlock, ErrChangedDuringSwap, ErrRefreshExpired error`.

- [ ] **Step 1: Write failing tests** with temp dirs: `TestReplaceKeepsMcpOAuthByteIdentical`, `TestReplaceCreatesBackupFirst`, `TestReplaceKeepsMode0600` (skip on Windows), `TestReplaceFailureLeavesOriginal` (inject a failing rename via an unexported `renameFn` var), `TestRestoreRecoversPreviousBlock`, `TestReplaceEmptyFile`, `TestReplaceMalformedJSONRefusesAndKeepsFile`, `TestReplaceMissingMcpOAuth`, `TestReplaceUnicodePath`, `TestReplaceConcurrentReturnsErrBusy` (lock file), `TestReplaceAbortsIfFileChangedDuringSwap` (Review Focus 1: hash the file before and just before rename; changed → `ErrChangedDuringSwap`, original untouched), `TestBackupsPrunedToFive`, `TestValidateBlockRejectsExpiredRefresh`.
- [ ] **Step 2: Run `go test ./internal/credfile`; expect FAIL.**
- [ ] **Step 3: Implement.** Decode the file as `map[string]json.RawMessage`, swap only `claudeAiOauth`, re-encode; backups go to `<dir>/.swap-backups/` at 0600; write temp in the same directory, `fsync`, `os.Rename`.
- [ ] **Step 4: Run; expect PASS (Windows and, via `wsl`, Linux).**
- [ ] **Step 5: Commit** `feat: credfile atomic block replace with rollback`.

### Task 3: vault (encrypted token file)

**Files:**
- Create: `internal/vault/vault.go`, `internal/vault/vault_test.go`

**Interfaces:**
- Produces: `type Account struct{ ID, Label, Identity string; Block json.RawMessage; Updated time.Time }`; `func Open(path, keyEnv string) (*Vault, error)`; `func (v *Vault) Put(Account) error`; `Get(id string) (Account, bool)`; `List() []Account` (no `Block` in the copy `ListPublic()` returns for the UI); `Delete(id string) error`; `var ErrNoKey, ErrBadKey error`.

- [ ] **Step 1: Write failing tests:** `TestPutGetRoundTripAcrossReopen`, `TestFileIsNotPlaintext` (grep file bytes for a known token substring), `TestWrongKeyReturnsErrBadKeyAndDoesNotOverwrite` (file bytes unchanged after the failed open), `TestMissingEnvReturnsErrNoKeyWithHint`, `TestTamperedFileFailsAuth`, `TestWriteIsAtomic` (inject failing rename; old file intact), `TestFileMode0600` (skip on Windows), `TestEmptyVaultListsEmpty`, `TestConcurrentPutSafe` (`-race`).
- [ ] **Step 2: Run `go test -race ./internal/vault`; expect FAIL.**
- [ ] **Step 3: Implement** AES-256-GCM; key = argon2id(env value, random 16-byte salt stored in the file header), fresh nonce per write.
- [ ] **Step 4: Run; expect PASS.**
- [ ] **Step 5: Commit** `feat: encrypted account vault`.

### Task 4: ownership state machine

**Files:**
- Create: `internal/ownership/ownership.go`, `internal/ownership/ownership_test.go`

**Interfaces:**
- Produces: `type Owner struct{ Server bool; HostID string }`; `type HostState int` (`Active`, `Shared`, `Stale`); `type Registry struct{...}`; `func New() *Registry`; `func (r *Registry) SwapIn(account, host string)` (host becomes owner; previous holders become Shared); `SwapAway(account, host string)` (host stops using it; if it was the owner and no one else uses it, owner → server; if others use it, owner → the most recent remaining holder); `HostLost(host string)` (a lost owner marks the account `Stale` if hosts still share it, else owner → server marked "needs writeback check"); `OwnerOf(account string) Owner`; `HostsUsing(account string) map[string]HostState`.

- [ ] **Step 1: Write failing tests:** `TestIdleAccountOwnedByServer`, `TestSwapInMakesHostOwner`, `TestSecondHostSwapInMovesOwnerAndMarksFirstShared`, `TestSwapAwayLastHostReturnsToServer`, `TestSwapAwayOwnerPassesToRemainingHolder`, `TestHostLostOwnerWithSharersMarksStale`, `TestSwapInSameHostTwiceIsIdempotent`, `TestConcurrentOpsRaceFree` (`-race`).
- [ ] **Step 2: Run `go test -race ./internal/ownership`; expect FAIL.**
- [ ] **Step 3: Implement** with a mutex and a map; no I/O.
- [ ] **Step 4: Run; expect PASS.**
- [ ] **Step 5: Commit** `feat: token ownership registry`.

### Task 5: session scan

**Files:**
- Create: `internal/sessions/sessions.go`, `internal/sessions/scan_windows.go`, `internal/sessions/scan_linux.go`, `internal/sessions/sessions_test.go`

**Interfaces:**
- Consumes: `proto.Session`.
- Produces: `func Scan(ctx context.Context) ([]proto.Session, error)`; `func parse(raw []byte) ([]proto.Session, error)` (unexported, pure; one per OS format chosen by the spike S3); `func NeedsReload(sessions []proto.Session, swappedAt time.Time) []string` (ids of sessions started before `swappedAt`).

- [ ] **Step 1: Write failing tests** against captured fixtures from the spike (non-secret): `TestParseWindowsFixture`, `TestParseLinuxFixture`, `TestParseEmptyOutput`, `TestScanIgnoresNonClaudeProcesses`, `TestNeedsReloadOnlyOlderSessions`, `TestScanSurvivesUnreadableProcEntry`, `TestCwdWithUnicodeAndSpaces`.
- [ ] **Step 2: Run `go test ./internal/sessions`; expect FAIL.**
- [ ] **Step 3: Implement** the scan the spike proved on each OS; if S3 found no session id on an OS, leave `Session.ID` empty and key on PID.
- [ ] **Step 4: Run; expect PASS on Windows and Linux.**
- [ ] **Step 5: Commit** `feat: claude session scan`.

### Task 6: usage poller (finalise field names after spike S5)

**Files:**
- Create: `internal/usage/usage.go`, `internal/usage/usage_test.go`

**Interfaces:**
- Produces: `type Window struct{ UsedPct float64; ResetsAt time.Time }`; `type Usage struct{ FiveHour, SevenDay Window; FetchedAt time.Time; Err string }`; `type Doer interface{ Do(*http.Request) (*http.Response, error) }`; `func Fetch(ctx context.Context, d Doer, accessToken string) (Usage, error)` (GET `https://api.anthropic.com/api/oauth/usage`, `Authorization: Bearer`); `var ErrRateLimited, ErrSchema, ErrUnauthorized error`; `type Poller struct{...}`; `func NewPoller(d Doer, interval time.Duration) *Poller`; `(p *Poller) Run(ctx context.Context, accounts func() []vault.Account, onUpdate func(accountID string, u Usage))`; `(p *Poller) Last(accountID string) (Usage, bool)`.

- [ ] **Step 1: Write failing tests** with a fake `Doer`: `TestFetchParsesFiveHourAndSevenDay`, `TestFetch429ReturnsErrRateLimitedWithRetryAfter`, `TestFetchUnexpectedSchemaReturnsErrSchemaNotPanic`, `TestFetch401ReturnsErrUnauthorized`, `TestPollerBacksOffExponentiallyOn429`, `TestPollerKeepsLastKnownWithTimestampOnError`, `TestOneRevokedAccountDoesNotStopOthers` (Review Focus 5), `TestPollerNeverLogsToken` (capture log output).
- [ ] **Step 2: Run `go test ./internal/usage`; expect FAIL.**
- [ ] **Step 3: Implement.** Poll only server-owned accounts; host-owned accounts take usage from the agent's report. Server-side token refresh uses the endpoint the spike S2 found, behind an `interface{ Refresh(ctx, block) (block, error) }` injected into the poller.
- [ ] **Step 4: Run; expect PASS.**
- [ ] **Step 5: Commit** `feat: usage poller with backoff and last-known`.

---

## Phase 2: Hub, agent, UI

### Task 7: hub (connections, enrolment, swap orchestration)

**Files:**
- Create: `internal/hub/hub.go`, `internal/hub/enrol.go`, `internal/hub/tls.go`, `internal/hub/hub_test.go`

**Interfaces:**
- Consumes: `proto`, `vault`, `ownership`, `logx`.
- Produces: `func New(v *vault.Vault, r *ownership.Registry, tokensPath string, log *slog.Logger) *Hub`; `(h *Hub) NewEnrolCode() (code string, expires time.Time)` (single use, 10 min); `(h *Hub) Enrol(code, hostName, os string) (agentToken string, err error)`; `(h *Hub) Revoke(hostID string) error`; `(h *Hub) ServeWS(w http.ResponseWriter, r *http.Request)`; `(h *Hub) Hosts() []HostView` (`HostID, Name, OS string; Online bool; ActiveAccount string; Sessions []SessionView{proto.Session; NeedsReload bool}`); `(h *Hub) Swap(ctx context.Context, hostID, accountID string) error`; `func EnsureCert(dir string) (certFile, keyFile, fingerprint string, err error)`; `var ErrAgentOffline, ErrUnknownLiveAccount, ErrBadCode, ErrRevoked error`. Agent tokens are stored as SHA-256 hashes.

- [ ] **Step 1: Write failing tests** with an in-process fake agent over `httptest`: `TestEnrolCodeSingleUse`, `TestEnrolCodeExpires`, `TestBadTokenRejected`, `TestRevokedTokenRejected`, `TestHeartbeatTimeoutMarksOffline`, `TestSwapRefusesOfflineHost`, `TestSwapWritesBackLiveBlockBeforeSending`, `TestSwapUnknownLiveAccountReturnsErrUnknownLiveAccountAndSendsNothing` (Review Focus 2), `TestSwapFailureLeavesOwnershipUnchanged`, `TestSwapSuccessMarksSessionsNeedsReload`, `TestConcurrentSwapsSameHostSerialised`, `TestTokenNeverInLogs`, `TestEnsureCertStableFingerprintAcrossRestarts`.
- [ ] **Step 2: Run `go test -race ./internal/hub`; expect FAIL.**
- [ ] **Step 3: Implement.** Swap order: offline check → `ExportReq` → match `Identity` to a vault account (else `ErrUnknownLiveAccount`) → vault writeback → `SwapReq` → on `SwapRes.OK` call `ownership.SwapIn` and record `swappedAt`; per-host mutex; heartbeat 15 s, offline after 45 s.
- [ ] **Step 4: Run; expect PASS.**
- [ ] **Step 5: Commit** `feat: hub with enrolment and swap orchestration`.

### Task 8: agent (dial-out, heartbeat, swap with journal)

**Files:**
- Create: `internal/agent/agent.go`, `internal/agent/backoff.go`, `internal/agent/journal.go`, `internal/agent/agent_test.go`, `cmd/agent/main.go`

**Interfaces:**
- Consumes: `proto`, `credfile`, `sessions`, `logx`.
- Produces: `type Config struct{ ServerURL, Token, Pin, CredsPath, StateDir string }`; `func Run(ctx context.Context, c Config) error`; `func NextDelay(attempt int) time.Duration` (1 s doubling to a 60 s cap, with jitter); `func Enrol(ctx context.Context, serverURL, pin, code, hostName string) (Config, error)`; `cmd/agent` subcommands `enrol --server --pin --code`, `run`, `install` (Task 11). Config file: `<StateDir>/agent.json`, mode 0600.

- [ ] **Step 1: Write failing tests:** `TestNextDelayGrowsAndCaps`, `TestReconnectsAfterServerDrop`, `TestRejectsServerWithWrongPin`, `TestExportReqReturnsLiveBlockWithoutLoggingIt`, `TestSwapAppliesBlockAndVerifiesReadBack`, `TestSwapRollsBackWhenReadBackFails`, `TestSwapRefusesExpiredRefreshToken` (Review Focus 3, reason `refresh token expired` in `SwapRes`), `TestJournalFinishesOrRollsBackAfterCrash` (Review Focus 4: write journal, simulate kill between backup and rename, restart, assert the original block is restored), `TestMissingCredsFileReportsCredsPresentFalse`, `TestHeartbeatCarriesSessions`.
- [ ] **Step 2: Run `go test -race ./internal/agent`; expect FAIL.**
- [ ] **Step 3: Implement.** Journal `{state, backupPath}` is written before `credfile.Replace` and cleared after read-back verification; on startup an unfinished journal triggers `credfile.Restore`.
- [ ] **Step 4: Run; expect PASS.**
- [ ] **Step 5: Commit** `feat: agent with dial-out, journal and rollback`.

### Task 9: web UI and API (login section: finalise after spike S1)

**Files:**
- Create: `internal/web/web.go`, `internal/web/static/index.html`, `internal/web/web_test.go`, `cmd/server/main.go`

**Interfaces:**
- Consumes: `hub.Hub`, `vault.Vault`, `usage.Poller`.
- Produces: `func Handler(h *hub.Hub, v *vault.Vault, p *usage.Poller, adminPassword string) http.Handler`; routes `GET /` (embedded HTML), `GET /api/accounts` (label, identity, usage left %, reset time, last-known age, owner, error — never `Block`), `GET /api/hosts`, `POST /api/swap {host, account}`, `POST /api/enrol-code`, `POST /api/hosts/{id}/revoke`, `POST /api/import {host, label}` (pull the live block from a logged-in host and create an account). `cmd/server` flags: `--listen host:port` (required, no default), `--data-dir`, env `CLAUDESWAP_KEY`, `CLAUDESWAP_ADMIN_PASSWORD`. If the web OAuth login is possible (S1), add `POST /api/login/start` and `/api/login/callback`; if not, the UI says "Add account: import from a logged-in host".

- [ ] **Step 1: Write failing tests** with `httptest`: `TestAccountsNeverIncludeTokens` (response body lacks the block substring), `TestUnauthenticatedRequestRejected`, `TestSwapEndpointCallsHub`, `TestSwapErrorShowsReasonNotToken`, `TestHostsShowNeedsReloadBadge`, `TestUsageShowsLastKnownWithAgeOnError`, `TestImportCreatesAccountFromHost`, `TestMcpOAuthNoticeShownInUI` (page text states MCP logins may belong to another account), `TestListenRequiredRefusesStartWithoutFlag`.
- [ ] **Step 2: Run `go test ./internal/web`; expect FAIL.**
- [ ] **Step 3: Implement** with `net/http` and `embed`; one page, accounts and hosts tables, a swap form per host, HTTP basic auth over TLS.
- [ ] **Step 4: Run; expect PASS.**
- [ ] **Step 5: Commit** `feat: server UI and API`.

### Task 10: service install and README

**Files:**
- Create: `internal/install/install.go`, `internal/install/install_test.go`, `README.md` (modify the existing two-line file)

**Interfaces:**
- Produces: `func RenderSystemdUserUnit(exe, stateDir string) string`; `func SchtasksCreateArgs(exe, user string) []string` (`/Create /SC ONLOGON /TN ClaudeSwapAgent /RU <user> /TR "<exe> run"`); `func Install(exe, stateDir string) error` (Windows: `schtasks`; Linux: write `~/.config/systemd/user/claude-swap-agent.service`, print `loginctl enable-linger` hint).

- [ ] **Step 1: Write failing tests:** `TestRenderSystemdUnitHasRestartAlways`, `TestSchtasksArgsQuoteExePathWithSpaces`, `TestRenderUnitNeverContainsToken`.
- [ ] **Step 2: Run `go test ./internal/install`; expect FAIL.**
- [ ] **Step 3: Implement** the two renderers and `Install`. README covers build (`go build ./...`, `GOOS=linux go build -o claude-swap-agent ./cmd/agent`), env vars, enrolment, the mcpOAuth caveat, and the Anthropic-terms risk.
- [ ] **Step 4: Run; expect PASS.**
- [ ] **Step 5: Commit** `feat: agent service install and README`.

### Task 11: end-to-end on real hosts

**Files:**
- Create: `scripts/e2e.ps1`, `docs/superpowers/e2e-results.md`

**Interfaces:**
- Consumes: both binaries.

- [ ] **Step 1: Sandbox run.** Start the server on the Windows desktop with a temp data dir and test key. Enrol three agents against temp `CLAUDE_CONFIG_DIR` folders: Windows, WSL, and the Linux laptop (cross-compiled with `GOOS=linux go build`). Use two fake credential blocks with future `refreshTokenExpiresAt`.
- [ ] **Step 2: Verify** swap A→B on each host: `mcpOAuth` byte-identical, backup exists, sessions show "needs reload", usage panel shows an error state for fake tokens without breaking the page.
- [ ] **Step 3: Failure drills.** Kill the agent mid-swap (journal restores), stop the server (agent reconnects with backoff), supply a wrong vault key (server refuses to start, file untouched).
- [ ] **Step 4: Real hosts.** With Matthew present, swap one real account on one real host. Confirm Claude Code starts, then swap back. Record results, not secrets.
- [ ] **Step 5: Commit** `docs: e2e results`.

---

## Self-review

- **Spec coverage:** transport (T7, T8), swap and backup (T2, T8), usage (T6), vault (T3), ownership incl. shared (T4), hosts/sessions and badge (T5, T7, T9), enrolment and TLS (T7), import fallback (T9), service (T10), v1-done check (T11), spike and Linux findings (T0). The spec's "UI notes MCP logins may differ" is `TestMcpOAuthNoticeShownInUI`.
- **Types checked:** `proto.Session`, `vault.Account`, `ownership.Registry` and `credfile` signatures match every consumer above.
- **Proportion:** plan is signatures, test names and assertions only; no function bodies.
