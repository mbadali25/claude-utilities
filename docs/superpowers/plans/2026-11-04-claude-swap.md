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
- Logging is an allowlist (Matthew, 2026-11-04, spec Decision 12): the logger emits only allowlisted safe keys and withholds every other attribute; allowlisted free-text values pass through `Redact` and a 256-byte cap. New fields are withheld until added to the allowlist.
- Enrolment is by approval (Matthew, 2026-11-04, spec Decision 13): an agent with no valid token appears in the UI's Pending connections list (host name, OS, source IP, time, fingerprint) and the owner clicks Allow or Deny. Allow issues a per-agent token over that same connection; Deny closes it and suppresses the fingerprint. The one-time code is an optional pre-approved path.
- Day-one hosts: `dadeush-desktop` (Windows) and the Linux laptop; each WSL install is its own host.

## Claude's calls in this plan (not decided by Matthew)

Module name `claude-utilities`; WebSocket library; TLS on by default with a self-signed cert and an agent-pinned fingerprint (tokens must not cross the LAN in clear); admin login by one password from an environment variable, exchanged for a session cookie (HttpOnly, Secure, SameSite=Strict) plus a per-session CSRF token that every POST must echo in `X-CSRF-Token`; agent runs as a Windows scheduled task at logon (not a SYSTEM service, so it runs as the user) and a systemd **user** unit on Linux; heartbeat 15 s, host offline after 45 s; usage poll every 5 min; keep the last 5 backups; swap journal on the agent.

**Pending connections, security calls (Claude's, not Matthew's; spec "Builder-check resolutions"):** viewing or acting on the pending list needs an admin session (else 401); Allow and Deny are POSTs with a CSRF token (wrong → 403); queue cap 20 entries; per-source-IP limit 3 pending entries per 10 min; entries expire after 10 min and an expired entry cannot be approved; a pending connection may send only its hello, receives no account/host/session data, and is dropped on any other message; the fingerprint is derived from the hello (host name, OS, per-attempt agent nonce) and the agent prints it so the owner matches it before clicking Allow; Deny suppresses the fingerprint for 1 h; every Allow/Deny writes one audit log line with allowlisted keys only; the issued token appears only in the single Approved message to the agent.

**Default logx allowlist (Claude's call):** `time`, `level`, `msg`, `host_id`, `host_name`, `os`, `source_ip`, `fingerprint`, `account_id`, `account_label`, `action`, `result`, `reason`, `err`, `pid`, `session_id`, `attempt`, `count`, `duration_ms`, `withheld`. Free-text keys (`msg`, `reason`, `err`) are redacted and capped at 256 bytes. `withheld` is the count of attributes the logger dropped on that line.

## Review Focus

Most likely to bite first; each has a test in the owning task.

1. Claude Code rewrites `.credentials.json` (its own refresh) while a swap is in flight: the swap must not clobber it (Task 2).
2. The host's live account is unknown to the server (Matthew logged in by hand): refuse and offer import, never overwrite (Task 7).
3. The incoming block's `refreshTokenExpiresAt` is in the past: refuse with a stated reason (Task 8).
4. The agent or host dies mid-swap: on restart the agent finishes or rolls back from its journal (Task 8).
5. One account's token is revoked or the usage endpoint returns 429 or a changed schema: other accounts' usage still updates (Task 6).
6. A log call carries a new, unlisted attribute (say `block` or `authorization`): the allowlist logger withholds it; nothing leaks by default (Task 1).
7. A pending (unapproved) connection sends anything but its hello, or a LAN device floods hellos: the connection is dropped, the queue stays capped at 20, the per-IP limit holds, and no account data was ever sent to it (Task 7).
8. Allow is called without an admin session, or with a wrong CSRF token: 401 or 403, no token issued, no state change (Task 9).
9. The Approved message is the one place a token legitimately travels: it is never logged, never in an API response, and the agent stores it at 0600 (Tasks 1, 8).

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
- Produces (`proto`): `const Version = 1`; `type Envelope struct{ V int; Type string; ID string; Body json.RawMessage }`; message type constants `TypeHello`, `TypePending`, `TypeApproved`, `TypeDenied`, `TypeHeartbeat`, `TypeReport`, `TypeExportReq`, `TypeExportRes`, `TypeSwapReq`, `TypeSwapRes`; body structs `Hello{Token, Code, HostName, OS, Nonce string}` (`Token` empty and `Code` empty → pending path; `Code` set → pre-approved path), `Pending{Fingerprint string; ExpiresAt time.Time}`, `Approved{Token string}` (the only server→agent message that carries a token), `Denied{Reason string; RetryAfter time.Duration}`, `Report{HostID, ActiveIdentity string; Sessions []Session; CredsPresent bool}`, `Session{PID int; ID, Cwd string; StartedAt time.Time}`, `ExportRes{Block json.RawMessage; Identity string; Err string}`, `SwapReq{Block json.RawMessage; Account string}`, `SwapRes{OK bool; Reason string}`; `func Encode(typ, id string, body any) ([]byte, error)`; `func Decode(b []byte) (Envelope, error)` (rejects `V != Version`); `func Fingerprint(h Hello) string` (8 lowercase base32 characters of SHA-256 over `HostName|OS|Nonce`; pure, so agent and server compute the same value).
- Produces (`logx`): `type Policy struct{...}`; `func Allow(keys ...string) *Policy` (the allowlist; `DefaultPolicy()` returns the list in "Claude's calls"); `func New(w io.Writer, p *Policy) *slog.Logger` (JSON handler: emits only allowlisted keys; drops every other attribute and adds `withheld=<count>`; passes the values of `msg`, `reason`, `err` through `Redact` then truncates to 256 bytes); `func Redact(s string) string` (masks bearer-token-looking substrings and `sk-ant-` prefixes).

- [ ] **Step 1: Write failing tests.** `TestEncodeDecodeRoundTrip`, `TestDecodeRejectsWrongVersion`, `TestDecodeRejectsMalformedJSON`, `TestSwapResNeverCarriesBlock`, `TestFingerprintIsDeterministicAnd8Chars`, `TestFingerprintChangesWithNonce` (same host name and OS, different nonce → different value), `TestPendingAndDeniedCarryNoToken` (encoded bodies lack the field), `TestLoggerEmitsOnlyAllowlistedKeys` (log `host_name=x accessToken=sk-ant-oat01-abc block={...}`; output has `host_name`, lacks `abc`, lacks `block`, has `withheld=2`), `TestLoggerUnknownKeyIsWithheldNotRedacted` (an unlisted key named `authorization` is absent from output, not emitted as `[redacted]`), `TestLoggerFreeTextIsRedactedAndCapped` (`reason` of 300 bytes containing `Bearer sk-ant-...` → output lacks the token and the value is at most 256 bytes), `TestRedactMasksBearer`.
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

### Task 7: hub (connections, pending approval, enrolment, swap orchestration)

**Files:**
- Create: `internal/hub/hub.go`, `internal/hub/pending.go`, `internal/hub/enrol.go`, `internal/hub/tls.go`, `internal/hub/hub_test.go`, `internal/hub/pending_test.go`

**Interfaces:**
- Consumes: `proto`, `vault`, `ownership`, `logx`.
- Produces: `func New(v *vault.Vault, r *ownership.Registry, tokensPath string, log *slog.Logger) *Hub`; `(h *Hub) NewEnrolCode() (code string, expires time.Time)` (optional pre-approved path; single use, 10 min); `(h *Hub) Revoke(hostID string) error`; `(h *Hub) ServeWS(w http.ResponseWriter, r *http.Request)`; `(h *Hub) Hosts() []HostView` (`HostID, Name, OS string; Online bool; ActiveAccount string; Sessions []SessionView{proto.Session; NeedsReload bool}`); `(h *Hub) Swap(ctx context.Context, hostID, accountID string) error`; `func EnsureCert(dir string) (certFile, keyFile, fingerprint string, err error)`; `var ErrAgentOffline, ErrUnknownLiveAccount, ErrBadCode, ErrRevoked error`. Agent tokens are stored as SHA-256 hashes.
- Produces (pending, spec Decision 13): `const PendingCap = 20`, `PendingTTL = 10 * time.Minute`, `DenySuppress = time.Hour`, `PendingPerIP = 3`, `PendingPerIPWindow = 10 * time.Minute`; `type PendingView struct{ Fingerprint, HostName, OS, SourceIP string; Since, ExpiresAt time.Time }`; `(h *Hub) Pending() []PendingView`; `(h *Hub) Allow(fingerprint string) (hostID string, err error)` (mints the token, sends `Approved` over the pending connection, stores the hash, promotes the connection to enrolled, logs `action=allow`); `(h *Hub) Deny(fingerprint string) error` (sends `Denied{RetryAfter: DenySuppress}`, closes, suppresses, logs `action=deny`); `var ErrNotPending, ErrPendingExpired, ErrPendingFull, ErrSuppressed, ErrRateLimited error`. A hello with a valid `Code` bypasses the queue; a hello with a valid `Token` is a normal reconnect.

- [ ] **Step 1: Write failing tests** with an in-process fake agent over `httptest`: `TestEnrolCodeSingleUse`, `TestEnrolCodeExpires`, `TestBadTokenRejected`, `TestRevokedTokenRejected`, `TestHeartbeatTimeoutMarksOffline`, `TestSwapRefusesOfflineHost`, `TestSwapWritesBackLiveBlockBeforeSending`, `TestSwapUnknownLiveAccountReturnsErrUnknownLiveAccountAndSendsNothing` (Review Focus 2), `TestSwapFailureLeavesOwnershipUnchanged`, `TestSwapSuccessMarksSessionsNeedsReload`, `TestConcurrentSwapsSameHostSerialised`, `TestTokenNeverInLogs`, `TestEnsureCertStableFingerprintAcrossRestarts`.
- [ ] **Step 1b: Write failing pending tests** (`pending_test.go`, fake clock): `TestTokenlessHelloIsListedPendingWithFingerprint` (entry shows host name, OS, source IP, since, and `proto.Fingerprint(hello)`; agent received `Pending` and nothing else), `TestPendingQueueCapIs20` (21st hello closed with reason `queue full`, `ErrPendingFull`, list length stays 20), `TestPendingPerIPLimit3Per10Min` (4th hello from one IP inside 10 min is closed before listing, `ErrRateLimited`; a different IP is unaffected; after the window the IP may add again), `TestPendingExpiresAfter10Min` (advance 10 min 1 s; entry gone; `Allow` → `ErrPendingExpired`; connection closed), `TestPendingConnectionSendingOtherMessageIsDropped` (Review Focus 7: a `Heartbeat`, `Report` or `ExportRes` before approval closes the connection and removes the entry), `TestPendingConnectionReceivesNoAccountData` (nothing but `Pending`/`Approved`/`Denied` is ever written to a pending socket, checked by a recording fake), `TestAllowIssuesTokenOverSameConnectionAndEnrols` (agent receives one `Approved`; its next hello with that token is accepted; stored value is the SHA-256, not the token), `TestAllowUnknownFingerprintIsErrNotPending`, `TestDenyClosesAndSuppressesForOneHour` (re-dial with the same fingerprint inside 1 h is closed, `ErrSuppressed`, not listed; a fresh nonce is listed; after 1 h the old fingerprint is listed again), `TestDeniedEntryCannotBeAllowed`, `TestValidCodeBypassesQueue`, `TestAllowAndDenyWriteAuditLineWithAllowlistedKeysOnly` (captured log has `action`, `fingerprint`, `host_name`, `os`, `source_ip`, `result`; lacks the token and any email), `TestConcurrentHellosRaceFree` (`-race`).
- [ ] **Step 2: Run `go test -race ./internal/hub`; expect FAIL.**
- [ ] **Step 3: Implement.** Swap order: offline check → `ExportReq` → match `Identity` to a vault account (else `ErrUnknownLiveAccount`) → vault writeback → `SwapReq` → on `SwapRes.OK` call `ownership.SwapIn` and record `swappedAt`; per-host mutex; heartbeat 15 s, offline after 45 s. Pending: a connection state machine `pending → enrolled | closed`; the read loop for a pending connection accepts no frame after the hello; a sweeper evicts expired entries and expired suppressions; suppression and rate-limit state are in memory (lost on restart, acceptable).
- [ ] **Step 4: Run; expect PASS.**
- [ ] **Step 5: Commit** `feat: hub with enrolment and swap orchestration`.

### Task 8: agent (dial-out, heartbeat, swap with journal)

**Files:**
- Create: `internal/agent/agent.go`, `internal/agent/backoff.go`, `internal/agent/journal.go`, `internal/agent/agent_test.go`, `cmd/agent/main.go`

**Interfaces:**
- Consumes: `proto`, `credfile`, `sessions`, `logx`.
- Produces: `type Config struct{ ServerURL, Token, Pin, CredsPath, StateDir string }`; `func Run(ctx context.Context, c Config) error`; `func NextDelay(attempt int) time.Duration` (1 s doubling to a 60 s cap, with jitter); `func Enrol(ctx context.Context, serverURL, pin, hostName, code string, out io.Writer) (Config, error)` (spec Decision 13: generates a fresh nonce, sends a tokenless hello, prints `Fingerprint: <8 chars>` and "approve this host in the web UI" to `out`, waits up to 10 min for `Approved`; `code` non-empty takes the pre-approved path); `var ErrDenied, ErrApprovalTimeout error`; `cmd/agent` subcommands `enrol --server --pin [--code]`, `run`, `install` (Task 11). Config file: `<StateDir>/agent.json`, mode 0600.

- [ ] **Step 1: Write failing tests:** `TestNextDelayGrowsAndCaps`, `TestReconnectsAfterServerDrop`, `TestRejectsServerWithWrongPin`, `TestExportReqReturnsLiveBlockWithoutLoggingIt`, `TestSwapAppliesBlockAndVerifiesReadBack`, `TestSwapRollsBackWhenReadBackFails`, `TestSwapRefusesExpiredRefreshToken` (Review Focus 3, reason `refresh token expired` in `SwapRes`), `TestJournalFinishesOrRollsBackAfterCrash` (Review Focus 4: write journal, simulate kill between backup and rename, restart, assert the original block is restored), `TestMissingCredsFileReportsCredsPresentFalse`, `TestHeartbeatCarriesSessions`.
- [ ] **Step 1b: Write failing enrolment tests** against a fake server: `TestEnrolPrintsFingerprintMatchingHello` (console output contains `proto.Fingerprint` of the hello it sent; output lacks the nonce), `TestEnrolSendsNothingAfterHelloUntilApproved` (no heartbeat or report while pending), `TestEnrolStoresApprovedTokenAt0600AndNeverLogsIt` (agent.json mode 0600, skip mode check on Windows; captured log and console lack the token), `TestEnrolDeniedExitsWithReasonAndHonoursRetryAfter` (`ErrDenied`; no re-dial before `RetryAfter`), `TestEnrolTimesOutAfter10Min` (fake clock; `ErrApprovalTimeout`; exit non-zero), `TestEnrolWithCodeSkipsPending` (fake server sees `Code` and replies `Approved` directly), `TestEnrolFreshNonceEachAttempt` (two runs produce two fingerprints).
- [ ] **Step 2: Run `go test -race ./internal/agent`; expect FAIL.**
- [ ] **Step 3: Implement.** Journal `{state, backupPath}` is written before `credfile.Replace` and cleared after read-back verification; on startup an unfinished journal triggers `credfile.Restore`. Enrol: one hello, then block on the read loop for `Pending` (print fingerprint and expiry), `Approved` (write config, exit 0) or `Denied` (print reason, exit 2).
- [ ] **Step 4: Run; expect PASS.**
- [ ] **Step 5: Commit** `feat: agent with dial-out, journal and rollback`.

### Task 9: web UI and API (login section: finalise after spike S1)

**Files:**
- Create: `internal/web/web.go`, `internal/web/static/index.html`, `internal/web/web_test.go`, `cmd/server/main.go`

**Interfaces:**
- Consumes: `hub.Hub`, `vault.Vault`, `usage.Poller`.
- Produces: `func Handler(h *hub.Hub, v *vault.Vault, p *usage.Poller, adminPassword string) http.Handler`; routes `GET /` (embedded HTML; login form when no session), `POST /login` (password → session cookie HttpOnly, Secure, SameSite=Strict; CSRF token embedded in the page and required as `X-CSRF-Token` on every POST), `GET /api/accounts` (label, identity, usage left %, reset time, last-known age, owner, error — never `Block`), `GET /api/hosts`, `POST /api/swap {host, account}`, `POST /api/enrol-code`, `POST /api/hosts/{id}/revoke`, `POST /api/import {host, label}` (pull the live block from a logged-in host and create an account). Pending connections (spec Decision 13): `GET /api/pending` (`hub.PendingView` list: fingerprint, host name, OS, source IP, since, expires), `POST /api/pending/{fingerprint}/allow`, `POST /api/pending/{fingerprint}/deny`; the page has a **Pending connections** panel with one row per entry, the fingerprint in large type, the text "Match this code with the one the agent printed before you click Allow", and Allow and Deny buttons; the panel refreshes every 5 s. Every route except `GET /` and `POST /login` requires the session (else 401). `cmd/server` flags: `--listen host:port` (required, no default), `--data-dir`, env `CLAUDESWAP_KEY`, `CLAUDESWAP_ADMIN_PASSWORD`. If the web OAuth login is possible (S1), add `POST /api/login/start` and `/api/login/callback`; if not, the UI says "Add account: import from a logged-in host".

- [ ] **Step 1: Write failing tests** with `httptest`: `TestAccountsNeverIncludeTokens` (response body lacks the block substring), `TestUnauthenticatedRequestRejected`, `TestSwapEndpointCallsHub`, `TestSwapErrorShowsReasonNotToken`, `TestHostsShowNeedsReloadBadge`, `TestUsageShowsLastKnownWithAgeOnError`, `TestImportCreatesAccountFromHost`, `TestMcpOAuthNoticeShownInUI` (page text states MCP logins may belong to another account), `TestListenRequiredRefusesStartWithoutFlag`.
- [ ] **Step 1b: Write failing pending-panel tests** with a fake hub: `TestPendingListRequiresAdminSession` (`GET /api/pending` without cookie → 401, empty body), `TestAllowWithoutAdminSessionIs401` (Review Focus 8: fake hub's `Allow` not called), `TestAllowWithWrongCSRFIs403` (valid cookie, wrong or missing `X-CSRF-Token` → 403, `Allow` not called), `TestDenyWithWrongCSRFIs403`, `TestAllowCallsHubAndResponseNeverContainsToken` (200, body is `{hostId}` only; token substring absent), `TestAllowExpiredEntryIs410WithReason` (hub returns `ErrPendingExpired` → 410, body says `expired`), `TestAllowUnknownFingerprintIs404`, `TestDenyThenListNoLongerShowsEntry`, `TestPendingPanelShowsFingerprintHostOSIPAndMatchInstruction` (page text contains the fingerprint, host name, OS, source IP and the match sentence), `TestPendingPanelRenderedEmptyWhenQueueEmpty`, `TestCSRFTokenRotatesPerSession`.
- [ ] **Step 2: Run `go test ./internal/web`; expect FAIL.**
- [ ] **Step 3: Implement** with `net/http` and `embed`; one page, accounts and hosts tables, a swap form per host, a Pending connections panel, session cookie plus CSRF over TLS.
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

- [ ] **Step 1: Sandbox run.** Start the server on the Windows desktop with a temp data dir and test key. Enrol three agents against temp `CLAUDE_CONFIG_DIR` folders: Windows, WSL, and the Linux laptop (cross-compiled with `GOOS=linux go build`). Enrol two through the Pending connections panel (confirm the fingerprint on the agent console matches the UI before clicking Allow) and one with a one-time code. Deny a fourth throwaway agent and confirm its re-dial is not listed. Use two fake credential blocks with future `refreshTokenExpiresAt`.
- [ ] **Step 2: Verify** swap A→B on each host: `mcpOAuth` byte-identical, backup exists, sessions show "needs reload", usage panel shows an error state for fake tokens without breaking the page.
- [ ] **Step 3: Failure drills.** Kill the agent mid-swap (journal restores), stop the server (agent reconnects with backoff), supply a wrong vault key (server refuses to start, file untouched).
- [ ] **Step 4: Real hosts.** With Matthew present, swap one real account on one real host. Confirm Claude Code starts, then swap back. Record results, not secrets.
- [ ] **Step 5: Commit** `docs: e2e results`.

---

## Self-review

- **Spec coverage:** transport (T7, T8), swap and backup (T2, T8), usage (T6), vault (T3), ownership incl. shared (T4), hosts/sessions and badge (T5, T7, T9), enrolment by approval and TLS (T1 proto types, T7 queue, T8 agent, T9 panel; spec Decision 13), optional one-time code (T7, T8), allowlist logging (T1; spec Decision 12), import fallback (T9), service (T10), v1-done check (T11), spike and Linux findings (T0). The spec's "UI notes MCP logins may differ" is `TestMcpOAuthNoticeShownInUI`.
- **Types checked:** `proto.Session`, `proto.Hello`/`Pending`/`Approved`/`Denied`, `proto.Fingerprint`, `hub.PendingView`, `vault.Account`, `ownership.Registry` and `credfile` signatures match every consumer above.
- **Proportion:** plan is signatures, test names and assertions only; no function bodies.
