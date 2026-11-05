# claude-swap: Add account (plan addendum, 2026-11-05)

Spec: `docs/superpowers/specs/2026-11-05-claude-swap-add-account-addendum.md`. Adds Task 12 after Task 11's code tasks; it does not edit the approved plan. Go: `go build ./...`, `go vet ./...`, `gofmt -l .`, `go test -race ./...`. Existing patterns: `hub.Import` (internal/hub/import.go), `hub.request`/`conn.deliver` (hub.go), `agent.handle` (agent.go), `server.importLogin`/`hubError`/`authPost` (web.go).

### Task 12: Add account via `claude auth login`

**Files:**
- Modify: `internal/proto/proto.go` (types, constants), `internal/hub/hub.go` (`dispatch`, `dropConn`), `internal/agent/agent.go` (`handle`, `Run` cleanup), `internal/web/web.go` (`hubAPI`, routes, handlers), `internal/web/static/index.html` (Add account panel), `internal/hub/import.go` (extract duplicate check)
- Create: `internal/hub/addaccount.go`, `internal/hub/addaccount_test.go`, `internal/agent/login.go`, `internal/agent/login_test.go`, `internal/proto/login_test.go`

**Interfaces (exact signatures):**

proto:
```go
const (
	TypeLoginStart  = "login_start"
	TypeLoginURL    = "login_url"
	TypeLoginCode   = "login_code"
	TypeLoginDone   = "login_done"
	TypeLoginCancel = "login_cancel"
)
type LoginStart struct{}
type LoginURL struct{ URL string `json:"url"` }
type LoginCode struct{ Code string `json:"code"` }
type LoginDone struct {
	Block    json.RawMessage `json:"block,omitempty"`
	Identity string          `json:"identity,omitempty"`
	Err      string          `json:"err,omitempty"` // callers logx.Redact before setting
}
// each gets String, GoString, LogValue masking url/code/block/identity (Err via logx.Redact)
```

hub:
```go
type AddState string // "starting","awaiting_code","finishing","done","failed","cancelled"
type AddView struct {
	ID      string
	State   AddState
	URL     string        // only in awaiting_code
	Account *vault.Account // only in done; Block always nil
	Error   string
}
var ErrAddBusy = errors.New("hub: an add-account sign-in is already running")
var ErrNoAdd   = errors.New("hub: no such add-account sign-in")
var ErrNotAwaitingCode = errors.New("hub: the sign-in is not waiting for a code")
func (h *Hub) AddAccount(ctx context.Context, hostID, label string) (id string, err error)
func (h *Hub) AddStatus(id string) (AddView, error)
func (h *Hub) AddCode(id, code string) error
func (h *Hub) AddCancel(id string) error
func (h *Hub) storeLogin(hostID, label, identity string, raw json.RawMessage) (vault.Account, error) // shared with Import
```

agent:
```go
// loginRunner is the test seam for the child process.
type loginRunner interface {
	Start(ctx context.Context, configDir string) (stdout io.Reader, stdin io.WriteCloser, wait func() error, kill func(), err error)
}
func (a *agent) startLogin(ctx context.Context, s *sess, id string)
func (a *agent) loginCode(id, code string) error
func (a *agent) cancelLogin(id string)
func extractLoginURL(stdout []byte) (string, error) // strips ESC sequences incl. OSC-8, validates host/path/len
func cleanStaleLogins(stateDir string)
```

web (`hubAPI` gains `AddAccount`, `AddStatus`, `AddCode`, `AddCancel`): handlers `addAccount`, `addStatus`, `addCode`, `addCancel`; routes `POST /api/accounts/add`, `GET /api/accounts/add/{id}`, `POST /api/accounts/add/{id}/code`, `POST /api/accounts/add/{id}/cancel`. `hubError` gains `ErrAddBusy` and `ErrNotAwaitingCode` -> 409, `ErrNoAdd` -> 404.

- [ ] **Step 1: Re-run the spike gate (blocking).** On a scratch temp `CLAUDE_CONFIG_DIR` with Matthew present, run `claude auth login --claudeai` with piped stdin, sign in, write the pasted code to stdin. Record: does it exit 0, which credentials file appears, does `oauthAccount` land in `.claude.json`. If stdin paste fails, stop and ask: pty fallback (ConPTY/pty dependency, needs approval) or "run login on host + existing Import". Record results (no secrets) in `docs/superpowers/e2e-results.md`.
- [ ] **Step 2: proto tests (red).** `TestLoginTypesMaskSecrets` (fmt `%v`, `%#v`, slog output of each type contains no planted url/code/block/identity); `TestLoginDoneRoundTrip`; `TestLoginMessagesRequireID` (dispatcher helper rejects empty ID). Then add types; green.
- [ ] **Step 3: agent `extractLoginURL` tests (red).** Table: spike-shaped output with OSC-8 wrapper and duplicate URL (returns first, no control bytes); plain URL; host `evil.example` refused; `http://` refused; no URL -> error; > 4096 chars refused; truncated mid-URL (no terminator yet) -> `errNeedMore`. Implement; green.
- [ ] **Step 4: agent login flow tests with a fake `loginRunner` (red).** `TestLoginSendsURLThenDone` (fake prints prompt, accepts code, writes credentials file; agent sends `login_url` then `login_done` with block+identity, env ID echoed); `TestLoginNoURLTimesOut` (15 s via injected clock/timeout, child killed, `login_done{err}`, dir gone); `TestLoginWrongCode` (child exits 1); `TestLoginCancelKillsChildAndRemovesDir`; `TestLoginSecondStartRefused`; `TestCleanStaleLoginsRemovesStrays`; `TestLoginNeverLogsURLCodeOrBlock` (capture log, planted values absent); `TestLoginDoesNotTouchLiveCreds` (live creds file bytes unchanged). Implement `login.go` and the `handle` cases (reject empty ID like swap_req); call `cleanStaleLogins` in `Run`; green.
- [ ] **Step 5: hub tests (red).** Use the existing fake-server rig. `TestAddAccountHappyPath` (start -> url -> code -> done; vault has account with `claudeAiOauth` only; live host ownership unchanged; `h.reg` not called); `TestAddAccountDuplicateIdentity` (ErrAlreadyStored, nothing stored); `TestAddAccountBlockWithMcpOnlyRefused`; `TestAddAccountBusy` (second job -> ErrAddBusy); `TestAddAccountAgentDropFails`; `TestAddAccountJobExpiresAfter10Min` (injected `h.now`); `TestAddCodeWrongState` (ErrNotAwaitingCode); `TestAddStatusHidesURLOutsideAwaitingCode`; `TestDispatchLoginFramesNotProtocolViolation` and `TestDispatchLoginFrameEmptyIDIsViolation`; `TestAddDoesNotHoldSwapMuWhileWaiting` (a Swap on the same host proceeds during `awaiting_code`); `TestAddLogsNoSecrets`. Implement `addaccount.go`, extend `dispatch` (route `login_url`/`login_done` to the job by ID; keep the existing waiter path for export/swap), `dropConn` (fail the job), extract `storeLogin` from `Import` and make `Import` call it; run existing `import_test.go` unchanged; green.
- [ ] **Step 6: web tests (red).** Extend the existing fake `hubAPI` in `web_test.go`. `TestAddAccountRequiresSession` (401 all four, incl. wrong-method probe), `TestAddAccountPostsRequireCSRF` (403), `TestAddAccountValidatesLabel` (empty, 65 chars, duplicate label 409), `TestAddAccountMapsHubErrors`, `TestAddStatusNeverReturnsBlock`, `TestAddCodeRejectsEmptyAndOversize`, `TestAddCodeNotLogged`, `TestAddUnknownFieldsRefused`. Implement handlers and routes; green.
- [ ] **Step 7: UI.** In `index.html` add the "Add account" panel: host select, label, Start; shows link and code field when `awaiting_code`; polls every 2 s; clears the code field after submit; Cancel; text saying "sign-in is completed on Anthropic's own page". No URL or code in the query string, localStorage, or title. Extend an existing web test to assert the template contains the panel and the CSRF header on each POST.
- [ ] **Step 8: Ripple.** `Grep` `hubAPI`, `TypeExportReq`, `dispatch(`, `proto.Type` and every fake of `hubAPI` or the hub in tests; update each. Confirm `logx` `allowed` needs no new key (do not add `url` or `code`).
- [ ] **Step 9: Verify.** `go build ./...`, `GOOS=linux go build ./...`, `go vet ./...`, `gofmt -l .`, `go test -race ./...`, then `bash _verify/smoke.sh`.
- [ ] **Step 10: E2E with Matthew** (extends Task 11 step 4): add one real account on one real host through the UI; confirm the account appears unowned, the host's live login is unchanged, the temp dir is gone, and no log line contains the URL, code or tokens (grep the server and agent logs for `oauth/authorize`, `state=`, and the pasted code). Record results without secrets in `e2e-results.md`.
- [ ] **Step 11: Commit** `feat: add account via claude auth login relay` (only after Matthew approves; the approved spec/plan files stay untouched).

**Done when:** all tests above pass under `-race`, an account added through the UI is in the vault with only the `claudeAiOauth` block, the host's live credentials are byte-identical before and after, and no log contains a URL, code, block or token.
