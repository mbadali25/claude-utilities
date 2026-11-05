package proto

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"claude-utilities/internal/logx"
)

// Add-account messages. The envelope ID is the job id; every one needs a non-empty ID.
const (
	TypeLoginStart  = "login_start"
	TypeLoginURL    = "login_url"
	TypeLoginCode   = "login_code"
	TypeLoginDone   = "login_done"
	TypeLoginCancel = "login_cancel"
)

// MaxLoginURL bounds a sign-in URL (bytes).
const MaxLoginURL = 4096

// LoginStart (hub to agent) asks the agent to run `claude auth login` in a throwaway config dir.
type LoginStart struct{}

// LoginURL (agent to hub) carries Anthropic's sign-in URL. The URL holds PKCE state: never log it.
type LoginURL struct {
	URL string `json:"url"`
}

// LoginCode (hub to agent) carries the one-time code the owner copied from Anthropic's page.
type LoginCode struct {
	Code string `json:"code"`
}

// LoginDone (agent to hub) ends a job: a login block plus identity, or an error.
type LoginDone struct {
	Block    json.RawMessage `json:"block,omitempty"`
	Identity string          `json:"identity,omitempty"`
	// Err goes on the wire as-is: callers must logx.Redact it before setting.
	Err string `json:"err,omitempty"`
}

func (l LoginURL) String() string   { return "LoginURL{URL:" + mask + "}" }
func (l LoginURL) GoString() string { return l.String() }
func (l LoginURL) LogValue() slog.Value {
	return slog.GroupValue(slog.String("url", mask))
}

func (l LoginCode) String() string   { return "LoginCode{Code:" + mask + "}" }
func (l LoginCode) GoString() string { return l.String() }
func (l LoginCode) LogValue() slog.Value {
	return slog.GroupValue(slog.String("code", mask))
}

func (l LoginDone) String() string {
	return fmt.Sprintf("LoginDone{Identity:%s Block:%s Err:%s}", mask, mask, logx.Redact(l.Err))
}
func (l LoginDone) GoString() string { return l.String() }
func (l LoginDone) LogValue() slog.Value {
	return slog.GroupValue(slog.String("identity", mask), slog.String("block", mask), slog.String("err", logx.Redact(l.Err)))
}

// ValidateLoginURL accepts only an https Anthropic authorize URL: host exactly claude.com or
// claude.ai (no port, no userinfo), path /cai/oauth/authorize or /oauth/authorize, no control or
// space bytes, at most MaxLoginURL bytes. Both the agent and the hub apply it.
func ValidateLoginURL(raw string) error {
	if raw == "" || len(raw) > MaxLoginURL {
		return errors.New("login url: empty or too long")
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] <= ' ' || raw[i] == 0x7f {
			return errors.New("login url: control or space byte")
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("login url: unparseable")
	}
	if u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return errors.New("login url: must be plain https")
	}
	if h := u.Hostname(); h != "claude.com" && h != "claude.ai" {
		return errors.New("login url: unexpected host")
	}
	if !strings.HasPrefix(u.Path, "/cai/oauth/authorize") && !strings.HasPrefix(u.Path, "/oauth/authorize") {
		return errors.New("login url: unexpected path")
	}
	return nil
}
