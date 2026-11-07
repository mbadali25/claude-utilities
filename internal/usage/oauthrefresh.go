package usage

// OAuthRefresher renews a stored claudeAiOauth block through the OAuth token endpoint. It is only
// wired when the operator passes --refresh-tokens, and only ever for accounts no host holds: a
// refresh may rotate the refresh token, so the server stays conservative and leaves a login a host is using to that host (a sign-out from this is unproven, not observed).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultOAuthEndpoint is the OAuth token endpoint.
const DefaultOAuthEndpoint = "https://platform.claude.com/v1/oauth/token"

// DefaultClientID is the OAuth client id sent with a refresh.
// provisional, pending confirmation
const DefaultClientID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"

const (
	refreshTimeout   = 30 * time.Second
	maxRefreshReply  = 1 << 20
	refreshGrantType = "refresh_token"
)

// OAuthRefresher implements Refresher. The zero value is not usable; use NewOAuthRefresher.
type OAuthRefresher struct {
	URL      string
	ClientID string
	HTTP     Doer
	Now      func() time.Time
}

// NewOAuthRefresher returns a refresher with the default endpoint, client id and a 30 s timeout.
func NewOAuthRefresher() *OAuthRefresher {
	return &OAuthRefresher{
		URL:      DefaultOAuthEndpoint,
		ClientID: DefaultClientID,
		HTTP:     &http.Client{Timeout: refreshTimeout},
		Now:      time.Now,
	}
}

type tokenReply struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshExpiresIn int64  `json:"refresh_token_expires_in"`
	Scope            string `json:"scope"`
}

// Refresh exchanges the block's refresh token and returns the block with the new tokens merged in.
// Fields it does not know are kept as they were. Errors never carry the response body, a token or
// the transport error's text.
func (r *OAuthRefresher) Refresh(ctx context.Context, block json.RawMessage) (json.RawMessage, error) {
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(block, &fields); err != nil {
		return nil, errors.New("oauth refresh: block is not a JSON object")
	}
	var oldRefresh string
	_ = json.Unmarshal(fields["refreshToken"], &oldRefresh)
	if oldRefresh == "" {
		return nil, errors.New("oauth refresh: block has no refresh token")
	}
	var scopes []string
	_ = json.Unmarshal(fields["scopes"], &scopes)

	body, err := json.Marshal(map[string]string{
		"grant_type":    refreshGrantType,
		"refresh_token": oldRefresh,
		"client_id":     r.ClientID,
		"scope":         strings.Join(scopes, " "),
	})
	if err != nil {
		return nil, errors.New("oauth refresh: encode request")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.URL, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("oauth refresh: build request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return nil, errors.New("oauth refresh: request failed") // the transport error can quote the URL
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxRefreshReply))
		return nil, fmt.Errorf("oauth refresh: status %d", resp.StatusCode)
	}
	var tr tokenReply
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRefreshReply)).Decode(&tr); err != nil {
		return nil, errors.New("oauth refresh: unreadable response")
	}
	if tr.AccessToken == "" || tr.ExpiresIn <= 0 {
		return nil, errors.New("oauth refresh: response lacks access_token or expires_in")
	}

	now := r.Now()
	set := func(k string, v any) {
		b, _ := json.Marshal(v) // strings and ints cannot fail
		fields[k] = b
	}
	set("accessToken", tr.AccessToken)
	if tr.RefreshToken != "" {
		set("refreshToken", tr.RefreshToken)
	}
	set("expiresAt", now.Add(time.Duration(tr.ExpiresIn)*time.Second).UnixMilli())
	if tr.RefreshExpiresIn > 0 {
		set("refreshTokenExpiresAt", now.Add(time.Duration(tr.RefreshExpiresIn)*time.Second).UnixMilli())
	}
	if tr.Scope != "" {
		set("scopes", strings.Fields(tr.Scope))
	}
	return json.Marshal(fields)
}
