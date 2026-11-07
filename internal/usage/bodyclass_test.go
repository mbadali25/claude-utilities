package usage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"claude-utilities/internal/logx"
)

func TestClassifyBody(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"expired", `{"type":"error","error":{"type":"authentication_error","message":"OAuth token has expired"}}`, "token_expired"},
		{"revoked", `{"error":{"type":"authentication_error","message":"OAuth token has been revoked"}}`, "token_revoked"},
		{"invalid", `{"error":{"type":"authentication_error","message":"Invalid bearer token"}}`, "invalid_credentials"},
		{"permission", `{"error":{"type":"permission_error","message":"scope not allowed"}}`, "permission"},
		{"string error field", `{"error":"invalid_grant","error_description":"Token EXPIRED"}`, "token_expired"},
		{"unknown json", `{"error":{"type":"weird","message":"teapot"}}`, "other"},
		{"json no error fields", `{"hello":"world"}`, "other"},
		{"empty", ``, "no_body"},
		{"whitespace", "  \n", "no_body"},
		{"html", `<html>denied</html>`, "unparseable"},
		{"json array", `[1,2]`, "unparseable"},
		{"marker outside error fields is ignored", `{"debug":"expired revoked","error":{"message":"nope"}}`, "other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyBody([]byte(tc.body)); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func fetchErr(t *testing.T, code int, body string) error {
	t.Helper()
	d := fakeDoer{fn: func(*http.Request) (*http.Response, error) { return resp(code, body, nil), nil }}
	_, err := Fetch(context.Background(), &d, "tok")
	return err
}

func TestFetch401CarriesBodyClassAndKeepsSentinel(t *testing.T) {
	err := fetchErr(t, 401, `{"error":{"message":"token expired"}}`)
	if !errors.Is(err, ErrUnauthorized) || HTTPStatus(err) != 401 || BodyClass(err) != "token_expired" {
		t.Fatalf("err %v status %d class %q", err, HTTPStatus(err), BodyClass(err))
	}
	err = fetchErr(t, 403, `{"error":{"message":"token revoked"}}`)
	if !errors.Is(err, ErrUnauthorized) || BodyClass(err) != "token_revoked" {
		t.Fatalf("403: err %v class %q", err, BodyClass(err))
	}
	if BodyClass(fetchErr(t, 401, "")) != "no_body" {
		t.Fatal("empty 401 body must be no_body")
	}
}

func TestBodyClassEmptyForOtherErrors(t *testing.T) {
	for _, err := range []error{nil, errors.New("x"), ErrUnauthorized, fetchErr(t, 500, `{"error":"expired"}`), fetchErr(t, 429, "expired")} {
		if got := BodyClass(err); got != "" {
			t.Fatalf("err %v: class %q, want empty", err, got)
		}
	}
}

type countingBody struct {
	r      io.Reader
	read   int
	closed bool
}

func (c *countingBody) Read(p []byte) (int, error) { n, err := c.r.Read(p); c.read += n; return n, err }
func (c *countingBody) Close() error               { c.closed = true; return nil }

func TestFetch401BodyIsBoundedAndClosed(t *testing.T) {
	cb := &countingBody{r: strings.NewReader(`{"error":{"message":"` + strings.Repeat("a", 10<<20) + ` expired"}}`)}
	d := fakeDoer{fn: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 401, Body: cb, Header: http.Header{}}, nil
	}}
	_, err := Fetch(context.Background(), &d, "tok")
	if !errors.Is(err, ErrUnauthorized) || BodyClass(err) != "unparseable" {
		t.Fatalf("err %v class %q", err, BodyClass(err))
	}
	if cb.read > 8<<10 || !cb.closed {
		t.Fatalf("read %d bytes, closed %v", cb.read, cb.closed)
	}
}

func TestPollFailureLogsBodyClassOnly(t *testing.T) {
	const fakeTok = "sk-ant-oat01-FAKETOKENVALUE123"
	const email = "someone@example.com"
	body := `{"error":{"type":"authentication_error","message":"token expired for ` + email + ` ` + fakeTok + `"}}`
	var buf bytes.Buffer
	old := logger
	logger = logx.New(&buf)
	defer func() { logger = old }()
	d := fakeDoer{fn: func(*http.Request) (*http.Response, error) { return resp(401, body, nil), nil }}
	p, _ := newSched(&d, "a")
	p.step(context.Background(), nil)
	out := buf.String()
	if !strings.Contains(out, `"body_class":"token_expired"`) || !strings.Contains(out, `"status":401`) ||
		strings.Contains(out, "[dropped]") {
		t.Fatalf("log: %s", out)
	}
	for _, leak := range []string{fakeTok, email, "FAKETOKEN", "authentication_error", "tok-a"} {
		if strings.Contains(out, leak) {
			t.Fatalf("log leaks %q: %s", leak, out)
		}
	}
}

func TestNon401FailureLogHasNoBodyClass(t *testing.T) {
	var buf bytes.Buffer
	old := logger
	logger = logx.New(&buf)
	defer func() { logger = old }()
	d := fakeDoer{fn: func(*http.Request) (*http.Response, error) { return resp(500, `{"error":"expired"}`, nil), nil }}
	p, _ := newSched(&d, "a")
	p.step(context.Background(), nil)
	if strings.Contains(buf.String(), "body_class") && !strings.Contains(buf.String(), `"body_class":""`) {
		t.Fatalf("log: %s", buf.String())
	}
}

func TestClassifyBodyConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if BodyClass(fetchErr(t, 401, `{"error":{"message":"revoked"}}`)) != "token_revoked" {
				t.Error("wrong class")
			}
		}()
	}
	wg.Wait()
}
