package web

import (
	"net/http"
	"strings"
	"testing"
)

// The site icons are the only routes outside /api/ that answer without a session: the login page
// carries them too, so a signed-out browser must be able to fetch them.
func TestIconsServeWithoutASession(t *testing.T) {
	for _, tc := range []struct{ path, ctype, sniff string }{
		{"/favicon.svg", "image/svg+xml", "<svg"},
		{"/apple-touch-icon.png", "image/png", "\x89PNG"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			r := newRig(t)
			w := r.do(http.MethodGet, tc.path, "", nil, "")
			if w.Code != http.StatusOK {
				t.Fatalf("status %d, want 200", w.Code)
			}
			if got := w.Header().Get("Content-Type"); got != tc.ctype {
				t.Errorf("Content-Type %q, want %q", got, tc.ctype)
			}
			if got := w.Header().Get("Cache-Control"); got != "public, max-age=86400" {
				t.Errorf("Cache-Control %q, want a cacheable value", got)
			}
			if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options %q, want nosniff", got)
			}
			if body := w.Body.String(); !strings.HasPrefix(body, tc.sniff) {
				t.Errorf("body does not start with %q (%d bytes)", tc.sniff, len(body))
			}
		})
	}
}

// The SVG carries both themes itself, because a favicon gets no stylesheet from the page.
func TestFaviconCarriesBothThemes(t *testing.T) {
	r := newRig(t)
	body := r.do(http.MethodGet, "/favicon.svg", "", nil, "").Body.String()
	for _, want := range []string{"prefers-color-scheme: dark", "#2447b8", "#8fabf6"} {
		if !strings.Contains(body, want) {
			t.Errorf("favicon.svg is missing %q", want)
		}
	}
}

// img-src is the only directive the icons added. Everything else, the per-render nonce above all,
// stays exactly as it was; a loosened script-src or style-src here would be the real regression.
func TestCSPAllowsOwnImagesOnly(t *testing.T) {
	r := newRig(t)
	csp := r.do(http.MethodGet, "/", "", nil, "").Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "img-src 'self'", "script-src 'nonce-",
		"style-src 'nonce-", "connect-src 'self'", "base-uri 'none'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP is missing %q: %s", want, csp)
		}
	}
	for _, unwanted := range []string{"unsafe-inline", "unsafe-eval", "img-src *", "data:", "https:"} {
		if strings.Contains(csp, unwanted) {
			t.Errorf("CSP has been loosened with %q: %s", unwanted, csp)
		}
	}
}

// Both pages declare the icons, and each says in its title which one it is.
func TestPageHeadDeclaresIconsAndTitle(t *testing.T) {
	links := []string{
		`<link rel="icon" type="image/svg+xml" href="/favicon.svg">`,
		`<link rel="apple-touch-icon" href="/apple-touch-icon.png">`,
		`<meta name="theme-color" content="#f4f5f7" media="(prefers-color-scheme: light)">`,
		`<meta name="theme-color" content="#101114" media="(prefers-color-scheme: dark)">`,
	}
	r := newRig(t)
	signedOut := r.do(http.MethodGet, "/", "", nil, "").Body.String()
	signedIn := page(r, r.login())

	for _, body := range []struct {
		name, html, title string
	}{
		{"login", signedOut, "<title>Sign in - claude-swap</title>"},
		{"main", signedIn, "<title>claude-swap - Claude Code logins on this network</title>"},
	} {
		for _, want := range append(links, body.title) {
			if !strings.Contains(body.html, want) {
				t.Errorf("%s page is missing %s", body.name, want)
			}
		}
	}

	// The mark sits beside the app name on both pages, and is decorative: the name is the label.
	for _, body := range []struct{ name, html string }{{"login", signedOut}, {"main", signedIn}} {
		if !strings.Contains(body.html, `<svg viewBox="0 0 32 32" aria-hidden="true"><rect class="t"`) {
			t.Errorf("%s page has no decorative swap mark in its header", body.name)
		}
	}
}
