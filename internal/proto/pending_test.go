package proto

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestFingerprintIsDeterministicAnd8Chars(t *testing.T) {
	h := Hello{HostName: "box", OS: "linux", Nonce: "n1"}
	a, b := Fingerprint(h), Fingerprint(h)
	if a != b || len(a) != 8 || a != strings.ToLower(a) {
		t.Fatalf("bad fingerprint %q %q", a, b)
	}
}

func TestFingerprintChangesWithNonce(t *testing.T) {
	a := Fingerprint(Hello{HostName: "box", OS: "linux", Nonce: "n1"})
	b := Fingerprint(Hello{HostName: "box", OS: "linux", Nonce: "n2"})
	if a == b {
		t.Fatal("nonce must change the fingerprint")
	}
}

func TestApprovedAndHelloCodeNeverPrint(t *testing.T) {
	out := fmt.Sprintf("%v %+v %#v %v", Approved{Token: "TOPSECRET"}, Hello{Token: "TOPSECRET", Code: "CODESECRET"},
		Approved{Token: "TOPSECRET"}, slog.Any("x", Hello{Code: "CODESECRET"}).Value.Resolve())
	if strings.Contains(out, "TOPSECRET") || strings.Contains(out, "CODESECRET") {
		t.Fatalf("secret printed: %s", out)
	}
}

func TestPendingAndDeniedCarryNoToken(t *testing.T) {
	for _, body := range []any{Pending{Fingerprint: "abcdefgh"}, Denied{Reason: "no"}} {
		b, err := Encode(TypePending, "", body)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.ToLower(string(b)), "token") {
			t.Fatalf("token field in %s", b)
		}
	}
}
