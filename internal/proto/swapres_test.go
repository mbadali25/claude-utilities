package proto

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"claude-utilities/internal/logx"
)

func TestSwapResRedactsReasonWhenLogged(t *testing.T) {
	r := SwapRes{Reason: "no such account me@example.com"}
	var buf bytes.Buffer
	logx.New(&buf).Info("swap", "res", r)
	out := buf.String() + fmt.Sprintf("%v %+v %#v", r, r, r)
	if strings.Contains(out, "me@example.com") {
		t.Fatalf("leaked email: %s", out)
	}
}
