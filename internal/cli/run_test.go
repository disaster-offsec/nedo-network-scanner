package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun_InvalidArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-p", "abc"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("code: got %d, want 1", code)
	}
	if stderr.Len() == 0 {
		t.Error("expected error output")
	}
}

func TestRun_InvalidFormat(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-f", "xml", "-p", "80", "-t", "127.0.0.1"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("code: got %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "unknown format") {
		t.Errorf("stderr: %q", stderr.String())
	}
}
