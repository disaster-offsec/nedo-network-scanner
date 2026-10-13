package export

import (
	"strings"
	"testing"
	"time"

	"portscanner/internal/scan"
)

func renderTXT(t *testing.T, r Report) string {
	t.Helper()
	data, err := ToTXT(r)
	if err != nil {
		t.Fatalf("ToTXT: %v", err)
	}
	return string(data)
}

func TestToTXT_Basic(t *testing.T) {
	out := renderTXT(t, Report{
		Target:     "scanme.nmap.org",
		TotalPorts: 1000,
		Timestamp:  time.Unix(1781035393, 0),
		Results: []scan.Result{
			{Port: 22, Banner: "SSH-2.0", OS: "Linux"},
		},
	})

	for _, want := range []string{
		"=== Scan Configuration ===",
		"Target: scanme.nmap.org",
		"Total ports scanned: 1000",
		"Timestamp: 1781035393",
		"=== Open Ports ===",
		"Port: 22 is OPEN",
		"(banner: SSH-2.0)",
		"[OS: Linux]",
		"Scan completed. 1/1000 ports open.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestToTXT_EmptyResults(t *testing.T) {
	out := renderTXT(t, Report{
		Target:     "example.com",
		TotalPorts: 0,
		Timestamp:  time.Unix(1700000000, 0),
		Results:    []scan.Result{},
	})

	if !strings.Contains(out, "No open ports found.") {
		t.Errorf("missing empty message:\n%s", out)
	}
}

func TestToTXT_ReplacesNewlines(t *testing.T) {
	out := renderTXT(t, Report{
		Results: []scan.Result{
			{Port: 80, Banner: "line1\nline2", OS: "Linux"},
		},
	})

	if !strings.Contains(out, "line1 line2") {
		t.Errorf("newlines not replaced:\n%s", out)
	}
	if strings.Contains(out, "line1\nline2") {
		t.Errorf("raw newlines leaked into output:\n%s", out)
	}
}

func TestToTXT_SkipsUnknownOS(t *testing.T) {
	out := renderTXT(t, Report{
		Results: []scan.Result{
			{Port: 22, Banner: "SSH", OS: "Unknown"},
		},
	})

	if strings.Contains(out, "[OS:") {
		t.Errorf("Unknown OS should be skipped:\n%s", out)
	}
}

func TestToTXT_SkipsEmptyBanner(t *testing.T) {
	out := renderTXT(t, Report{
		Results: []scan.Result{
			{Port: 22, Banner: "", OS: "Linux"},
		},
	})

	if strings.Contains(out, "(banner:") {
		t.Errorf("empty banner should be skipped:\n%s", out)
	}
}

func TestToTXT_TruncatesLongBanner(t *testing.T) {
	long := strings.Repeat("A", 150)
	out := renderTXT(t, Report{
		Results: []scan.Result{
			{Port: 80, Banner: long, OS: "Linux"},
		},
	})

	if !strings.Contains(out, "...") {
		t.Errorf("long banner not truncated:\n%s", out)
	}
	if strings.Contains(out, long) {
		t.Errorf("full long banner should not appear:\n%s", out)
	}
}
