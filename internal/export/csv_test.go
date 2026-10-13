package export

import (
	"bytes"
	"encoding/csv"
	"testing"
	"time"

	"portscanner/internal/scan"
)

func TestToCSV_Basic(t *testing.T) {
	report := Report{
		Target:     "scanme.nmap.org",
		TotalPorts: 1000,
		Timestamp:  time.Unix(1781035393, 0),
		Results: []scan.Result{
			{Port: 22, IsOpen: true, Banner: "SSH-2.0", OS: "Linux"},
		},
	}

	rows := parseCSV(t, report)

	if len(rows) != 2 {
		t.Fatalf("rows: got %d, want 2", len(rows))
	}
	if rows[0][3] != "Port" {
		t.Errorf("header[3]: got %q, want Port", rows[0][3])
	}
	if rows[1][3] != "22" {
		t.Errorf("port: got %q, want 22", rows[1][3])
	}
}

// parseCSV runs ToCSV and parses the result, failing the test on any error.
func parseCSV(t *testing.T, r Report) [][]string {
	t.Helper()
	data, err := ToCSV(r)
	if err != nil {
		t.Fatalf("ToCSV: %v", err)
	}
	rows, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil {
		t.Fatalf("invalid CSV: %v\n%s", err, data)
	}
	return rows
}

func TestToCSV_EscapesComma(t *testing.T) {
	report := Report{
		Results: []scan.Result{
			{Port: 80, Banner: "HTTP/1.1 200 OK, text/html"},
		},
	}

	rows := parseCSV(t, report)

	if len(rows[1]) != 6 {
		t.Fatalf("comma broke CSV: got %d columns: %v", len(rows[1]), rows[1])
	}
	if rows[1][4] != "HTTP/1.1 200 OK, text/html" {
		t.Errorf("banner: got %q", rows[1][4])
	}
}

func TestToCSV_ReplacesNewlines(t *testing.T) {
	report := Report{
		Results: []scan.Result{
			{Banner: "line1\nline2\r\nline3"},
		},
	}

	rows := parseCSV(t, report)

	if got := rows[1][4]; got != "line1 line2 line3" {
		t.Errorf("banner: got %q, want %q", got, "line1 line2 line3")
	}
}

func TestToCSV_EmptyResults(t *testing.T) {
	report := Report{
		Results: []scan.Result{},
	}

	rows := parseCSV(t, report)

	if len(rows) != 1 {
		t.Fatalf("expected header only, got %d rows", len(rows))
	}
}
