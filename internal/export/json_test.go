package export

import (
	"encoding/json"
	"testing"
	"time"

	"portscanner/internal/scan"
)

func TestToJSON_ReturnsValidJSON(t *testing.T) {
	report := Report{
		Target:     "example.com",
		TotalPorts: 100,
		Timestamp:  time.Unix(1700000000, 0),
		Results: []scan.Result{
			{Port: 22, IsOpen: true, Banner: "SSH-2.0", OS: "Linux"},
			{Port: 80, IsOpen: true, Banner: "HTTP/1.1 200", OS: "Linux"},
		},
	}

	data, err := ToJSON(report)
	if err != nil {
		t.Fatalf("ToJSON returned error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, data)
	}
}

func TestToJSON_EscapesNewlines(t *testing.T) {
	report := Report{
		Results: []scan.Result{
			{Port: 22, IsOpen: true, Banner: "line1\nline2"},
		},
	}
	data, err := ToJSON(report)
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("banner with newline produced invalid JSON: %v", err)
	}
}
