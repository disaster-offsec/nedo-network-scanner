package cli

import "testing"

func TestParse_Basic(t *testing.T) {
	cfg, err := Parse([]string{"--target", "example.com", "--ports", "22,80"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scan.Target != "example.com" {
		t.Errorf("target: %q", cfg.Scan.Target)
	}
	if len(cfg.Scan.Ports) != 2 {
		t.Errorf("ports: %v", cfg.Scan.Ports)
	}
}

func TestParse_ShortFlags(t *testing.T) {
	cfg, err := Parse([]string{"-t", "example.com", "-p", "80"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scan.Target != "example.com" {
		t.Errorf("target: %q", cfg.Scan.Target)
	}
	if len(cfg.Scan.Ports) != 1 || cfg.Scan.Ports[0] != 80 {
		t.Errorf("ports: %v", cfg.Scan.Ports)
	}
}

func TestParse_Defaults(t *testing.T) {
	cfg, err := Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scan.Target != "127.0.0.1" {
		t.Errorf("default target: %q", cfg.Scan.Target)
	}
	if cfg.Scan.Timeout.Seconds() != 2 {
		t.Errorf("default timeout: %v", cfg.Scan.Timeout)
	}
	if cfg.Format != "text" {
		t.Errorf("default format: %q", cfg.Format)
	}
	if cfg.Output != "" {
		t.Errorf("default output: %q", cfg.Output)
	}
}

func TestParse_InvalidPorts(t *testing.T) {
	_, err := Parse([]string{"-p", "abc"})
	if err == nil {
		t.Fatal("expected error for invalid ports")
	}
}

func TestParse_OutputFormat(t *testing.T) {
	cfg, err := Parse([]string{"--output", "out.json", "--format", "json"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Output != "out.json" {
		t.Errorf("output: %q", cfg.Output)
	}
	if cfg.Format != "json" {
		t.Errorf("format: %q", cfg.Format)
	}
}
