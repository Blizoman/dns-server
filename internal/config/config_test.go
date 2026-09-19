package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempFile(t *testing.T, name, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	return path
}

func TestLoad_YAML(t *testing.T) {
	path := writeTempFile(t, "config.yaml", `
listen: "127.0.0.1:8053"
default_ttl: 60
records:
  - domain: "example.local"
    ip: "10.0.0.50"
  - domain: "Test.Local."
    ip: "10.0.0.99"
    ttl: 120
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Listen != "127.0.0.1:8053" {
		t.Errorf("Listen = %q, want %q", cfg.Listen, "127.0.0.1:8053")
	}
	if len(cfg.Records) != 2 {
		t.Fatalf("len(Records) = %d, want 2", len(cfg.Records))
	}

	lookup := cfg.Lookup()
	// Domain must be normalized: lower-cased with trailing dot stripped.
	rec, ok := lookup["test.local"]
	if !ok {
		t.Fatalf("lookup missing normalized domain %q; got %v", "test.local", lookup)
	}
	if rec.TTL != 120 {
		t.Errorf("TTL = %d, want 120 (explicit)", rec.TTL)
	}

	rec2, ok := lookup["example.local"]
	if !ok {
		t.Fatalf("lookup missing domain %q", "example.local")
	}
	if rec2.TTL != 60 {
		t.Errorf("TTL = %d, want 60 (default)", rec2.TTL)
	}
}

func TestLoad_JSON(t *testing.T) {
	path := writeTempFile(t, "config.json", `{
		"listen": "0.0.0.0:9000",
		"records": [
			{"domain": "json.local", "ip": "1.2.3.4"}
		]
	}`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Listen != "0.0.0.0:9000" {
		t.Errorf("Listen = %q, want %q", cfg.Listen, "0.0.0.0:9000")
	}
	if cfg.DefaultTTL != DefaultTTL {
		t.Errorf("DefaultTTL = %d, want default %d", cfg.DefaultTTL, DefaultTTL)
	}
	lookup := cfg.Lookup()
	if _, ok := lookup["json.local"]; !ok {
		t.Fatalf("lookup missing domain %q", "json.local")
	}
}

func TestLoad_InvalidIP(t *testing.T) {
	path := writeTempFile(t, "config.yaml", `
records:
  - domain: "bad.local"
    ip: "not-an-ip"
`)

	if _, err := Load(path); err == nil {
		t.Fatalf("expected error for invalid IP, got nil")
	}
}

func TestLoad_NoRecords(t *testing.T) {
	path := writeTempFile(t, "config.yaml", `listen: "127.0.0.1:8053"`)

	if _, err := Load(path); err == nil {
		t.Fatalf("expected error for missing records, got nil")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	if _, err := Load("/nonexistent/path/config.yaml"); err == nil {
		t.Fatalf("expected error for missing file, got nil")
	}
}

func TestLoad_RejectsIPv6(t *testing.T) {
	path := writeTempFile(t, "config.yaml", `
records:
  - domain: "v6.local"
    ip: "::1"
`)

	if _, err := Load(path); err == nil {
		t.Fatalf("expected error for IPv6 address, got nil")
	}
}
