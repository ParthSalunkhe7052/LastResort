package attack

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParsersWithFixtures(t *testing.T) {
	fixtureDir := filepath.Join("..", "..", "test_data", "fixtures", "tool_outputs")

	t.Run("Nuclei", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join(fixtureDir, "nuclei.jsonl"))
		if err != nil {
			t.Fatalf("failed to read fixture: %v", err)
		}
		findings := parseNucleiOutput(data)
		if len(findings) != 2 {
			t.Errorf("expected 2 findings, got %d", len(findings))
		}
		if findings[1].Severity != "HIGH" { // critical is mapped to HIGH in tools.go
			t.Errorf("expected HIGH severity for critical finding, got %s", findings[1].Severity)
		}
	})

	t.Run("NucleiManual", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join(fixtureDir, "nuclei.jsonl"))
		if err != nil {
			t.Fatalf("failed to read fixture: %v", err)
		}
		findings := parseNucleiManualOutput(data, "v3.0.0")
		if len(findings) != 2 {
			t.Errorf("expected 2 findings, got %d", len(findings))
		}
		if findings[1].Severity != "CRITICAL" { // manual keeps original severity
			t.Errorf("expected CRITICAL severity, got %s", findings[1].Severity)
		}
	})

	t.Run("HTTPx", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join(fixtureDir, "httpx.jsonl"))
		if err != nil {
			t.Fatalf("failed to read fixture: %v", err)
		}
		findings := parseHTTPxOutput(data, "v1.3.0")
		// 1 server finding + 2 tech findings = 3
		if len(findings) != 3 {
			t.Errorf("expected 3 findings, got %d", len(findings))
		}
	})

	t.Run("Dalfox", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join(fixtureDir, "dalfox.json"))
		if err != nil {
			t.Fatalf("failed to read fixture: %v", err)
		}
		findings := parseDalfoxOutput(data, "https://example.com")
		if len(findings) != 1 {
			t.Errorf("expected 1 finding, got %d", len(findings))
		}
	})

	t.Run("Wapiti", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join(fixtureDir, "wapiti.json"))
		if err != nil {
			t.Fatalf("failed to read fixture: %v", err)
		}
		findings := parseWapitiOutput(data, "https://example.com")
		if len(findings) != 1 {
			t.Errorf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].Severity != "CRITICAL" {
			t.Errorf("expected CRITICAL for sql_injection, got %s", findings[0].Severity)
		}
	})

	t.Run("Corsy", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join(fixtureDir, "corsy.json"))
		if err != nil {
			t.Fatalf("failed to read fixture: %v", err)
		}
		findings := parseCorsyOutput(data, "https://example.com")
		if len(findings) != 1 {
			t.Errorf("expected 1 finding, got %d", len(findings))
		}
	})

	t.Run("Nikto", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join(fixtureDir, "nikto.json"))
		if err != nil {
			t.Fatalf("failed to read fixture: %v", err)
		}
		findings := parseNiktoOutput(data, "https://example.com")
		if len(findings) != 1 {
			t.Errorf("expected 1 finding, got %d", len(findings))
		}
	})

	t.Run("SSLyze", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join(fixtureDir, "sslyze.json"))
		if err != nil {
			t.Fatalf("failed to read fixture: %v", err)
		}
		findings := parseSSLyzeOutput(data, "https://example.com")
		// Heartbleed + Deprecated TLS = 2
		if len(findings) != 2 {
			t.Errorf("expected 2 findings, got %d", len(findings))
		}
	})

	t.Run("WhatWeb", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join(fixtureDir, "whatweb.json"))
		if err != nil {
			t.Fatalf("failed to read fixture: %v", err)
		}
		findings := parseWhatWebOutput(data, "v0.5.5", "https://example.com")
		if len(findings) != 1 {
			t.Errorf("expected 1 finding, got %d", len(findings))
		}
	})
}
