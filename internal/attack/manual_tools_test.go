package attack

import (
	"context"
	"testing"
)

func TestToolProbes(t *testing.T) {
	ctx := context.Background()

	t.Run("httpxProbe", func(t *testing.T) {
		probe := &httpxProbe{baseProbe{binary: "httpx"}}
		ok, info := probe.Check(ctx)
		// On this machine, httpx is the Python version, so it should be false
		if ok {
			t.Errorf("httpxProbe should have failed on Python httpx, but got ok=true, info=%s", info)
		} else {
			t.Logf("httpxProbe correctly failed: %s", info)
		}
	})

	t.Run("nucleiProbe", func(t *testing.T) {
		probe := &nucleiProbe{baseProbe{binary: "nuclei"}}
		ok, info := probe.Check(ctx)
		if !ok {
			t.Errorf("nucleiProbe should have succeeded, but failed: %s", info)
		} else {
			t.Logf("nucleiProbe version: %s", info)
		}
	})

	t.Run("dalfoxProbe", func(t *testing.T) {
		probe := &dalfoxProbe{baseProbe{binary: "dalfox"}}
		ok, info := probe.Check(ctx)
		if !ok {
			t.Errorf("dalfoxProbe should have succeeded, but failed: %s", info)
		} else {
			t.Logf("dalfoxProbe version: %s", info)
		}
	})

	t.Run("whatwebProbe", func(t *testing.T) {
		probe := &whatwebProbe{baseProbe{binary: "whatweb"}}
		ok, info := probe.Check(ctx)
		if ok {
			t.Errorf("whatwebProbe should have failed (missing), but succeeded: %s", info)
		} else {
			t.Logf("whatwebProbe correctly failed: %s", info)
		}
	})
}

func TestCheckAllToolAvailability(t *testing.T) {
	results := CheckAllToolAvailability()
	foundHTTPx := false
	for _, res := range results {
		if res.Name == "httpx" {
			foundHTTPx = true
			if res.Available {
				t.Errorf("httpx should be reported as unavailable (Python version), but got Available=true")
			}
			t.Logf("httpx status: Available=%v, Version=%s", res.Available, res.Version)
		}
	}
	if !foundHTTPx {
		t.Errorf("httpx not found in CheckAllToolAvailability results")
	}
}

func TestParsers(t *testing.T) {
	t.Run("parseHTTPxOutput", func(t *testing.T) {
		data := []byte("{\"url\":\"https://example.com\",\"status_code\":200,\"title\":\"Example Domain\",\"webserver\":\"Apache\",\"tech\":[\"PHP\",\"MySQL\"],\"content_length\":1256}\n")
		findings := parseHTTPxOutput(data, "v2.5.0")
		if len(findings) != 3 { // 1 server + 2 tech
			t.Errorf("Expected 3 findings, got %d", len(findings))
		}
		if findings[0].Tool != "httpx" || findings[0].Category != "Technology Detection" {
			t.Errorf("Unexpected finding[0]: %+v", findings[0])
		}
	})

	t.Run("parseNucleiManualOutput", func(t *testing.T) {
		data := []byte("{\"template-id\":\"exposed-git\",\"info\":{\"name\":\"Exposed Git Repository\",\"severity\":\"high\",\"description\":\"Git repo found\"},\"type\":\"http\",\"host\":\"https://example.com\",\"matched-at\":\"https://example.com/.git/\"}\n")
		findings := parseNucleiManualOutput(data, "v3.1.0")
		if len(findings) != 1 {
			t.Errorf("Expected 1 finding, got %d", len(findings))
		}
		if findings[0].Severity != "HIGH" || findings[0].Category != "Critical Vulnerability" {
			t.Errorf("Unexpected finding[0]: %+v", findings[0])
		}
	})

	t.Run("parseWapitiOutput", func(t *testing.T) {
		data := []byte("{\"vulnerabilities\":{\"sql_injection\":[{\"method\":\"GET\",\"info\":\"SQLi found\",\"path\":\"/index.php\",\"parameter\":\"id\"}]}}\n")
		findings := parseWapitiOutput(data, "https://example.com")
		if len(findings) != 1 {
			t.Errorf("Expected 1 finding, got %d", len(findings))
		}
		if findings[0].Severity != "CRITICAL" || findings[0].Category != "SQL Injection" {
			t.Errorf("Unexpected finding[0]: %+v", findings[0])
		}
	})
}
