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
