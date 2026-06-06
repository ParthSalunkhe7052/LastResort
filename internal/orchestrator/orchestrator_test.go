package orchestrator

import (
	"testing"

	scanv1 "github.com/parth/lastresort/internal/gen/scan/v1"
)

func TestProfileModuleSelection(t *testing.T) {
	// 1. Verify QUICK profile maps to correct modules
	quickMods := ProfileModules[scanv1.ScanProfile_SCAN_PROFILE_QUICK]
	if len(quickMods) != 7 {
		t.Errorf("expected 7 modules for QUICK profile, got %d", len(quickMods))
	}

	// 2. Verify STANDARD profile maps to correct modules
	stdMods := ProfileModules[scanv1.ScanProfile_SCAN_PROFILE_STANDARD]
	if len(stdMods) != 13 {
		t.Errorf("expected 13 modules for STANDARD profile, got %d", len(stdMods))
	}

	// 3. Verify DEEP profile maps to correct modules
	deepMods := ProfileModules[scanv1.ScanProfile_SCAN_PROFILE_DEEP]
	if len(deepMods) != 14 {
		t.Errorf("expected 14 modules for DEEP profile, got %d", len(deepMods))
	}
}
