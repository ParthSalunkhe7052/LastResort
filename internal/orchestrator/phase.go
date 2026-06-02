package orchestrator

import (
	scanv1 "github.com/parth/lastresort/internal/gen/scan/v1"
)

// Module names
const (
	ModuleRecon          = "recon"
	ModuleCrawlStatic    = "crawl_static"
	ModulePassive        = "passive"
	ModuleHeaders        = "headers"
	ModuleCors           = "cors"
	ModuleXssReflected   = "xss_reflected"
	ModuleSqliBasic      = "sqli_basic"
	ModuleCsrfBasic      = "csrf_basic"
	ModuleRateLimitBasic = "rate_limit_basic"
	ModuleAiHypotheses   = "ai_hypotheses"
	ModuleReport         = "report"
)

// ProfileModules maps each ScanProfile to its list of enabled modules.
var ProfileModules = map[scanv1.ScanProfile][]string{
	scanv1.ScanProfile_SCAN_PROFILE_QUICK: {
		ModuleRecon,
		ModuleCrawlStatic,
		ModulePassive,
		ModuleHeaders,
		ModuleCors,
		ModuleReport,
	},
	scanv1.ScanProfile_SCAN_PROFILE_STANDARD: {
		ModuleRecon,
		ModuleCrawlStatic,
		ModulePassive,
		ModuleHeaders,
		ModuleCors,
		ModuleXssReflected,
		ModuleSqliBasic,
		ModuleCsrfBasic,
		ModuleAiHypotheses,
		ModuleReport,
	},
	scanv1.ScanProfile_SCAN_PROFILE_DEEP: {
		ModuleRecon,
		ModuleCrawlStatic,
		ModulePassive,
		ModuleHeaders,
		ModuleCors,
		ModuleXssReflected,
		ModuleSqliBasic,
		ModuleCsrfBasic,
		ModuleAiHypotheses,
		ModuleRateLimitBasic,
		ModuleReport,
	},
}

// ModuleProgressWeights returns the relative weight of each module for progress calculation.
func GetModuleWeights(modules []string) map[string]float64 {
	weights := make(map[string]float64)
	if len(modules) == 0 {
		return weights
	}
	unit := 1.0 / float64(len(modules))
	for _, m := range modules {
		weights[m] = unit
	}
	return weights
}
