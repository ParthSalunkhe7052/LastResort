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
	ModuleCsrfBasic      = "csrf_basic"
	ModuleRateLimitBasic = "rate_limit_basic"
	ModulePathTraversal  = "path_traversal"
	ModuleAuthDiscovery  = "auth_discovery"
	ModuleNuclei         = "nuclei"
	ModuleVisualExploit  = "visual_exploit"
	ModuleReport         = "report"
	ModuleSqliAgent      = "sqli_agent"
)

// ProfileModules maps each ScanProfile to its list of enabled modules.
var ProfileModules = map[scanv1.ScanProfile][]string{
	scanv1.ScanProfile_SCAN_PROFILE_QUICK: {
		ModuleRecon,
		ModuleCrawlStatic,
		ModulePassive,
		ModuleHeaders,
		ModuleCors,
		ModuleVisualExploit,
		ModuleReport,
	},
	scanv1.ScanProfile_SCAN_PROFILE_STANDARD: {
		ModuleRecon,
		ModuleAuthDiscovery,
		ModuleCrawlStatic,
		ModulePassive,
		ModuleHeaders,
		ModuleCors,
		ModuleXssReflected,
		ModuleSqliAgent,
		ModuleCsrfBasic,
		ModulePathTraversal,
		ModuleNuclei,
		ModuleVisualExploit,
		ModuleReport,
	},
	scanv1.ScanProfile_SCAN_PROFILE_DEEP: {
		ModuleRecon,
		ModuleAuthDiscovery,
		ModuleCrawlStatic,
		ModulePassive,
		ModuleHeaders,
		ModuleCors,
		ModuleXssReflected,
		ModuleSqliAgent,
		ModuleCsrfBasic,
		ModuleRateLimitBasic,
		ModulePathTraversal,
		ModuleNuclei,
		ModuleVisualExploit,
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
