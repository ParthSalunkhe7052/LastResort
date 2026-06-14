package attack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// NormalizedFinding is the unified schema for findings from all manual testing tools.
type NormalizedFinding struct {
	Tool            string   `json:"tool"`
	ToolVersion     string   `json:"tool_version,omitempty"`
	FindingID       string   `json:"finding_id"`
	Severity        string   `json:"severity"`
	Category        string   `json:"category"`
	Title           string   `json:"title"`
	Description     string   `json:"description"`
	URL             string   `json:"url"`
	Parameter       string   `json:"parameter"`
	Payload         string   `json:"payload"`
	Evidence        string   `json:"evidence"`
	Remediation     string   `json:"remediation"`
	References      []string `json:"references"`
	ManualTestSteps []string `json:"manual_test_steps"`
	CurlCommand     string   `json:"curl_command"`
}

// ToolStatus represents the availability status of an external tool.
type ToolStatus struct {
	Name        string `json:"name"`
	Available   bool   `json:"available"`
	Version     string `json:"version,omitempty"`
	InstallCmd  string `json:"install_cmd"`
	Description string `json:"description"`
}

// toolProbe defines the interface for specialized tool availability and version checks.
type toolProbe interface {
	Check(ctx context.Context) (bool, string)
}

// baseProbe provides common functionality for tool probes.
type baseProbe struct {
	binary string
}

func (p *baseProbe) runVersion(ctx context.Context, args []string) (string, error) {
	tctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(tctx, p.binary, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// genericProbe is a fallback that just checks if the binary is in PATH.
type genericProbe struct {
	baseProbe
}

func (p *genericProbe) Check(ctx context.Context) (bool, string) {
	if !ToolAvailable(p.binary) {
		return false, ""
	}
	return true, "Detected"
}

// httpxProbe verifies ProjectDiscovery httpx identity.
type httpxProbe struct {
	baseProbe
}

func (p *httpxProbe) Check(ctx context.Context) (bool, string) {
	out, _ := p.runVersion(ctx, []string{"-version"})
	if strings.Contains(strings.ToLower(out), "projectdiscovery") {
		lines := strings.Split(out, "\n")
		for _, line := range lines {
			if strings.Contains(line, "Version:") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					return true, parts[2]
				}
			}
		}
		return true, "Detected"
	}
	if out != "" || ToolAvailable(p.binary) {
		return false, "Imposter (Python)"
	}
	return false, "Not Found"
}

// nucleiProbe checks nuclei version.
type nucleiProbe struct {
	baseProbe
}

func (p *nucleiProbe) Check(ctx context.Context) (bool, string) {
	out, _ := p.runVersion(ctx, []string{"-version"})
	if strings.Contains(out, "Engine Version:") {
		idx := strings.Index(out, "v")
		if idx != -1 {
			// Extract until next space or newline
			fields := strings.Fields(out[idx:])
			if len(fields) > 0 {
				return true, fields[0]
			}
		}
	}
	if ToolAvailable(p.binary) {
		return true, "Detected"
	}
	return false, "Not Found"
}

// dalfoxProbe checks dalfox version.
type dalfoxProbe struct {
	baseProbe
}

func (p *dalfoxProbe) Check(ctx context.Context) (bool, string) {
	out, _ := p.runVersion(ctx, []string{"version"})
	// Find the last "v" followed by digits (Dalfox has ASCII art)
	idx := strings.LastIndex(out, "v")
	if idx != -1 {
		fields := strings.Fields(out[idx:])
		if len(fields) > 0 && len(fields[0]) > 1 && fields[0][1] >= '0' && fields[0][1] <= '9' {
			return true, fields[0]
		}
	}
	if ToolAvailable(p.binary) {
		return true, "Detected"
	}
	return false, "Not Found"
}

// whatwebProbe checks whatweb and its ruby dependency.
type whatwebProbe struct {
	baseProbe
}

func (p *whatwebProbe) Check(ctx context.Context) (bool, string) {
	if !ToolAvailable("ruby") {
		return false, "Ruby Missing"
	}
	out, _ := p.runVersion(ctx, []string{"--version"})
	if strings.Contains(out, "WhatWeb") {
		if idx := strings.Index(out, "version "); idx != -1 {
			fields := strings.Fields(out[idx:])
			if len(fields) >= 2 {
				return true, fields[1]
			}
		}
		return true, "Detected"
	}
	
	// Check common manual install locations if not in PATH
	possiblePaths := []string{
		"WhatWeb/whatweb",
		"/opt/WhatWeb/whatweb",
	}
	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			return true, "Found (manual)"
		}
	}
	
	return false, "Not Found"
}

// CheckAllToolAvailability returns the status of all manual testing tools.
func CheckAllToolAvailability() []ToolStatus {
	ctx := context.Background()
	probes := map[string]toolProbe{
		"nuclei": &nucleiProbe{baseProbe{binary: "nuclei"}},
		"httpx":  &httpxProbe{baseProbe{binary: "httpx"}},
		"dalfox": &dalfoxProbe{baseProbe{binary: "dalfox"}},
		"whatweb": &whatwebProbe{baseProbe{binary: "whatweb"}},
		"wapiti": &genericProbe{baseProbe{binary: "wapiti"}},
		"nikto":  &genericProbe{baseProbe{binary: "nikto"}},
		"sslyze": &genericProbe{baseProbe{binary: "sslyze"}},
	}

	toolConfigs := []struct {
		Name        string
		InstallCmd  string
		Description string
	}{
		{Name: "nuclei", InstallCmd: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", Description: "8000+ CVE vulnerability templates"},
		{Name: "httpx", InstallCmd: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", Description: "HTTP probing and fingerprinting"},
		{Name: "dalfox", InstallCmd: "go install github.com/hahwul/dalfox/v3@latest", Description: "Reflected/DOM XSS scanning"},
		{Name: "wapiti", InstallCmd: "pip install wapiti3", Description: "Comprehensive black-box web scanner"},
		{Name: "nikto", InstallCmd: "git clone https://github.com/sullo/nikto", Description: "Server misconfiguration scanner"},
		{Name: "sslyze", InstallCmd: "pip install sslyze", Description: "SSL/TLS configuration analyzer"},
		{Name: "corsy", InstallCmd: "git clone https://github.com/s0md3v/Corsy", Description: "CORS misconfiguration scanner"},
		{Name: "whatweb", InstallCmd: "git clone https://github.com/urbanadventurer/WhatWeb", Description: "Technology stack fingerprinting"},
	}

	var results []ToolStatus
	for _, cfg := range toolConfigs {
		available := false
		version := ""

		if probe, ok := probes[cfg.Name]; ok {
			available, version = probe.Check(ctx)
		} else if cfg.Name == "corsy" {
			available = ToolAvailable("python3") || ToolAvailable("python")
			version = "Requires Python"
		} else {
			available = ToolAvailable(cfg.Name)
			if available {
				version = "Detected"
			}
		}

		results = append(results, ToolStatus{
			Name:        cfg.Name,
			Available:   available,
			Version:     version,
			InstallCmd:  cfg.InstallCmd,
			Description: cfg.Description,
		})
	}
	return results
}

// runToolExec is a helper to run an external command with timeout, streaming output.
func runToolExec(ctx context.Context, name string, args []string, timeout time.Duration, onLog func(string)) ([]byte, error) {
	return runToolExecWithRetry(ctx, name, args, timeout, onLog, 2)
}

// runToolExecWithRetry runs an external tool with optional retries for transient failures.
// maxRetries=0 means no retry. Retries are skipped for "not found" or context cancellation errors.
func runToolExecWithRetry(ctx context.Context, name string, args []string, timeout time.Duration, onLog func(string), maxRetries int) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			onLog(fmt.Sprintf("[%s] Retrying in %v (attempt %d/%d)...", name, backoff, attempt+1, maxRetries+1))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		output, err := runToolExecOnce(ctx, name, args, timeout, onLog)
		if err == nil {
			return output, nil
		}
		lastErr = err

		errStr := err.Error()
		// Don't retry if tool is not installed, context cancelled, or intentional exit errors
		if strings.Contains(errStr, "not found") ||
			strings.Contains(errStr, "failed to start") && strings.Contains(errStr, "exec:") ||
			ctx.Err() != nil {
			return output, err
		}
		onLog(fmt.Sprintf("[%s] Attempt %d failed: %v", name, attempt+1, err))
	}
	return nil, lastErr
}

func runToolExecOnce(ctx context.Context, name string, args []string, timeout time.Duration, onLog func(string)) ([]byte, error) {
	toolCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(toolCtx, name, args...)
	cmd.Env = os.Environ()

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer

	go func() {
		io.Copy(&stdoutBuf, stdout)
	}()
	go func() {
		io.Copy(&stderrBuf, stderr)
	}()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start %s: %w", name, err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-toolCtx.Done():
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		onLog(fmt.Sprintf("[%s] [TIMEOUT] Tool exceeded timeout. Terminating.", name))
		return stdoutBuf.Bytes(), fmt.Errorf("%s timed out after %v", name, timeout)
	case err := <-done:
		if stderrBuf.Len() > 0 {
			for _, line := range strings.Split(stderrBuf.String(), "\n") {
				if l := strings.TrimSpace(line); l != "" {
					onLog(fmt.Sprintf("[%s-ERR] %s", name, l))
				}
			}
		}
		if err != nil {
			return stdoutBuf.Bytes(), fmt.Errorf("%s exited with error: %w", name, err)
		}
	}

	return stdoutBuf.Bytes(), nil
}

// RunHTTPxProbe runs httpx to probe the target and return HTTP info + tech detection.
func RunHTTPxProbe(ctx context.Context, targetURL string, onLog func(string)) ([]NormalizedFinding, error) {
	probe := &httpxProbe{baseProbe{binary: "httpx"}}
	ok, info := probe.Check(ctx)
	if !ok {
		return nil, fmt.Errorf("httpx validation failed: %s", info)
	}

	onLog("[HTTPx] Starting HTTP probing and fingerprinting...")

	toolCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(toolCtx, "httpx",
		"-silent", "-json", "-title", "-tech-detect", "-status-code",
		"-server", "-content-length", "-follow-redirects",
	)
	cmd.Env = os.Environ()
	cmd.Stdin = strings.NewReader(targetURL + "\n")

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	var stdoutBuf bytes.Buffer
	go func() { io.Copy(&stdoutBuf, stdout) }()
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stderr.Read(buf)
			if n > 0 {
				onLog(fmt.Sprintf("[HTTPx-ERR] %s", strings.TrimSpace(string(buf[:n]))))
			}
			if err != nil {
				break
			}
		}
	}()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start httpx: %w", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-toolCtx.Done():
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		onLog("[HTTPx] [TIMEOUT] httpx exceeded 3-minute budget.")
	case err := <-done:
		if err != nil {
			onLog(fmt.Sprintf("[HTTPx] Exited with: %v", err))
		}
	}

	data := stdoutBuf.Bytes()
	var findings []NormalizedFinding
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		var result struct {
			URL          string   `json:"url"`
			StatusCode   int      `json:"status_code"`
			Title        string   `json:"title"`
			WebServer    string   `json:"webserver"`
			Technologies []string `json:"tech"`
			ContentLength int     `json:"content_length"`
		}
		if err := json.Unmarshal([]byte(trimmed), &result); err != nil {
			continue
		}

		if result.WebServer != "" {
			findings = append(findings, NormalizedFinding{
				Tool:        "httpx",
				ToolVersion: info,
				Severity:    "INFO",
				Category:    "Technology Detection",
				Title:       fmt.Sprintf("Web Server: %s", result.WebServer),
				Description: fmt.Sprintf("Server header reveals: %s", result.WebServer),
				URL:         result.URL,
				Evidence:    fmt.Sprintf("Status: %d, Server: %s, Title: %s", result.StatusCode, result.WebServer, result.Title),
			})
		}

		for _, tech := range result.Technologies {
			findings = append(findings, NormalizedFinding{
				Tool:        "httpx",
				ToolVersion: info,
				Severity:    "INFO",
				Category:    "Technology Detection",
				Title:       fmt.Sprintf("Detected Technology: %s", tech),
				Description: fmt.Sprintf("Technology stack includes: %s", tech),
				URL:         result.URL,
			})
		}
	}

	onLog(fmt.Sprintf("[HTTPx] Probe complete. Found %d items.", len(findings)))
	return findings, nil
}

// RunWhatWebScan runs WhatWeb for technology fingerprinting.
func RunWhatWebScan(ctx context.Context, targetURL string, onLog func(string)) ([]NormalizedFinding, error) {
	probe := &whatwebProbe{baseProbe{binary: "whatweb"}}
	ok, info := probe.Check(ctx)
	if !ok {
		return nil, fmt.Errorf("whatweb validation failed: %s", info)
	}

	onLog("[WhatWeb] Starting technology fingerprinting...")

	tmpFile, err := os.CreateTemp("", "whatweb-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	data, err := runToolExec(ctx, "whatweb", []string{
		targetURL, "--log-json=" + tmpPath, "--color=never",
	}, 3*time.Minute, onLog)
	if err != nil {
		return nil, err
	}

	_ = data
	var findings []NormalizedFinding

	output, readErr := os.ReadFile(tmpPath)
	if readErr == nil && len(output) > 0 {
		var results []map[string]interface{}
		if json.Unmarshal(output, &results) == nil {
			for _, r := range results {
				if plugins, ok := r["plugins"].(map[string]interface{}); ok {
					for name, details := range plugins {
						findings = append(findings, NormalizedFinding{
							Tool:        "whatweb",
							ToolVersion: info,
							Severity:    "INFO",
							Category:    "Technology Detection",
							Title:       fmt.Sprintf("Technology: %s", name),
							Description: fmt.Sprintf("Detected on %s", targetURL),
							URL:         targetURL,
							Evidence:    fmt.Sprintf("%v", details),
						})
					}
				}
			}
		}
	}

	onLog(fmt.Sprintf("[WhatWeb] Scan complete. Found %d technologies.", len(findings)))
	return findings, nil
}

// WapitiJSONOutput represents Wapiti JSON output format.
type WapitiJSONOutput struct {
	Vulnerabilities map[string][]struct {
		Method    string `json:"method"`
		Info      string `json:"info"`
		Path      string `json:"path"`
		Parameter string `json:"parameter"`
		HTTPError int    `json:"http_request"`
		CurlCommand string `json:"curl_command"`
	} `json:"vulnerabilities"`
}

// RunWapitiScan runs Wapiti for comprehensive vulnerability scanning.
func RunWapitiScan(ctx context.Context, targetURL string, onLog func(string)) ([]NormalizedFinding, error) {
	if !ToolAvailable("wapiti") {
		return nil, fmt.Errorf("wapiti binary not found in PATH")
	}

	onLog("[Wapiti] Starting comprehensive vulnerability scan...")

	tmpDir, err := os.MkdirTemp("", "wapiti-out-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	outputJSON := tmpDir + "/results.json"

	_, err = runToolExec(ctx, "wapiti", []string{
		"-u", targetURL,
		"-o", outputJSON,
		"--format", "json",
		"--timeout", "10",
		"--max-links-per-page", "50",
		"-q",
	}, 8*time.Minute, onLog)
	if err != nil {
		onLog(fmt.Sprintf("[Wapiti] Scan completed with error: %v", err))
	}

	var findings []NormalizedFinding
	data, readErr := os.ReadFile(outputJSON)
	if readErr != nil {
		onLog("[Wapiti] No output file found, scan may not have completed.")
		return findings, nil
	}

	var wapitiResult WapitiJSONOutput
	if err := json.Unmarshal(data, &wapitiResult); err != nil {
		onLog(fmt.Sprintf("[Wapiti] Failed to parse JSON output: %v", err))
		return findings, nil
	}

	severityMap := map[string]string{
		"sql_injection":    "CRITICAL",
		"xss":             "HIGH",
		"ssrf":            "CRITICAL",
		"file_inclusion":  "HIGH",
		"csrf":            "MEDIUM",
		"commands_execution": "CRITICAL",
		"open_redirect":   "MEDIUM",
		"backup":          "HIGH",
		"brute_force":     "MEDIUM",
		"denial_of_service": "MEDIUM",
		"internal_error":  "LOW",
		"weak_password":   "MEDIUM",
		"server_misconfig": "LOW",
		"redirection":     "LOW",
	}

	categoryMap := map[string]string{
		"sql_injection":    "SQL Injection",
		"xss":             "Cross-Site Scripting",
		"ssrf":            "Server-Side Request Forgery",
		"file_inclusion":  "File Inclusion",
		"csrf":            "Cross-Site Request Forgery",
		"commands_execution": "Command Injection",
		"open_redirect":   "Open Redirect",
		"backup":          "Backup File Exposure",
		"brute_force":     "Brute Force",
		"denial_of_service": "Denial of Service",
		"internal_error":  "Internal Error",
		"weak_password":   "Weak Password",
		"server_misconfig": "Server Misconfiguration",
		"redirection":     "Redirection",
	}

	for vulnType, vulns := range wapitiResult.Vulnerabilities {
		severity := severityMap[vulnType]
		if severity == "" {
			severity = "MEDIUM"
		}
		category := categoryMap[vulnType]
		if category == "" {
			category = vulnType
		}

		for _, v := range vulns {
			findingURL := targetURL
			if v.Path != "" {
				if strings.HasPrefix(v.Path, "http") {
					findingURL = v.Path
				} else {
					findingURL = targetURL + v.Path
				}
			}

			findings = append(findings, NormalizedFinding{
				Tool:        "wapiti",
				Severity:    severity,
				Category:    category,
				Title:       fmt.Sprintf("[%s] %s", category, v.Info),
				Description: v.Info,
				URL:         findingURL,
				Parameter:   v.Parameter,
				Evidence:    fmt.Sprintf("Method: %s, Path: %s, Parameter: %s", v.Method, v.Path, v.Parameter),
				CurlCommand: v.CurlCommand,
			})
		}
	}

	onLog(fmt.Sprintf("[Wapiti] Scan complete. Found %d vulnerabilities.", len(findings)))
	return findings, nil
}

// CorsyJSONOutput represents Corsy JSON output format.
type CorsyJSONOutput struct {
	URL          string `json:"url"`
	VulnerabilityType string `json:"vulnerability_type"`
	Severity     string `json:"severity"`
	Description  string `json:"description"`
	Payload      string `json:"payload"`
}

// RunCorsyScan runs Corsy for CORS misconfiguration detection.
func RunCorsyScan(ctx context.Context, targetURL string, onLog func(string)) ([]NormalizedFinding, error) {
	onLog("[Corsy] Starting CORS misconfiguration scan...")

	if !ToolAvailable("python3") && !ToolAvailable("python") {
		return nil, fmt.Errorf("python3/python binary not found in PATH (required for Corsy)")
	}

	corsyPath := ""
	if envPath := os.Getenv("CORSY_PATH"); envPath != "" {
		if _, err := os.Stat(envPath); err == nil {
			corsyPath = envPath
		}
	}
	if corsyPath == "" {
		possiblePaths := []string{
			"Corsy/corsy.py",
			"/opt/Corsy/corsy.py",
			os.ExpandEnv("$HOME/Corsy/corsy.py"),
			os.ExpandEnv("$USERPROFILE/Corsy/corsy.py"),
			os.ExpandEnv("$HOME/.local/share/Corsy/corsy.py"),
			"/usr/local/lib/python3/dist-packages/Corsy/corsy.py",
		}
		for _, p := range possiblePaths {
			if _, err := os.Stat(p); err == nil {
				corsyPath = p
				break
			}
		}
	}

	if corsyPath == "" {
		onLog("[Corsy] Corsy not found in standard locations. Skipping.")
		return nil, fmt.Errorf("Corsy not found. Clone it from https://github.com/s0md3v/Corsy")
	}

	pythonCmd := "python3"
	if !ToolAvailable("python3") {
		pythonCmd = "python"
	}

	tmpFile, err := os.CreateTemp("", "corsy-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	_, err = runToolExec(ctx, pythonCmd, []string{
		corsyPath, "-u", targetURL, "-o", tmpPath, "--json",
	}, 5*time.Minute, onLog)
	if err != nil {
		return nil, err
	}

	var findings []NormalizedFinding
	data, readErr := os.ReadFile(tmpPath)
	if readErr == nil && len(data) > 0 {
		var corsyResults []CorsyJSONOutput
		if json.Unmarshal(data, &corsyResults) == nil {
			for _, r := range corsyResults {
				severity := strings.ToUpper(r.Severity)
				if severity == "" {
					severity = "MEDIUM"
				}
				findings = append(findings, NormalizedFinding{
					Tool:        "corsy",
					Severity:    severity,
					Category:    "CORS Misconfiguration",
					Title:       fmt.Sprintf("CORS: %s", r.VulnerabilityType),
					Description: r.Description,
					URL:         r.URL,
					Payload:     r.Payload,
					Evidence:    r.Description,
				})
			}
		}
	}

	onLog(fmt.Sprintf("[Corsy] Scan complete. Found %d CORS issues.", len(findings)))
	return findings, nil
}

// NiktoJSONWrapper represents the full Nikto JSON output structure.
type NiktoJSONWrapper struct {
	Host            string           `json:"host"`
	IP              string           `json:"ip"`
	Port            string           `json:"port"`
	Vulnerabilities []NiktoJSONOutput `json:"vulnerabilities"`
}

// NiktoJSONOutput represents a single Nikto vulnerability finding.
type NiktoJSONOutput struct {
	OSVDB   string `json:"OSVDB"`
	Method  string `json:"method"`
	URL     string `json:"url"`
	Message string `json:"msg"`
}

// RunNiktoScan runs Nikto for server misconfiguration detection.
func RunNiktoScan(ctx context.Context, targetURL string, onLog func(string)) ([]NormalizedFinding, error) {
	if !ToolAvailable("nikto") {
		return nil, fmt.Errorf("nikto binary not found in PATH")
	}

	onLog("[Nikto] Starting server misconfiguration scan...")

	tmpFile, err := os.CreateTemp("", "nikto-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	_, err = runToolExec(ctx, "nikto", []string{
		"-h", targetURL,
		"-Format", "json",
		"-o", tmpPath,
		"-nointeractive",
	}, 8*time.Minute, onLog)
	if err != nil {
		onLog(fmt.Sprintf("[Nikto] Scan completed with error: %v", err))
	}

	var findings []NormalizedFinding
	data, readErr := os.ReadFile(tmpPath)
	if readErr == nil && len(data) > 0 {
		var niktoWrapper NiktoJSONWrapper
		var niktoResults []NiktoJSONOutput

		// Try the wrapped format first: { "host": "...", "vulnerabilities": [...] }
		if json.Unmarshal(data, &niktoWrapper) == nil && len(niktoWrapper.Vulnerabilities) > 0 {
			niktoResults = niktoWrapper.Vulnerabilities
		} else {
			// Fallback: try flat array format (older Nikto versions)
			_ = json.Unmarshal(data, &niktoResults)
		}

		for _, r := range niktoResults {
			severity := "MEDIUM"
			msgLower := strings.ToLower(r.Message)
			if strings.Contains(msgLower, "critical") || strings.Contains(msgLower, "remote code") {
				severity = "HIGH"
			} else if strings.Contains(msgLower, "warning") || strings.Contains(msgLower, "misconfiguration") {
				severity = "MEDIUM"
			} else {
				severity = "LOW"
			}

			findings = append(findings, NormalizedFinding{
				Tool:        "nikto",
				Severity:    severity,
				Category:    "Server Misconfiguration",
				Title:       r.Message,
				Description: r.Message,
				URL:         r.URL,
				Evidence:    fmt.Sprintf("OSVDB: %s, Method: %s", r.OSVDB, r.Method),
				References:  []string{fmt.Sprintf("https://www.osvdb.org/show/%s", r.OSVDB)},
			})
		}
	}

	onLog(fmt.Sprintf("[Nikto] Scan complete. Found %d issues.", len(findings)))
	return findings, nil
}

// SSLyzeJSONOutput represents SSLyze JSON output.
type SSLyzeJSONOutput struct {
	ServerScanResults []struct {
		ServerInfo struct {
			Hostname string `json:"hostname"`
			Port     int    `json:"port"`
		} `json:"server_info"`
		ScanResult struct {
			SSLScanResult struct {
				AcceptedCipherSuites []struct {
					CipherSuite struct {
						Name string `json:"name"`
					} `json:"cipher_suite"`
				} `json:"accepted_cipher_suites"`
				IsVulnerableToHeartbleed bool `json:"is_vulnerable_to_heartbleed"`
				IsVulnerableToCRIME      bool `json:"is_vulnerable_to_crime"`
				IsVulnerableToROBOT     bool `json:"is_vulnerable_to_robot"`
				IsVulnerableToPaddingOracle bool `json:"is_vulnerable_to_padding_oracle"`
				TLSVersions []struct {
					Version string `json:"version"`
					Name    string `json:"name"`
				} `json:"tls_versions"`
				CertificateInfos []struct {
					Hostname  string `json:"hostname"`
					Certificate struct {
						NotAfter string `json:"not_after"`
						Issuer   string `json:"issuer"`
					} `json:"certificate"`
				} `json:"certificate_infos"`
			} `json:"ssl_scan_result"`
		} `json:"scan_result"`
	} `json:"server_scan_results"`
}

// RunSSLyzeScan runs SSLyze for SSL/TLS configuration analysis.
func RunSSLyzeScan(ctx context.Context, targetURL string, onLog func(string)) ([]NormalizedFinding, error) {
	if !ToolAvailable("sslyze") {
		return nil, fmt.Errorf("sslyze binary not found in PATH")
	}

	onLog("[SSLyze] Starting SSL/TLS configuration analysis...")

	hostname := strings.TrimPrefix(targetURL, "https://")
	hostname = strings.TrimPrefix(hostname, "http://")
	hostname = strings.TrimSuffix(hostname, "/")
	if idx := strings.Index(hostname, "/"); idx > 0 {
		hostname = hostname[:idx]
	}

	// Preserve non-standard ports for SSLyze
	port := "443"
	if idx := strings.Index(hostname, ":"); idx > 0 {
		port = hostname[idx+1:]
		hostname = hostname[:idx]
	}

	tmpFile, err := os.CreateTemp("", "sslyze-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	args := []string{"--json_out", tmpPath, "--port", port, hostname}
	_, err = runToolExec(ctx, "sslyze", args, 5*time.Minute, onLog)
	if err != nil {
		return nil, err
	}

	var findings []NormalizedFinding
	data, readErr := os.ReadFile(tmpPath)
	if readErr == nil && len(data) > 0 {
		var sslyzeResult SSLyzeJSONOutput
		if json.Unmarshal(data, &sslyzeResult) == nil {
			for _, scan := range sslyzeResult.ServerScanResults {
				result := scan.ScanResult.SSLScanResult

				if result.IsVulnerableToHeartbleed {
					findings = append(findings, NormalizedFinding{
						Tool:        "sslyze",
						Severity:    "CRITICAL",
						Category:    "SSL/TLS Vulnerability",
						Title:       "Heartbleed Vulnerability (CVE-2014-0160)",
						Description: "Server is vulnerable to Heartbleed, allowing memory disclosure.",
						URL:         targetURL,
						Evidence:    "SSLyze confirmed Heartbleed vulnerability.",
						References:  []string{"https://heartbleed.com/"},
					})
				}
				if result.IsVulnerableToCRIME {
					findings = append(findings, NormalizedFinding{
						Tool:        "sslyze",
						Severity:    "HIGH",
						Category:    "SSL/TLS Vulnerability",
						Title:       "CRIME Vulnerability",
						Description: "Server is vulnerable to CRIME attack, enabling session cookie theft.",
						URL:         targetURL,
					})
				}
				if result.IsVulnerableToROBOT {
					findings = append(findings, NormalizedFinding{
						Tool:        "sslyze",
						Severity:    "HIGH",
						Category:    "SSL/TLS Vulnerability",
						Title:       "ROBOT Vulnerability",
						Description: "Server is vulnerable to Return Of Bleichenbacher's Oracle Threat.",
						URL:         targetURL,
					})
				}
				if result.IsVulnerableToPaddingOracle {
					findings = append(findings, NormalizedFinding{
						Tool:        "sslyze",
						Severity:    "HIGH",
						Category:    "SSL/TLS Vulnerability",
						Title:       "Padding Oracle Vulnerability",
						Description: "Server is vulnerable to padding oracle attack.",
						URL:         targetURL,
					})
				}

				for _, ver := range result.TLSVersions {
					if strings.Contains(strings.ToLower(ver.Name), "ssl") || strings.Contains(ver.Version, "1.0") || strings.Contains(ver.Version, "1.1") {
						findings = append(findings, NormalizedFinding{
							Tool:        "sslyze",
							Severity:    "MEDIUM",
							Category:    "SSL/TLS Misconfiguration",
							Title:       fmt.Sprintf("Deprecated TLS Version: %s", ver.Name),
							Description: fmt.Sprintf("Server supports %s which is deprecated and insecure.", ver.Name),
							URL:         targetURL,
							Evidence:    fmt.Sprintf("Supported: %s (%s)", ver.Name, ver.Version),
							Remediation: "Disable TLS 1.0 and 1.1. Only allow TLS 1.2 and 1.3.",
						})
					}
				}
			}
		}
	}

	onLog(fmt.Sprintf("[SSLyze] Scan complete. Found %d issues.", len(findings)))
	return findings, nil
}

// RunNucleiScanAllTemplates runs Nuclei with ALL templates (not just safe ones) for manual mode.
func RunNucleiScanAllTemplates(ctx context.Context, targetURL string, proxyPort int, cookieStr string, onLog func(string)) ([]NormalizedFinding, error) {
	probe := &nucleiProbe{baseProbe{binary: "nuclei"}}
	ok, info := probe.Check(ctx)
	if !ok {
		return nil, fmt.Errorf("nuclei validation failed: %s", info)
	}

	onLog("[Nuclei] Starting full vulnerability scan (all templates)...")

	if !checkNucleiTemplatesExist() {
		onLog("[Nuclei] Templates not found. Attempting initialization...")
		InitNucleiTemplates()
	}

	toolCtx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()

	tmpFile, err := os.CreateTemp("", "nuclei-full-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	args := []string{"-u", targetURL, "-json-export", tmpPath, "-silent", "-as"}
	if proxyPort > 0 {
		args = append(args, "-proxy", fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	}
	if cookieStr != "" {
		args = append(args, "-H", fmt.Sprintf("Cookie: %s", cookieStr))
	}

	cmd := exec.CommandContext(toolCtx, "nuclei", args...)
	cmd.Env = os.Environ()

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				onLog(fmt.Sprintf("[Nuclei] %s", strings.TrimSpace(string(buf[:n]))))
			}
			if err != nil {
				break
			}
		}
	}()
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stderr.Read(buf)
			if n > 0 {
				onLog(fmt.Sprintf("[Nuclei-ERR] %s", strings.TrimSpace(string(buf[:n]))))
			}
			if err != nil {
				break
			}
		}
	}()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start nuclei: %w", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-ctx.Done():
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		onLog("[Nuclei] [TIMEOUT] Nuclei scan terminated.")
	case err := <-done:
		if err != nil {
			onLog(fmt.Sprintf("[Nuclei] Exited with: %v", err))
		}
	}

	var findings []NormalizedFinding
	data, readErr := os.ReadFile(tmpPath)
	if readErr != nil {
		return findings, nil
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		var item NucleiJSONOutput
		if err := json.Unmarshal([]byte(trimmed), &item); err == nil {
			severity := strings.ToUpper(item.Info.Severity)
			if severity == "" {
				severity = "INFO"
			}
			if severity == "CRITICAL" {
				severity = "CRITICAL"
			}

			category := "Security Misconfiguration"
			severityLower := strings.ToLower(item.Info.Severity)
			switch {
			case strings.Contains(severityLower, "critical") || strings.Contains(severityLower, "high"):
				category = "Critical Vulnerability"
			case item.Type == "http":
				category = "HTTP Misconfiguration"
			}

			var refs []string
			if item.TemplateID != "" {
				refs = append(refs, fmt.Sprintf("https://github.com/projectdiscovery/nuclei-templates/blob/master/%s.yaml", item.TemplateID))
			}

			findings = append(findings, NormalizedFinding{
				Tool:        "nuclei",
				ToolVersion: info,
				Severity:    severity,
				Category:    category,
				Title:       item.Info.Name,
				Description: item.Info.Description,
				URL:         item.MatchedPath,
				Payload:     fmt.Sprintf("Template ID: %s", item.TemplateID),
				Evidence:    fmt.Sprintf("Host: %s, Matched: %s", item.Host, item.MatchedPath),
				References:  refs,
			})
		}
	}

	onLog(fmt.Sprintf("[Nuclei] Full scan complete. Found %d vulnerabilities.", len(findings)))
	return findings, nil
}
