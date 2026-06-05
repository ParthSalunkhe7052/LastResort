package attack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ToolFinding represents a vulnerability finding discovered by an external tool.
type ToolFinding struct {
	Title             string
	Severity          string
	VulnerabilityType string
	Endpoint          string
	Payload           string
	Evidence          string
	Source            string // "dalfox", "sqlmap", "nuclei"
}

// ToolAvailable checks if an executable exists in the PATH.
func ToolAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// RunKatanaCrawl runs the Katana crawler on targetURL.
// It calls onEndpoint for every discovered URL parsed from Katana's output.
func RunKatanaCrawl(ctx context.Context, targetURL string, proxyPort int, onEndpoint func(method, urlStr, source string)) error {
	if !ToolAvailable("katana") {
		return fmt.Errorf("katana binary not found in PATH")
	}

	tmpFile, err := os.CreateTemp("", "katana-*.txt")
	if err != nil {
		return fmt.Errorf("failed to create temp file for katana: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	// Command: katana -u <target> -d 3 -jc -silent -o <tmpPath>
	args := []string{"-u", targetURL, "-d", "3", "-jc", "-silent", "-o", tmpPath}
	if proxyPort > 0 {
		args = append(args, "-proxy", fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	}
	cmd := exec.CommandContext(ctx, "katana", args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("katana execution failed: %w", err)
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return fmt.Errorf("failed to read katana output: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// Default to GET for crawled URLs
		onEndpoint("GET", trimmed, "katana")
	}

	return nil
}

// DalfoxJSONOutput represents a single finding in Dalfox's JSON output format.
type DalfoxJSONOutput struct {
	Type     string `json:"type"` // e.g. "VULN", "WEAK"
	Param    string `json:"param"`
	Method   string `json:"method"`
	Evidence string `json:"evidence"`
	Message  string `json:"message"`
}

// RunDalfoxScan executes Dalfox against targetURL.
func RunDalfoxScan(ctx context.Context, targetURL string, proxyPort int) ([]ToolFinding, error) {
	if !ToolAvailable("dalfox") {
		return nil, fmt.Errorf("dalfox binary not found in PATH")
	}

	tmpFile, err := os.CreateTemp("", "dalfox-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file for dalfox: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	// Command: dalfox url <url> --silence --output <tmpPath> --format json
	args := []string{"url", targetURL, "--silence", "--output", tmpPath, "--format", "json"}
	if proxyPort > 0 {
		args = append(args, "--proxy", fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	}
	cmd := exec.CommandContext(ctx, "dalfox", args...)
	if err := cmd.Run(); err != nil {
		// Dalfox returns non-zero code sometimes if findings are found, or on scan issues.

		// We proceed to check if the output file has content regardless.
	}

	fileInfo, err := os.Stat(tmpPath)
	if err != nil || fileInfo.Size() == 0 {
		return nil, nil // No findings or couldn't read file
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read dalfox output: %w", err)
	}

	var findings []ToolFinding
	trimmedData := strings.TrimSpace(string(data))
	
	// Dalfox format json can be a single JSON array containing objects:
	// [{"type":"VULN",...}]
	if strings.HasPrefix(trimmedData, "[") && strings.HasSuffix(trimmedData, "]") {
		var items []DalfoxJSONOutput
		if err := json.Unmarshal(data, &items); err == nil {
			for _, item := range items {
				if item.Type == "VULN" {
					findings = append(findings, ToolFinding{
						Title:             fmt.Sprintf("Reflected XSS in Parameter: %s", item.Param),
						Severity:          "HIGH",
						VulnerabilityType: "Reflected XSS",
						Endpoint:          targetURL,
						Payload:           item.Evidence,
						Evidence:          item.Message,
						Source:            "dalfox",
					})
				}
			}
			return findings, nil
		}
	}

	// Fallback to line-by-line JSON parsing
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		var item DalfoxJSONOutput
		if err := json.Unmarshal([]byte(trimmed), &item); err == nil {
			// We only save actual vulnerability reports
			if item.Type == "VULN" {
				findings = append(findings, ToolFinding{
					Title:             fmt.Sprintf("Reflected XSS in Parameter: %s", item.Param),
					Severity:          "HIGH",
					VulnerabilityType: "Reflected XSS",
					Endpoint:          targetURL,
					Payload:           item.Evidence,
					Evidence:          item.Message,
					Source:            "dalfox",
				})
			}
		}
	}

	return findings, nil
}

// RunSQLMapScan runs SQLMap on targetURL.
func RunSQLMapScan(ctx context.Context, targetURL string, proxyPort int) ([]ToolFinding, error) {
	if !ToolAvailable("sqlmap") {
		return nil, fmt.Errorf("sqlmap binary not found in PATH")
	}

	tmpDir, err := os.MkdirTemp("", "sqlmap-out-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir for sqlmap: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Command: sqlmap -u <targetURL> --batch --level=2 --risk=1 --output-dir=<tmpDir> --forms --non-interactive
	// Note: --non-interactive is crucial on Windows to avoid prompt hangs at exit.
	args := []string{"-u", targetURL, "--batch", "--level=2", "--risk=1", "--output-dir=" + tmpDir, "--forms", "--non-interactive"}
	if proxyPort > 0 {
		args = append(args, "--proxy", fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	}
	cmd := exec.CommandContext(ctx, "sqlmap", args...)
	if err := cmd.Run(); err != nil {
		// sqlmap might return non-zero exit codes when finding injection or when encountering errors.

		// We still parse the log file to extract injection details.
	}

	// SQLMap writes output to subdirectories under the output-dir based on hostnames.
	// We scan the directory to find any "log" files.
	var findings []ToolFinding
	err = filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && info.Name() == "log" {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			logContent := string(data)
			if strings.Contains(logContent, "Injectable parameter") || strings.Contains(logContent, "Type:") {
				// Extraction is successful. We create a generic SQL injection finding.
				findings = append(findings, ToolFinding{
					Title:             "SQL Injection Discovered",
					Severity:          "HIGH",
					VulnerabilityType: "SQL Injection",
					Endpoint:          targetURL,
					Payload:           "Refer to SQLMap scan evidence.",
					Evidence:          logContent,
					Source:            "sqlmap",
				})
			}
		}
		return nil
	})

	return findings, err
}

// NucleiJSONOutput represents Nuclei JSON output line schema.
type NucleiJSONOutput struct {
	TemplateID    string   `json:"template-id"`
	Info          struct {
		Name        string `json:"name"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
	} `json:"info"`
	Type          string   `json:"type"`
	Host          string   `json:"host"`
	MatchedPath   string   `json:"matched-at"`
	ExtractedResults []string `json:"extracted-results"`
	Metadata      map[string]interface{} `json:"meta"`
}

// RunNucleiScan executes Nuclei scanner on targetURL.
func RunNucleiScan(ctx context.Context, targetURL string, proxyPort int) ([]ToolFinding, error) {
	if !ToolAvailable("nuclei") {
		return nil, fmt.Errorf("nuclei binary not found in PATH")
	}

	// Ensure templates are initialized if they appear to be missing
	if !checkNucleiTemplatesExist() {
		log.Printf("[Nuclei] Templates not found in default location. Attempting synchronous initialization...")
		InitNucleiTemplates()
	}

	tmpFile, err := os.CreateTemp("", "nuclei-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file for nuclei: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	// Command: nuclei -u <target> -tags safe -as -json-export <tmpPath> -silent
	args := []string{"-u", targetURL, "-tags", "safe", "-as", "-json-export", tmpPath, "-silent"}
	if proxyPort > 0 {
		args = append(args, "-proxy", fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	}
	cmd := exec.CommandContext(ctx, "nuclei", args...)
	cmd.Env = os.Environ()

	// Create buffers to capture stderr to help debug failures
	var stderrBuf bytes.Buffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderrBuf

	if err := cmd.Run(); err != nil {
		stderrStr := strings.TrimSpace(stderrBuf.String())
		if strings.Contains(stderrStr, "no templates provided") {
			return nil, fmt.Errorf("nuclei failed: no templates found. Ensure 'nuclei -ut' has been run and templates are accessible: %s", stderrStr)
		}
		return nil, fmt.Errorf("nuclei execution failed (stderr: %s): %w", stderrStr, err)
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read nuclei output: %w", err)
	}

	var findings []ToolFinding
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
			// Map nuclei severity categories to ours: CRITICAL, HIGH, MEDIUM, LOW, INFO
			if severity == "CRITICAL" {
				severity = "HIGH"
			}
			findings = append(findings, ToolFinding{
				Title:             item.Info.Name,
				Severity:          severity,
				VulnerabilityType: "Security Misconfiguration",
				Endpoint:          item.MatchedPath,
				Payload:           fmt.Sprintf("Template ID: %s", item.TemplateID),
				Evidence:          item.Info.Description,
				Source:            "nuclei",
			})
		}
	}

	return findings, nil
}

// checkNucleiTemplatesExist performs a basic check for the existence of the nuclei-templates directory.
func checkNucleiTemplatesExist() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	// Default location is usually ~/nuclei-templates
	tmplDir := filepath.Join(home, "nuclei-templates")
	info, err := os.Stat(tmplDir)
	return err == nil && info.IsDir()
}

// InitNucleiTemplates detects nuclei, checks templates, and updates them if missing/outdated.
func InitNucleiTemplates() {
	if !ToolAvailable("nuclei") {
		log.Printf("[Nuclei] Nuclei binary not found in PATH. Skipping template initialization.")
		return
	}

	log.Printf("[Nuclei] Nuclei binary detected. Checking templates...")
	versionCmd := exec.Command("nuclei", "-version")
	versionCmd.Env = os.Environ()
	out, err := versionCmd.CombinedOutput()
	if err == nil {
		log.Printf("[Nuclei] Version and template info:\n%s", string(out))
	}

	log.Printf("[Nuclei] Updating/downloading templates and engine...")
	// Use modern flags: -ut (update templates), -up (update project/engine)
	updateCmd := exec.Command("nuclei", "-ut")
	updateCmd.Env = os.Environ()
	if err := updateCmd.Run(); err != nil {
		log.Printf("[Nuclei] [WARNING] Failed to update templates with -ut: %v. Trying fallback -update-templates...", err)
		fallbackCmd := exec.Command("nuclei", "-update-templates")
		fallbackCmd.Env = os.Environ()
		_ = fallbackCmd.Run()
	}

	updateEngineCmd := exec.Command("nuclei", "-up")
	updateEngineCmd.Env = os.Environ()
	if err := updateEngineCmd.Run(); err != nil {
		log.Printf("[Nuclei] [WARNING] Failed to update engine: %v", err)
	}

	log.Printf("[Nuclei] Initialization process complete.")
}

