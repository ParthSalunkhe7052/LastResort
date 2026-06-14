# LastResort — Manual Testing Audit & Improvement Plan

## Executive Summary

This document presents an in-depth audit of the LastResort penetration testing platform's **Manual Testing** mode (`testingMode=2`), identifies critical gaps, and proposes a comprehensive improvement plan that integrates real open-source penetration testing tools to produce actionable, non-coder-friendly manual testing guides.

---

## 1. Current State Analysis

### 1.1 What Happens When "Manual Review" Is Clicked

**Flow:**
```
User clicks "Manual Review" (testingMode=2)
  → Frontend calls client.createScan({ testingMode: 2 })
  → Backend orchestrator reads testingMode from DB
  → Filters modules to only: [headers, cors, nuclei]
  → Appends: manual_guide
  → Skips: browser health check, browser session cleanup
  → Runs: headers → cors → nuclei → manual_guide
  → manual_guide calls AI (Gemini) to generate a Markdown guide
  → Frontend receives "manual.guide.ready" event
  → ManualGuidePanel renders the Markdown guide
```

### 1.2 Critical Issues Found

| # | Issue | Severity | Location |
|---|-------|----------|----------|
| 1 | **Only 3 tools run in manual mode** — headers, cors, nuclei (safe templates only). No SQLMap, Dalfox, Wapiti, SSLyze, Nikto, WhatWeb. | CRITICAL | `orchestrator.go:88-105` |
| 2 | **Nuclei runs with `-tags safe`** — only safe templates. No actual vulnerability detection. | CRITICAL | `tools.go:326` |
| 3 | **Headers/CORS modules need crawled endpoints** — In manual mode, `ModuleCrawlStatic` is skipped, so `endpoints` table is empty. Headers and CORS modules query `ListEndpoints()` which returns nothing. | CRITICAL | `orchestrator.go:1190-1216` |
| 4 | **No reconnaissance** — No tech stack detection, no subdomain enumeration, no HTTP probing. AI has no context about the target. | HIGH | `orchestrator.go:88-105` |
| 5 | **AI guide generation depends on findings** — If no findings exist (likely due to issue #3), the guide generation returns early with "No critical vulnerabilities found." | HIGH | `orchestrator.go:1594-1597` |
| 6 | **No filtering mechanism** — The "top 10" query exists but if all findings are INFO/LOW severity from headers/cors, the guide will be useless. | MEDIUM | `orchestrator.go:1565-1578` |
| 7 | **ManualGuidePanel is minimal** — Just a Markdown renderer with no interactivity, no finding details, no severity badges, no copy-to-clipboard for payloads. | MEDIUM | `ManualGuidePanel.tsx` |
| 8 | **No tool availability checking** — Manual mode doesn't verify which tools are installed before attempting to run them. | MEDIUM | `orchestrator.go` |
| 9 | **Duplicate `makeFormSubmitScript`** — Identical function in `module.go` and `orchestrator.go`. | LOW | `module.go:163-205`, `orchestrator.go:670-712` |
| 10 | **Dead code in `streamToolOutput`** — Unused dummy variables before real implementation. | LOW | `tools.go:397-405` |

### 1.3 Frontend State for Manual Mode

The frontend **does correctly** handle `testingMode === 2`:
- ✅ Switches to 2-column layout (EventTimeline + ManualGuidePanel)
- ✅ Hides LiveBrowserPanel (no browser needed)
- ✅ Shows "Generating Guide..." placeholder while waiting
- ✅ Renders Markdown guide when received

**However:**
- ❌ No progress indicators for individual tools running
- ❌ No tool status display (which tools are installed/running/complete)
- ❌ No findings summary before the guide
- ❌ No way to re-run or customize which tools to use
- ❌ The "Crawl/Attack Profile" selector is shown but meaningless in manual mode (all profiles produce the same 3 tools)

---

## 2. Proposed Manual Testing Pipeline

### 2.1 Architecture

```
User enters URL → clicks "Manual Review"
  │
  ▼
Phase 1: Reconnaissance (No browser needed)
  ├── httpx (HTTP probing + tech detection)
  ├── whatweb (technology stack fingerprinting)
  └── subfinder (subdomain enumeration — optional)
  │
  ▼
Phase 2: Vulnerability Scanning (No browser needed)
  ├── nuclei (ALL templates, not just safe)
  ├── wapiti (comprehensive black-box scanner)
  ├── dalfox (XSS scanning)
  ├── corsy (CORS misconfiguration)
  ├── nikto (server misconfiguration)
  └── sslyze (SSL/TLS analysis)
  │
  ▼
Phase 3: Filtering & Ranking
  ├── Normalize all findings to unified schema
  ├── Deduplicate across tools
  ├── Rank by severity → confidence → exploitability
  └── Select top 10 critical findings
  │
  ▼
Phase 4: AI Guide Generation
  ├── Feed top 10 findings + target context to Gemini
  ├── Generate step-by-step manual exploitation guide
  ├── Include: what to check, exact URLs, payloads, expected results
  └── Make it non-coder friendly
  │
  ▼
Phase 5: Frontend Display
  ├── Findings summary dashboard (severity breakdown)
  ├── Interactive guide with expandable sections
  ├── Copy-to-clipboard for payloads/URLs
  └── Tool status indicators
```

### 2.2 New Module Definitions

```go
// New modules for manual testing pipeline
const (
    ModuleManualRecon     = "manual_recon"      // httpx + whatweb
    ModuleManualNuclei    = "manual_nuclei"     // nuclei (all templates)
    ModuleManualWapiti    = "manual_wapiti"     // wapiti scanner
    ModuleManualDalfox    = "manual_dalfox"     // dalfox XSS
    ModuleManualCorsy     = "manual_corsy"      // corsy CORS
    ModuleManualNikto     = "manual_nikto"      // nikto server scan
    ModuleManualSSLyze    = "manual_sslyze"     // sslyze TLS
    ModuleManualGuide     = "manual_guide"      // AI guide generation (existing)
)
```

### 2.3 Tool Integration Details

#### Tier 1 — Must Integrate

| Tool | Purpose | Install Command | Run Command | JSON Output |
|------|---------|----------------|-------------|-------------|
| **Nuclei** | 8000+ vulnerability templates | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` | `nuclei -u <url> -json-export out.json` | ✅ Native |
| **Wapiti** | Comprehensive black-box scanner | `pip install wapiti3` | `wapiti -u <url> -o out.json --format json` | ✅ Native |
| **Dalfox** | XSS scanning with PoC URLs | `go install github.com/hahwul/dalfox/v3@latest` | `dalfox url <url> --format json` | ✅ Native |
| **Corsy** | CORS misconfiguration | `git clone + pip install requests` | `python3 corsy.py -u <url> -o out.json` | ✅ Native |

#### Tier 2 — Strong Complement

| Tool | Purpose | Install Command | Run Command | JSON Output |
|------|---------|----------------|-------------|-------------|
| **WhatWeb** | Technology detection | `git clone (Ruby)` | `whatweb <url> --log-json=out.json` | ✅ Native |
| **HTTPx** | HTTP probing + fingerprinting | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` | `echo <url> \| httpx -json` | ✅ Native |
| **SSLyze** | SSL/TLS analysis | `pip install sslyze` | `python -m sslyze --json_out out.json <url>` | ✅ Native |
| **Nikto** | Server misconfiguration | `git clone (Perl)` | `perl nikto.pl -h <url> -Format json -o out.json` | ✅ Native |

#### Tier 3 — Optional

| Tool | Purpose | Install Command | Run Command | JSON Output |
|------|---------|----------------|-------------|-------------|
| **SQLMap** | SQL injection (deep) | `git clone (Python)` | `python sqlmap.py -u <url> --batch --forms` | ⚠️ Partial |
| **Gobuster** | Directory bruteforce | `go install github.com/OJ/gobuster/v3@latest` | `gobuster dir -u <url> -w wordlist.txt` | ❌ Parse stdout |

### 2.4 Normalized Finding Schema

All tool outputs should be normalized to this structure before AI processing:

```go
type NormalizedFinding struct {
    Tool            string   `json:"tool"`            // "nuclei", "wapiti", "dalfox", etc.
    FindingID       string   `json:"finding_id"`      // Unique ID
    Severity        string   `json:"severity"`        // CRITICAL, HIGH, MEDIUM, LOW, INFO
    Category        string   `json:"category"`        // "SQL Injection", "XSS", "CORS", etc.
    Title           string   `json:"title"`           // Human-readable title
    Description     string   `json:"description"`     // What the vulnerability is
    URL             string   `json:"url"`             // Affected URL
    Parameter       string   `json:"parameter"`       // Affected parameter (if any)
    Payload         string   `json:"payload"`         // Exploit payload used
    Evidence        string   `json:"evidence"`        // Proof of vulnerability
    Remediation     string   `json:"remediation"`     // How to fix
    References      []string `json:"references"`      // CVE links, documentation
    ManualTestSteps []string `json:"manual_test_steps"` // Steps for manual verification
}
```

### 2.5 AI Prompt Enhancement

Current prompt is basic. Enhanced prompt should include:

```
You are LastResort, a senior security researcher and mentor.

TARGET INFORMATION:
- URL: {targetURL}
- Technology Stack: {detectedTechnologies} (from WhatWeb/HTTPx)
- Server: {serverHeader}
- TLS Version: {tlsVersion}

VULNERABILITIES FOUND (ranked by severity):
{findingsList}

For EACH vulnerability, provide:
1. **Risk Level** (Critical/High/Medium/Low with color emoji)
2. **What is this?** (2-3 sentence explanation a 10-year-old could understand)
3. **Prerequisites** (What tools/access you need: browser, curl, Burp Suite, etc.)
4. **Step-by-Step Exploitation:**
   a. Open browser and go to: [exact URL]
   b. In the address bar, type: [exact payload]
   c. Press Enter / Click [specific button]
   d. Look for: [specific visual indicator]
5. **Expected Result** (What success looks like on screen)
6. **If It Doesn't Work** (Troubleshooting: "If you see X instead, try Y")
7. **Real-World Impact** (Why this matters: "An attacker could...")
8. **How to Fix** (Remediation for developers)

IMPORTANT:
- Write for someone who has NEVER coded before
- Use exact URLs, exact commands, exact copy-paste text
- Include screenshots descriptions: "You should see a red error message that says..."
- Use `code blocks` for anything that needs to be typed or copied
- Number every step sequentially
- If a step requires a tool like Burp Suite, explain how to open it first
```

---

## 3. Implementation Plan

### Phase 1: Fix Broken Manual Mode (Immediate)

**Files to modify:**
- `internal/orchestrator/orchestrator.go` — Fix module filtering
- `internal/orchestrator/phase.go` — Add new module constants

**Changes:**
1. Add a lightweight HTTP crawl in manual mode (single GET request to discover endpoints)
2. Fix Headers/CORS modules to work without full crawl (use target URL directly)
3. Run Nuclei WITHOUT `-tags safe` in manual mode
4. Add tool availability checks before running each module

### Phase 2: Integrate Open-Source Tools (Core)

**New file: `internal/attack/manual_tools.go`**

Create wrapper functions for each new tool:
```go
func RunWapitiScan(ctx context.Context, targetURL string, onLog func(string)) ([]NormalizedFinding, error)
func RunCorsyScan(ctx context.Context, targetURL string, onLog func(string)) ([]NormalizedFinding, error)
func RunNiktoScan(ctx context.Context, targetURL string, onLog func(string)) ([]NormalizedFinding, error)
func RunSSLyzeScan(ctx context.Context, targetURL string, onLog func(string)) ([]NormalizedFinding, error)
func RunWhatWebScan(ctx context.Context, targetURL string, onLog func(string)) ([]NormalizedFinding, error)
func RunHTTPxProbe(ctx context.Context, targetURL string, onLog func(string)) ([]NormalizedFinding, error)
```

**Modify: `internal/orchestrator/orchestrator.go`**

Update manual mode module list:
```go
if testingMode == scanv1.TestingMode_TESTING_MODE_MANUAL {
    filteredModules = []string{
        ModuleManualRecon,     // httpx + whatweb
        ModuleManualNuclei,    // nuclei (all templates)
        ModuleManualWapiti,    // wapiti
        ModuleManualDalfox,    // dalfox
        ModuleManualCorsy,     // corsy
        ModuleManualNikto,     // nikto
        ModuleManualSSLyze,    // sslyze
        ModuleManualGuide,     // AI guide generation
    }
}
```

### Phase 3: Finding Aggregation & Filtering

**New file: `internal/orchestrator/finding_aggregator.go`**

```go
type FindingAggregator struct {
    findings []NormalizedFinding
}

func (fa *FindingAggregator) Add(findings []NormalizedFinding)
func (fa *FindingAggregator) Deduplicate() []NormalizedFinding
func (fa *FindingAggregator) RankBySeverity() []NormalizedFinding
func (fa *FindingAggregator) TopN(n int) []NormalizedFinding
func (fa *FindingAggregator) ToAIContext() string
```

**Deduplication logic:**
- Same URL + same category = duplicate → keep highest severity
- Same URL + same parameter = duplicate → merge evidence

**Ranking logic:**
```
CRITICAL (10pts) > HIGH (7pts) > MEDIUM (4pts) > LOW (2pts) > INFO (1pt)
Tiebreaker: exploitability score (tools with PoC = +3pts)
```

### Phase 4: Enhanced AI Guide Generation

**Modify: `internal/orchestrator/orchestrator.go` — `ModuleManualGuide` case**

1. Collect all normalized findings from aggregator
2. Include technology stack context from recon
3. Use enhanced prompt (see section 2.5)
4. Generate guide with structured sections per vulnerability
5. Include a "Quick Reference" table at the top

### Phase 5: Frontend Improvements

**New component: `ToolStatusPanel.tsx`**
```tsx
// Shows real-time status of each tool
// Tool name | Status (pending/running/complete/failed) | Findings count
// Progress bar for overall scan
```

**Enhanced: `ManualGuidePanel.tsx`**
```tsx
// Add:
// - Severity badges (colored pills)
// - Expandable sections per vulnerability
// - Copy-to-clipboard buttons for payloads/URLs
// - "Open in Browser" links for test URLs
// - Findings summary table at top
// - Tool status sidebar
```

**Enhanced: `Dashboard.tsx`**
```tsx
// Manual mode layout:
// ┌─────────────────┬──────────────────┬─────────────────┐
// │  Tool Status    │  Event Timeline  │  Manual Guide   │
// │  (left sidebar) │  (center)        │  (right panel)  │
// │                 │                  │                 │
// │  ✓ httpx        │  [events...]     │  ## Vuln 1      │
// │  ✓ whatweb      │                  │  ### What is... │
// │  ◐ nuclei       │                  │  ### Steps...   │
// │  ○ wapiti       │                  │                 │
// │  ○ dalfox       │                  │  ## Vuln 2      │
// └─────────────────┴──────────────────┴─────────────────┘
```

### Phase 6: Settings & Configuration

**Enhanced: `Settings.tsx`**
```tsx
// Add "Manual Testing Tools" section:
// - Toggle which tools to enable/disable
// - Set timeout per tool
// - Configure Nuclei template severity filter
// - Set maximum findings to include in guide
// - API keys for tools that need them (optional)
```

---

## 4. New REST Endpoints

```go
// GET /api/v1/tools/status — Check which tools are installed
// Response: { "nuclei": true, "wapiti": false, "dalfox": true, ... }

// GET /api/v1/tools/install-guide — Returns install instructions
// Response: { "nuclei": { "install": "go install ...", "check": "nuclei -version" }, ... }

// GET /api/v1/scan/findings?scan_id=xxx — Get normalized findings
// Response: { "findings": [...], "summary": { "critical": 2, "high": 5, ... } }

// POST /api/v1/scan/regenerate-guide — Re-generate guide with different params
// Body: { "scan_id": "...", "max_findings": 10, "focus_categories": ["SQLi", "XSS"] }
```

---

## 5. File Change Summary

| File | Action | Description |
|------|--------|-------------|
| `internal/attack/manual_tools.go` | **CREATE** | Wrapper functions for Wapiti, Corsy, Nikto, SSLyze, WhatWeb, HTTPx |
| `internal/orchestrator/finding_aggregator.go` | **CREATE** | Finding deduplication, ranking, and AI context generation |
| `internal/orchestrator/phase.go` | **MODIFY** | Add new module constants and profile mappings |
| `internal/orchestrator/orchestrator.go` | **MODIFY** | Fix manual mode module list, add new module runners, enhance AI prompt |
| `internal/attack/tools.go` | **MODIFY** | Remove dead code, fix Nuclei tags for manual mode |
| `ui/src/components/dashboard/ManualGuidePanel.tsx` | **MODIFY** | Enhanced guide rendering with severity badges, copy buttons, expandable sections |
| `ui/src/components/dashboard/Dashboard.tsx` | **MODIFY** | 3-column layout for manual mode (tools + timeline + guide) |
| `ui/src/components/dashboard/ToolStatusPanel.tsx` | **CREATE** | Real-time tool status display |
| `ui/src/components/dashboard/FindingsSummary.tsx` | **CREATE** | Severity breakdown table before guide |
| `ui/src/components/settings/Settings.tsx` | **MODIFY** | Add manual testing tool configuration |
| `internal/api/rest_routes.go` | **MODIFY** | Add tool status and findings endpoints |

---

## 6. Dependencies to Add

### Go Dependencies
```bash
# No new Go dependencies needed — all tools are CLI-based
# Existing os/exec wrapper pattern is sufficient
```

### External Tool Installation (User's System)
```bash
# Required for manual testing:
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/hahwul/dalfox/v3@latest
pip install wapiti3
pip install sslyze
git clone https://github.com/s0md3v/Corsy
git clone https://github.com/sullo/nikto
git clone https://github.com/urbanadventurer/WhatWeb
```

---

## 7. Testing Strategy

1. **Unit tests** for `FindingAggregator` (dedup, ranking, top-N)
2. **Unit tests** for each new tool wrapper (mock exec output)
3. **Integration test** with mock tool outputs
4. **Manual testing** against `https://demo.testfire.net/` (AltoroJ test site)
5. **Verify** guide generation produces non-coder-friendly output

---

## 8. Risk Assessment

| Risk | Mitigation |
|------|-----------|
| Tools not installed on user's system | Tool availability check + install guide in Settings |
| Tool execution timeout | Per-tool timeout budgets (3-8 min) + graceful degradation |
| AI generates poor guide | Enhanced prompt + structured output format + retry logic |
| Too many findings overwhelm user | Top-10 filtering + severity ranking + deduplication |
| Windows compatibility | Use `exec.Command` with proper path handling; test on Windows |

---

## 9. Success Criteria

- [ ] Manual mode runs 7+ open-source tools (not just 3)
- [ ] All tools produce real findings (not fake/safe-only results)
- [ ] Findings are deduplicated and ranked by severity
- [ ] Top 10 critical vulnerabilities are selected
- [ ] AI generates step-by-step guide that a non-coder can follow
- [ ] Guide includes exact URLs, payloads, commands, and expected results
- [ ] Frontend shows tool status, findings summary, and interactive guide
- [ ] No Playwright browser required for manual mode
- [ ] Works on Windows with proper tool detection
