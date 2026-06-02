# LastResort Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the current LastResort MVP into a working local-first web application security testing platform that can scan an authorized personal website, capture evidence, show findings, and generate a basic report.

**Architecture:** Keep the existing hybrid architecture: Go owns the daemon, proxy, storage, scanner, and ConnectRPC API; React owns the local operator UI; Python owns AI-assisted analysis. The first production-worthy milestone should be a reliable MVP, not the full long-term autonomous platform described in the PRD.

**Tech Stack:** Go 1.22, SQLite via `modernc.org/sqlite`, ConnectRPC/protobuf, React 19, Vite 6, TypeScript 5.7, Tailwind CSS 4, Python 3.12, gRPC, Gemini/Ollama/mock LLM providers.

---

## Current-State Audit

### What Is Built

- `cmd/lastresort/main.go` starts the local daemon, SQLite database, MITM proxy on port `8080`, ConnectRPC API on port `8443`, and an AI gRPC client for `http://localhost:50052`.
- `internal/storage/db.go`, `flows.go`, and `findings.go` create and write `projects`, `scans`, `http_flows`, and `findings`.
- `internal/api/server.go` implements scan creation, scan start, scan/list, streaming scan events, proxy history, findings, and raw repeater requests.
- `internal/proxy` implements a custom HTTP/HTTPS MITM proxy with a generated root CA, per-host certificates, in-scope filtering, flow capture, and passive findings for missing security headers, session cookie flags, and one CORS misconfiguration.
- `internal/scanner/recon.go` performs root request header/cookie collection, common web port checks, and simple `robots.txt` parsing.
- `internal/crawler` performs static BFS crawling, robots/sitemap parsing, HTML link/form/script extraction, and regex-based JavaScript route discovery.
- `ai/src/server.py` exposes `AnalyzeRecon`, `GenerateHypotheses`, and `ScoreConfidence` over gRPC.
- `ai/src/llm/provider.py` supports mock, Gemini, and Ollama-style providers.
- `ui/src/App.tsx` is a single-page local UI with dashboard, scan start, event console, proxy history, HTTP repeater, findings browser, AI console, and settings.
- `dev.ps1`, `Taskfile.yml`, and `run-lastresort.bat` are local launcher entry points.

### What Is Missing Against `docs/01-PRD.md`

- Browser-based Playwright crawling, session capture, screenshots, DOM XSS monitoring, and multi-account workflows are not implemented.
- Active vulnerability scanning is not implemented beyond passive proxy checks. Missing P0 classes include XSS, SQLi, CSRF, IDOR/BOLA, rate limit, GraphQL basics, and API auth tests.
- Scan profiles are accepted by the API but do not change module execution.
- Pause/stop/resume scan controls are in the proto enums but not implemented as API methods or orchestrator state.
- Reports are not implemented. No HTML/PDF/Markdown/JSON export exists.
- AI hypothesis generation exists in Python but is not used by the Go orchestrator after crawl discovery.
- There is no OOB callback server for SSRF, XXE, or blind XSS correlation.
- Storage is inline table creation, not versioned migrations. There is no schema versioning, FTS search, blob storage, report storage, or finding deduplication.
- UI is a single large `App.tsx` file instead of the component structure described in the architecture docs.
- There are no Go tests, no UI tests, and no Python tests.
- Documentation index references `docs/05` through `docs/10`, but those files are not present.

### Baseline Verification On 2026-06-02

- `go test ./...` passes compile checks for all Go packages, but reports `[no test files]`.
- `npm run build` succeeds for the React UI.
- Python compile check succeeds for `ai/src/server.py` and `ai/src/llm/provider.py`.
- `ai/.venv/Scripts/python.exe`, `ui/node_modules`, and `lastresort.exe` exist.

---

## File Structure To Create Or Modify

- Modify: `proto/scan/v1/scan.proto` - add scan controls, report APIs, module config, endpoint records, and richer findings.
- Modify: `proto/ai/v1/ai.proto` - add business-logic plan, report narrative, and endpoint-hypothesis messages.
- Modify: `cmd/lastresort/main.go` - add static UI serving option, graceful shutdown, AI health reporting, OOB startup, and browser launch flags.
- Modify: `internal/api/server.go` - split scan/proxy/finding/report handlers after API expansion.
- Create: `internal/api/scan_service.go` - scan lifecycle methods.
- Create: `internal/api/proxy_service.go` - proxy history and repeater methods.
- Create: `internal/api/finding_service.go` - finding listing, false-positive marking, dedup actions.
- Create: `internal/api/report_service.go` - report generation and export methods.
- Modify: `internal/orchestrator/orchestrator.go` - make phases profile-aware and cancellable.
- Create: `internal/orchestrator/phase.go` - named phase definitions and progress weights.
- Create: `internal/orchestrator/cancellation.go` - pause/stop support.
- Create: `internal/scanner/scanner.go` - common scanner module interface.
- Create: `internal/scanner/insertion.go` - insertion point extraction.
- Create: `internal/scanner/headers.go` - security header scanner moved from passive analyzer into reusable module.
- Create: `internal/scanner/cors.go` - CORS tests.
- Create: `internal/scanner/xss.go` - reflected XSS smoke tests.
- Create: `internal/scanner/sqli.go` - SQLi smoke tests.
- Create: `internal/scanner/csrf.go` - CSRF token checks.
- Create: `internal/scanner/idor.go` - manual multi-account comparison foundation.
- Create: `internal/scanner/ratelimit.go` - conservative rate-limit probe.
- Create: `internal/oob/server.go` - local HTTP callback server.
- Create: `internal/oob/correlator.go` - callback token mapping.
- Create: `internal/report/generator.go` - HTML/Markdown/JSON report generation.
- Create: `internal/report/templates/default.html` - local report template.
- Modify: `internal/storage/db.go` - replace inline schema with migrations.
- Create: `internal/storage/migrations/001_initial.sql` - current schema.
- Create: `internal/storage/migrations/002_scan_modules.sql` - scan modules, endpoints, report tables.
- Create: `internal/storage/endpoints.go` - discovered endpoint CRUD.
- Create: `internal/storage/reports.go` - report CRUD.
- Create: `internal/storage/dedupe.go` - finding fingerprinting.
- Create: `browser/package.json` - Playwright automation service package.
- Create: `browser/src/server.ts` - HTTP/JSON or gRPC bridge for browser crawl requests.
- Create: `browser/src/crawler.ts` - Playwright SPA crawler.
- Create: `browser/src/capture.ts` - request/response capture.
- Create: `browser/src/screenshot.ts` - evidence screenshots.
- Modify: `ai/src/server.py` - add report narrative and business-logic planning RPCs.
- Create: `ai/src/prompts/report.py` - report narrative prompt.
- Create: `ai/src/prompts/business_logic.py` - business-logic scenario prompt.
- Modify: `ui/src/App.tsx` - split into components after API is stable.
- Create: `ui/src/api/client.ts` - shared ConnectRPC client.
- Create: `ui/src/components/layout/MainLayout.tsx` - shell layout.
- Create: `ui/src/components/dashboard/Dashboard.tsx` - target and scan summary.
- Create: `ui/src/components/proxy/ProxyHistory.tsx` - proxy table/detail split.
- Create: `ui/src/components/editor/HttpRepeater.tsx` - raw request editor.
- Create: `ui/src/components/findings/FindingsBrowser.tsx` - findings table/detail split.
- Create: `ui/src/components/reports/ReportGenerator.tsx` - report generation UI.
- Create: `ui/src/components/settings/Settings.tsx` - CA path, ports, AI provider state.
- Create: `tests/fixtures/target_app.go` - local vulnerable test target for repeatable scanner tests.

---

## Milestone 1: Make The MVP Reliable

### Task 1: Add Backend Test Harness

**Files:**
- Create: `tests/fixtures/target_app.go`
- Create: `internal/proxy/proxy_test.go`
- Create: `internal/crawler/crawler_test.go`
- Create: `internal/scanner/recon_test.go`
- Create: `internal/storage/storage_test.go`

- [ ] **Step 1: Create a deterministic local test target**

Add a Go `httptest` helper with these routes: `/`, `/login`, `/dashboard`, `/api/users/1`, `/api/users/2`, `/search?q=`, `/unsafe-cors`, `/set-cookie`, `/robots.txt`, `/sitemap.xml`, and `/static/app.js`.

Expected behavior:
- `/set-cookie` returns `Set-Cookie: sessionid=abc123; Path=/` so passive cookie findings can be tested.
- `/unsafe-cors` returns `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Credentials: true`.
- `/static/app.js` contains `fetch("/api/users/1")` and `"/hidden-admin"`.

- [ ] **Step 2: Test storage initialization and inserts**

Run: `go test ./internal/storage -run Test -v`

Expected: tests prove `InitDB`, `SaveFlow`, and `SaveFinding` persist rows in an isolated temporary database.

- [ ] **Step 3: Test crawler discovery**

Run: `go test ./internal/crawler -run Test -v`

Expected: crawler discovers root links, sitemap URLs, robots disallow paths, and JS-discovered API paths without leaving host scope.

- [ ] **Step 4: Test passive proxy analyzer findings**

Run: `go test ./internal/proxy -run TestPassive -v`

Expected: missing security headers, insecure session cookie flags, and bad CORS findings are saved once per tested response after dedupe is added in Task 2.

- [ ] **Step 5: Run full Go baseline**

Run: `go test ./...`

Expected: all packages pass with real tests.

### Task 2: Add Finding Deduplication

**Files:**
- Modify: `internal/storage/db.go`
- Create: `internal/storage/dedupe.go`
- Modify: `internal/storage/findings.go`
- Test: `internal/storage/storage_test.go`

- [ ] **Step 1: Add a stable finding fingerprint column**

Add `fingerprint TEXT` and a unique index on `(scan_id, fingerprint)` to the findings table.

- [ ] **Step 2: Implement deterministic fingerprints**

Fingerprint input must be `scan_id`, `vulnerability_type`, `endpoint`, and normalized `title`.

- [ ] **Step 3: Change `SaveFinding` to upsert**

If a duplicate fingerprint exists, update `confidence`, `response_status`, and `created_at` instead of inserting a duplicate row.

- [ ] **Step 4: Verify dedupe**

Run: `go test ./internal/storage -run TestSaveFindingDeduplicates -v`

Expected: saving the same finding twice leaves one row.

### Task 3: Add Real Health Checks

**Files:**
- Modify: `cmd/lastresort/main.go`
- Modify: `ai/src/server.py`
- Modify: `proto/ai/v1/ai.proto`
- Modify generated proto files after running codegen.

- [ ] **Step 1: Add AI health RPC**

Add `rpc Health(HealthRequest) returns (HealthResponse)` to `proto/ai/v1/ai.proto`.

- [ ] **Step 2: Implement Python health response**

Return provider name, model name, and whether the provider initialized without fallback.

- [ ] **Step 3: Update Go `/health`**

Return JSON with `db`, `proxy`, `ai.status`, `ai.provider`, `ai.model`, and `version`.

- [ ] **Step 4: Verify API health**

Run the AI service, run `go run cmd/lastresort/main.go serve`, then run:

```powershell
Invoke-RestMethod http://localhost:8443/health
```

Expected: JSON includes `db: connected`, `proxy: listening`, and `ai.status`.

---

## Milestone 2: Finish Core Scanning

### Task 4: Make Scan Profiles Execute Different Modules

**Files:**
- Modify: `proto/scan/v1/scan.proto`
- Modify: `internal/orchestrator/orchestrator.go`
- Create: `internal/orchestrator/phase.go`
- Create: `internal/scanner/scanner.go`

- [ ] **Step 1: Define scan modules**

Use these module names: `recon`, `crawl_static`, `passive`, `headers`, `cors`, `xss_reflected`, `sqli_basic`, `csrf_basic`, `rate_limit_basic`, `ai_hypotheses`, `report`.

- [ ] **Step 2: Map profiles**

Use this exact MVP mapping:
- `QUICK`: `recon`, `crawl_static`, `passive`, `headers`, `cors`, `report`
- `STANDARD`: quick modules plus `xss_reflected`, `sqli_basic`, `csrf_basic`, `ai_hypotheses`
- `DEEP`: standard modules plus `rate_limit_basic`

- [ ] **Step 3: Persist enabled modules**

Store module execution status in a `scan_modules` table with columns `scan_id`, `module`, `status`, `started_at`, `finished_at`, `error`.

- [ ] **Step 4: Verify profile execution**

Run: `go test ./internal/orchestrator -run TestProfileModuleSelection -v`

Expected: each profile expands to the exact module list above.

### Task 5: Persist Discovered Endpoints

**Files:**
- Modify: `internal/storage/db.go`
- Create: `internal/storage/endpoints.go`
- Modify: `internal/crawler/crawler.go`
- Modify: `proto/scan/v1/scan.proto`
- Modify: `internal/api/server.go`

- [ ] **Step 1: Add `endpoints` table**

Columns: `id`, `scan_id`, `method`, `url`, `source`, `status_code`, `content_type`, `first_seen_at`, `last_seen_at`, `fingerprint`.

- [ ] **Step 2: Save endpoints during crawl**

Every `DiscoveredEndpoint` must be persisted before it is published to the UI.

- [ ] **Step 3: Add `ListEndpoints` API**

Return all endpoints for a scan ordered by `source`, then `url`.

- [ ] **Step 4: Verify endpoint persistence**

Run: `go test ./internal/crawler ./internal/storage -run TestEndpoint -v`

Expected: JS and sitemap endpoints are written once per scan.

### Task 6: Implement Basic Active Scanners

**Files:**
- Create: `internal/scanner/insertion.go`
- Create: `internal/scanner/xss.go`
- Create: `internal/scanner/sqli.go`
- Create: `internal/scanner/csrf.go`
- Create: `internal/scanner/cors.go`
- Create: `internal/scanner/headers.go`
- Create: `internal/scanner/ratelimit.go`
- Modify: `internal/orchestrator/orchestrator.go`

- [ ] **Step 1: Extract insertion points**

Support URL query parameters, form actions from crawled HTML, JSON body fields when a captured flow has `Content-Type: application/json`, and cookies.

- [ ] **Step 2: Add reflected XSS smoke test**

Use payload `<lr-xss-test>` first. Save a finding only when the exact payload is reflected unencoded in an HTML response.

- [ ] **Step 3: Add SQLi smoke test**

Use payloads `'`, `"`, `')`, and `1 OR 1=1`. Save a finding only when response contains a known database error marker such as `SQL syntax`, `SQLite`, `PostgreSQL`, `MySQL`, `ORA-`, or `ODBC`.

- [ ] **Step 4: Add CSRF basic check**

For state-changing forms and captured POST/PUT/PATCH/DELETE requests, save a low-confidence finding when no hidden token, `csrf` field, `xsrf` field, or anti-CSRF header appears.

- [ ] **Step 5: Add conservative rate-limit probe**

Send 10 requests to the same endpoint with a 100 ms delay. Save an informational finding when all requests return 2xx/3xx without any 429, lockout, or throttling signal.

- [ ] **Step 6: Verify active scanner modules**

Run: `go test ./internal/scanner -run Test -v`

Expected: scanners create findings against the local fixture and avoid findings against safe fixture routes.

---

## Milestone 3: Browser And Evidence

### Task 7: Add Playwright Browser Service

**Files:**
- Create: `browser/package.json`
- Create: `browser/tsconfig.json`
- Create: `browser/src/server.ts`
- Create: `browser/src/crawler.ts`
- Create: `browser/src/capture.ts`
- Create: `browser/src/screenshot.ts`
- Modify: `Taskfile.yml`
- Modify: `run-lastresort.bat`

- [ ] **Step 1: Create browser service package**

Install dependencies: `playwright`, `typescript`, `tsx`, and `@types/node`.

- [ ] **Step 2: Implement `/crawl` endpoint**

Accept JSON `{ "scanId": "...", "targetUrl": "...", "proxyPort": 8080 }`.

- [ ] **Step 3: Launch Chromium through the MITM proxy**

Use a persistent context with `--proxy-server=http://127.0.0.1:8080`.

- [ ] **Step 4: Capture requests and screenshots**

Return discovered URLs and screenshot file paths under `data/screenshots/<scan_id>/`.

- [ ] **Step 5: Verify browser crawl**

Run: `npm --prefix browser test` after adding a basic Playwright fixture.

Expected: service returns at least root URL and one clicked link for a local fixture app.

### Task 8: Wire Browser Crawl Into Go

**Files:**
- Modify: `internal/orchestrator/orchestrator.go`
- Create: `internal/browser/client.go`
- Modify: `internal/storage/endpoints.go`

- [ ] **Step 1: Add browser client**

Create a Go client that POSTs crawl requests to `http://localhost:50053/crawl`.

- [ ] **Step 2: Run browser crawl after static crawl**

Only run it for `STANDARD` and `DEEP` profiles.

- [ ] **Step 3: Save browser-discovered endpoints**

Use source `browser`.

- [ ] **Step 4: Verify browser fallback**

Run Go tests with the browser service disabled.

Expected: `QUICK` scans and static crawling still work when browser service is offline.

---

## Milestone 4: Reporting

### Task 9: Add Report Storage And Export

**Files:**
- Create: `internal/report/generator.go`
- Create: `internal/report/templates/default.html`
- Create: `internal/storage/reports.go`
- Modify: `proto/scan/v1/scan.proto`
- Create: `internal/api/report_service.go`

- [ ] **Step 1: Add `reports` table**

Columns: `id`, `scan_id`, `format`, `path`, `title`, `created_at`.

- [ ] **Step 2: Generate Markdown report**

Include target, scan status, detected technologies, auth model, finding counts by severity, each finding, evidence URL, payload, confidence, and remediation text.

- [ ] **Step 3: Generate HTML report**

Render Markdown content into a simple dark HTML report saved under `data/reports/<scan_id>/report.html`.

- [ ] **Step 4: Add `GenerateReport` API**

Return report ID and absolute file path.

- [ ] **Step 5: Verify report generation**

Run: `go test ./internal/report ./internal/api -run TestGenerateReport -v`

Expected: generated report file exists and contains at least one seeded finding.

### Task 10: Use AI For Narrative, Not Blocking Execution

**Files:**
- Modify: `proto/ai/v1/ai.proto`
- Modify: `ai/src/server.py`
- Create: `ai/src/prompts/report.py`
- Modify: `internal/report/generator.go`

- [ ] **Step 1: Add `GenerateFindingNarrative` RPC**

Input: vulnerability type, title, endpoint, evidence, confidence. Output: concise description and remediation.

- [ ] **Step 2: Call AI with timeout**

Use a 10-second timeout per finding. If AI fails, use deterministic fallback text.

- [ ] **Step 3: Verify fallback**

Run report tests with AI service offline.

Expected: report still generates with fallback narratives.

---

## Milestone 5: Frontend Refactor And UX Completion

### Task 11: Split `App.tsx` Into Components

**Files:**
- Modify: `ui/src/App.tsx`
- Create: `ui/src/api/client.ts`
- Create: `ui/src/components/layout/MainLayout.tsx`
- Create: `ui/src/components/dashboard/Dashboard.tsx`
- Create: `ui/src/components/proxy/ProxyHistory.tsx`
- Create: `ui/src/components/editor/HttpRepeater.tsx`
- Create: `ui/src/components/findings/FindingsBrowser.tsx`
- Create: `ui/src/components/reports/ReportGenerator.tsx`
- Create: `ui/src/components/settings/Settings.tsx`

- [ ] **Step 1: Move ConnectRPC client**

Export one configured client from `ui/src/api/client.ts`.

- [ ] **Step 2: Extract layout**

Move sidebar, header, and system indicators into `MainLayout`.

- [ ] **Step 3: Extract each tab**

Each tab component receives only the props it needs and owns its local UI state.

- [ ] **Step 4: Verify UI build**

Run: `npm run build` from `ui/`.

Expected: TypeScript and Vite build succeed.

### Task 12: Add Report And Endpoint Views

**Files:**
- Create: `ui/src/components/endpoints/EndpointMap.tsx`
- Create: `ui/src/components/reports/ReportGenerator.tsx`
- Modify: `ui/src/App.tsx`

- [ ] **Step 1: Add endpoint map tab**

Show method, URL, source, status, and content type.

- [ ] **Step 2: Add report generator tab**

Button calls `GenerateReport`, then displays the report path and opens it in a new browser tab if served by the Go daemon.

- [ ] **Step 3: Add empty and error states**

Every tab must show a concrete offline state when `goDaemonStatus` is disconnected.

- [ ] **Step 4: Verify UI behavior**

Run `npm run build`.

Expected: build passes and no tab relies on undefined data.

---

## Milestone 6: Local Launcher And Personal Website Testing

### Task 13: Harden The Windows Launcher

**Files:**
- Modify: `run-lastresort.bat`
- Modify: `dev.ps1`
- Modify: `Taskfile.yml`

- [ ] **Step 1: Check prerequisites**

Check for `go`, `node`, `npm`, and `ai/.venv/Scripts/python.exe`.

- [ ] **Step 2: Start services in named windows**

Start Python AI service, Go backend, and Vite UI.

- [ ] **Step 3: Wait for health endpoints**

Poll `http://localhost:8443/health` and `http://localhost:5173`.

- [ ] **Step 4: Open browser**

Open `http://localhost:5173` after both endpoints respond.

- [ ] **Step 5: Verify from a clean shell**

Double-click `run-lastresort.bat`.

Expected: three terminal windows stay open, the browser opens to the UI, and the UI health indicator shows the Go daemon connected.

### Task 14: Add Personal-Website Test Checklist

**Files:**
- Create: `docs/personal-website-test-checklist.md`

- [ ] **Step 1: Document authorized scan setup**

Include target URL format, scope warning, and scan profile selection.

- [ ] **Step 2: Document proxy browser setup**

Include proxy `127.0.0.1:8080` and CA certificate path `data/certs/ca.crt`.

- [ ] **Step 3: Document expected MVP outputs**

Expected outputs: scan row, event stream, crawled routes, proxy flows, passive findings, and report file.

---

## Final Verification Checklist

- [ ] Run `go test ./...`.
- [ ] Run `npm run build` in `ui/`.
- [ ] Run `python -m py_compile ai/src/server.py ai/src/llm/provider.py` using the AI virtual environment.
- [ ] Start services with `run-lastresort.bat`.
- [ ] Open `http://localhost:5173`.
- [ ] Run a `QUICK` scan against an authorized local or personal website.
- [ ] Confirm at least one scan record, one event stream, and one endpoint row.
- [ ] Configure browser proxy to `127.0.0.1:8080` and confirm proxy history captures an authorized page load.
- [ ] Generate a report and confirm it exists under `data/reports/<scan_id>/`.

---

## Execution Order

1. Milestone 1: tests, dedupe, health.
2. Milestone 2: profile-aware scan phases and basic active scanners.
3. Milestone 4: reports, because the user needs visible scan output.
4. Milestone 5: frontend split and report/endpoints UI.
5. Milestone 3: Playwright browser service, because it is larger and should be added after the static MVP is stable.
6. Milestone 6: launcher hardening and personal website checklist.

Plan complete and saved to `docs/superpowers/plans/2026-06-02-lastresort-completion-plan.md`. Recommended execution path: implement Milestone 1 first, then re-run the baseline verification before adding scanner modules.
