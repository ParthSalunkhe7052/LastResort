# LastResort In-Depth Audit and Implementation Plan

Date: 2026-06-06

## Executive Summary

The docs describe a pivot from a proxy/repeater-driven scanner to an autonomous, browser-first pentesting agent: AI plans attacks, Playwright executes them, DOM/browser state verifies them, and evidence is stored as a first-class artifact. The current codebase partially implements that direction, but it is still a hybrid system with duplicated attack paths, stale proxy-era contracts, missing runtime tables, and a frontend that displays several important values incorrectly.

Compile-level health is good: `go test ./...`, `go build ./cmd/lastresort`, `npm run build` in `ui`, and `npm run build` in `browser` all pass. The app is not error-free at runtime because the tests do not cover end-to-end scan execution, report evidence integrity, UI/API field compatibility, or removed proxy dependencies.

## Intended Product From Docs

The intended app is an autonomous browser pentesting agent:

- The orchestrator owns scan phases and drives the end-to-end workflow.
- Playwright is the primary execution environment for crawl, auth discovery, attack execution, screenshots, DOM capture, cookies, local storage, and network feedback.
- AI should be used for contextual planning and verification, not only reporting.
- Findings should move through states: observation, hypothesis, attempt, verified finding.
- Verified findings require concrete evidence: request, response/DOM, screenshot/browser event, confidence, verification method, and replayable steps.
- Deprecated manual proxy/repeater flows should not be part of the core product.

## What Is Actually Built

### Backend

- `cmd/lastresort/main.go` starts one Go daemon, SQLite storage, the Go-native AI client, ConnectRPC scan APIs, REST extension APIs, and static report serving.
- `browser/` is a separate Playwright HTTP service with `/crawl`, `/action`, `/health`, session isolation by scan ID, worker pages, screenshots, DOM capture, cookies, local storage, AX tree extraction, and dialog detection for XSS.
- `internal/orchestrator/orchestrator.go` owns almost all scan behavior: profiles, module scheduling, crawling, auth discovery, deterministic attacks, AI SQLi agent, external tool wrappers, verification, report generation, and event publishing.
- `internal/attack/sql_agent.go` implements a real AI SQLi loop, but only for SQLi.
- `internal/attack/engine.go` still contains a separate no-op planner/verifier and HTTP executor abstraction that is not the real execution path.
- `internal/scanner/` still contains static payload repositories and direct HTTP scanners. Some are marked deprecated but remain active.
- `internal/storage/` now has useful evidence, verification, attack attempts, journal, replay, forms, endpoints, settings, metrics, and report tables.

### Frontend

- `ui/src/App.tsx` is the only mounted shell for dashboard/settings.
- `ui/src/components/dashboard/Dashboard.tsx` is the primary UX and contains launch form, history, live browser spectator, event timeline, findings, verification pipeline, module status, metrics, and report iframe.
- `EndpointMap`, `FindingsBrowser`, and `ReportGenerator` still exist but are not mounted.
- The UI talks to both ConnectRPC and REST endpoints directly with hard-coded `http://127.0.0.1:8443`.

## Major Broken or Misaligned Areas

### 1. CSRF Module Is Runtime-Broken

`runAgentCsrf` queries `http_flows`, but `internal/proxy` and `internal/storage/flows.go` were deleted and `InitDB` no longer creates `http_flows`. Standard scans include `csrf_basic`, so this module will fail at runtime with `no such table: http_flows`.

Required change: make CSRF derive state-changing surfaces from `forms`, `endpoints`, browser network events, and attack attempts instead of proxy flows.

### 2. Rate Limit Module Still Uses Deprecated Direct HTTP Path

`internal/scanner/ratelimit.go` says `ScanRateLimit` is deprecated and should be replaced by browser-aware `runAgentRateLimit`, but `runModule` still calls `as.ScanRateLimit`. The verification engine has `VerifyRateLimit`, but no orchestrator path feeds it the expected DOM marker.

Required change: implement browser-based rate limit execution and remove the active deprecated path from profiles.

### 3. SQLi Runs Twice in Standard and Deep Profiles

`ProfileModules` includes both `sqli_basic` and `sqli_agent`. `sqli_basic` is already browser-executed but static payload-based; `sqli_agent` uses AI-planned SQLi. Running both causes duplicate attacks, duplicated findings, inconsistent logs, and more risk against targets.

Required change: choose one SQLi module. Keep the AI agent path and fold deterministic fallback into it as a fallback stage, not a separate profile module.

### 4. Attack Architecture Is Split Across Three Places

Attack behavior is spread across:

- `internal/orchestrator/orchestrator.go`: real browser attack execution for SQLi, XSS, CSRF, path traversal.
- `internal/attack/sql_agent.go`: AI SQLi execution loop.
- `internal/attack/engine.go`: no-op interfaces and direct HTTP executor.
- `internal/scanner/payloads.go`: static payload catalog.

This contradicts the intended architecture because there is no single attack contract for planner, executor, verifier, journal, evidence, and replay.

Required change: create one `AttackModule` interface implemented per vulnerability family. Each module should produce attempts and verification results through shared browser/evidence services.

### 5. AI Planning Is SQLi-Only

`proto/ai/v1/ai.proto` exposes `PlanSQLiAttack` and `VerifyAttackResult`, but there is no general `PlanAttack` contract for XSS, CSRF, path traversal, auth, or rate limit. XSS/path traversal are browser-executed but still static payload-driven.

Required change: replace `PlanSQLiAttack` with a generic attack-planning RPC or add a backend-local planner interface that can support AI and deterministic planners.

### 6. Settings UI Does Not Control the AI Client

`Settings.tsx` saves `ai_provider` and `gemini_model` into SQLite, but `internal/ai/client.go` reads only environment variables and hard-codes provider/model behavior. The health endpoint also reports `gemini-2.5-flash`, while the UI defaults to `gemini-3.5-flash`.

Required change: make AI configuration a backend service concern. Store provider/model/key-source settings consistently and have `LocalServiceClient` read effective settings from storage or a validated config object.

### 7. Frontend Metrics Use Wrong Field Names

The backend returns `pages_crawled`, `attack_attempts`, and `scan_duration`. The dashboard reads `visited_pages`, `fuzz_requests`, and `elapsed_seconds`, so the UI shows zeros even when metrics exist.

Required change: align dashboard metric names with `ScanPerformanceMetrics` or change the API response to the names the UI expects.

### 8. Backend Metrics Count Wrong Finding Categories

Storage uses `VERIFIED_FINDING`, `POTENTIAL_FINDING`, `NEEDS_REVIEW`, and `OBSERVATION`. The API maps some values to UI categories like `VERIFIED_ATTACK`, but `GetScanPerformance` queries `VERIFIED_ATTACK` and `ATTEMPT` directly from storage. Successful and failed attack counts are therefore wrong.

Required change: keep one canonical category enum across storage, API, report, and UI.

### 9. Report Evidence Falls Back Silently

`report/generator.go` still attempts to join `finding_evidence` to `http_flows`. Since `http_flows` is gone, raw requests/responses are silently blank. The report can look successful while omitting proof details.

Required change: generate reports from `finding_evidence`, `attack_attempts`, `attack_verifications`, and `attack_replays`, not proxy flow rows.

### 10. Auth Cookie Input Is Dead UI

The dashboard has a "Session Authentication Cookie" input stored only in local React state. It is never sent to `CreateScan`, saved to `scans.auth_cookies`, or applied to the browser context.

Required change: either remove the field or implement `auth_cookies` in scan creation and browser session initialization.

### 11. Scope Patterns Are Accepted But Ignored

`ScanConfig.scope_patterns` exists in proto and the UI sends an empty list, but storage does not persist scope and the crawler/orchestrator only use target-host checks.

Required change: persist scan scope and pass it into crawler, browser, tool wrappers, and attack modules.

### 12. Deprecated API Surface Still Exists

`ListFlows` and `SendRepeaterRequest` remain in `scan.proto`; one returns empty data and the other returns unimplemented. Generated frontend code still includes them. The docs explicitly call repeater/proxy drift a problem.

Required change: remove these RPCs in a breaking proto cleanup or move them behind a separate legacy/debug API.

### 13. Dead or Unmounted Frontend Components

`EndpointMap`, `FindingsBrowser`, and `ReportGenerator` are not mounted. Their responsibilities are partially duplicated inside `Dashboard.tsx`.

Required change: either recompose the dashboard from these components or delete them after their useful pieces are folded into the active UI.

### 14. Large God Files Are Blocking Maintainability

`internal/orchestrator/orchestrator.go` is roughly 80 KB and `Dashboard.tsx` is roughly 43 KB. Both combine orchestration, domain logic, presentation state, and feature-specific behavior.

Required change: split by responsibility after stabilizing behavior:

- backend: scheduler, module runner, attack surface builder, browser executor, evidence writer, report runner, auth discovery.
- frontend: launch form, live browser, event timeline, findings/evidence panel, module status, reports, metrics.

### 15. External Tool Findings Are Over-Trusted

SQLMap, Dalfox, and Nuclei findings are saved as verified with `VerificationDOMMarker` even though they are tool outputs, not browser DOM verification. This weakens the evidence model.

Required change: classify external tool output as `POTENTIAL_FINDING` unless a browser or deterministic verifier replays and verifies it.

### 16. Tests Do Not Cover Runtime Product Flows

Current tests pass, but they miss:

- starting a standard scan against a fixture app;
- CSRF module behavior without `http_flows`;
- report evidence generation after proxy removal;
- UI/API metric field compatibility;
- category mapping consistency;
- browser service unavailable behavior;
- duplicated SQLi execution;
- settings actually affecting AI client behavior.

Required change: add fixture-driven integration tests and contract tests.

## Target Architecture

Use a single browser-first scan pipeline:

1. Scan configuration is created with target URL, profile, scope, optional auth cookies, and AI settings reference.
2. Orchestrator runs profile modules through a small scheduler.
3. Discovery modules populate endpoints, forms, browser context snapshots, and network observations.
4. Attack surface builder creates normalized `AttackSurface` records from endpoints/forms/network events.
5. Each attack module follows the same contract:
   - plan attempts;
   - execute attempts through `BrowserExecutor`;
   - capture request/response/DOM/screenshot/network events;
   - verify with deterministic rules and optional AI;
   - persist attempt, verification, evidence, replay;
   - emit events.
6. Reports and UI read from persisted evidence/verification/replay records only.
7. Deprecated proxy/repeater contracts are removed from the primary API.

## Prioritized Implementation Plan

### P0: Stabilize Runtime Correctness

1. Replace CSRF dependency on `http_flows`.
   - Build CSRF candidates from `forms` where method is POST/PUT/PATCH/DELETE.
   - Include endpoint records with mutative methods once network capture persistence exists.
   - Run through browser form submission and `VerifyCSRF`.
   - Add test proving standard scan does not fail on a fresh DB.

2. Fix metrics contract.
   - Update dashboard fields to `pages_crawled`, `attack_attempts`, and `scan_duration`.
   - Fix backend category counts to use storage categories.
   - Count forms from the `forms` table, not `endpoints source = browser_form`.

3. Fix report evidence.
   - Remove `http_flows` join.
   - Render raw request/response from `finding_evidence`, `attack_attempts`, and verification artifacts.
   - Add a report test with a verified finding and no proxy tables.

4. Remove duplicate SQLi profile execution.
   - Keep one SQLi module in standard/deep profiles.
   - Move static payload fallback inside the AI SQLi module.
   - Add a profile test asserting SQLi appears once.

5. Make browser service availability explicit.
   - At scan start, check `/health` for profiles requiring browser execution.
   - Fail early with actionable module error if the browser service is offline.

### P1: Unify Attack Execution Architecture

1. Introduce `internal/attack/module.go`.
   - Define `AttackModule`, `Planner`, `BrowserExecutor`, `Verifier`, and `EvidenceRecorder` contracts.
   - Move attack-surface building out of `orchestrator.go`.

2. Convert SQLi to the shared module contract.
   - Keep AI planner.
   - Use deterministic payloads only when AI is unavailable or returns invalid output.
   - Save every attempt, failed verification, and successful verification.

3. Convert XSS and path traversal.
   - Use same browser executor and verification output shape.
   - Remove copy-pasted save/update verification code from orchestrator.

4. Implement browser-aware rate limit module.
   - Execute controlled burst through Playwright/fetch inside page context.
   - Inject `lastresort-ratelimit-results`.
   - Feed DOM marker to `VerifyRateLimit`.

5. Reclassify external tool findings.
   - Save SQLMap/Dalfox/Nuclei as potential findings.
   - Promote only after replay/browser verification.

### P2: Clean API and Data Model

1. Remove or isolate deprecated flow/repeater RPCs.
   - Delete `ListFlows` and `SendRepeaterRequest` from primary proto.
   - Regenerate Go and TypeScript code.
   - Delete duplicate `ui/src/gen/proto/**` if not used.

2. Normalize finding states.
   - Pick one enum: `OBSERVATION`, `HYPOTHESIS`, `ATTEMPT`, `VERIFIED_ATTACK`, `FALSE_POSITIVE`.
   - Migrate storage/API/UI/report to the same values.

3. Persist scan scope and auth input.
   - Add storage columns or child table for scope patterns.
   - Add optional auth cookies to create scan or a dedicated scan auth endpoint.
   - Apply cookies before crawl/auth/attack browser sessions.

4. Make settings real.
   - Backend loads effective AI settings from storage/env.
   - Health endpoint reports the effective provider/model.
   - UI only shows supported providers/models.

### P3: Frontend Refactor

1. Split `Dashboard.tsx`.
   - `ScanLaunchForm`
   - `ScanHistory`
   - `LiveBrowserPanel`
   - `EventTimeline`
   - `FindingProofPanel`
   - `VerificationPanel`
   - `ModuleStatusPanel`
   - `ReportPanel`

2. Remove dead UI or remount it intentionally.
   - Fold useful `EndpointMap`, `FindingsBrowser`, and `ReportGenerator` pieces into the new dashboard components.
   - Delete unused assets and duplicate generated clients.

3. Add API client wrappers.
   - Centralize REST and ConnectRPC base URL handling.
   - Use one typed client layer instead of direct fetch calls scattered across components.

4. Improve labels to match product reality.
   - Replace "Simulation", "Manual Proofs", and "AI pipeline" where they obscure actual scan state.
   - Show "Potential", "Attempted", and "Verified" distinctly.

### P4: Test and Release Hardening

1. Add end-to-end fixture scan tests.
   - Start fixture target.
   - Start browser service or mock browser service.
   - Create and run quick/standard scans.
   - Assert module statuses, findings, verifications, metrics, and report output.

2. Add frontend contract tests.
   - Mock backend responses for metrics, modules, findings, verifications.
   - Assert dashboard renders non-zero values and category names correctly.

3. Add migration tests.
   - Fresh DB.
   - Older DB with legacy columns.
   - DB without proxy tables.

4. Add smoke script.
   - One command starts backend, browser service, UI, and fixture app.
   - One command runs a standard scan and validates outputs.

## Dead Code and Cleanup List

- `internal/attack/engine.go`: keep only if it becomes the real shared attack contract; otherwise delete no-op planner/verifier and HTTP executor.
- `internal/scanner/ratelimit.go`: remove after browser-aware rate limit module lands.
- `internal/scanner/csrf.go`: keep heuristic only if used by browser CSRF module; otherwise move heuristic into attack module.
- `proto/scan/v1/scan.proto`: remove deprecated repeater/flow RPCs from primary service.
- `ui/src/components/endpoints/EndpointMap.tsx`: remount or delete.
- `ui/src/components/findings/FindingsBrowser.tsx`: remount or delete.
- `ui/src/components/reports/ReportGenerator.tsx`: remount or delete.
- `ui/src/gen/proto/**`: appears duplicate and unused; delete after proto generation is cleaned.
- `Taskfile.yml`: remove deleted Python AI service commands and fix proto generation paths.
- `docs/personal-website-test-checklist.md`: update proxy/repeater guidance after architecture cleanup.

## Recommended First Sprint

Do P0 only:

1. Fix CSRF no-table failure.
2. Fix metrics category and JSON mismatches.
3. Fix report evidence source.
4. Remove duplicate SQLi execution.
5. Add integration tests proving a standard scan can complete against the fixture app without proxy tables.

Do not start broad frontend redesign until P0 is green. The frontend can only be made trustworthy after the backend emits consistent categories, metrics, evidence, and scan module states.

