# Enhance Browser Service Implementation Plan

## Overview
This plan addresses the statelessness and data poverty of the Browser Service. We will implement a unified session pool to reuse browser contexts across crawl and action requests, and a robust DOM scraping engine to provide the AI service with the structured metadata (links, buttons, forms) it requires for autonomous exploration.

## Scope Definition (CRITICAL)
### In Scope
- Refactoring `browser/src/server.ts` to use a unified session pool.
- Implementing structured DOM scraping in `browser/src/dom.ts`.
- Updating `/action` and `/crawl` endpoints to return/use session data.
- Updating Go client and orchestrator to propagate new metadata.
### Out of Scope (DO NOT TOUCH)
- Modifying the Python AI service logic (only the data it receives).
- Changing the frontend UI (except for handling new event data if necessary, though not requested).
- Database schema changes (not required for these fields).

## Current State Analysis
- **Statelessness**: `browser/src/server.ts:60` launches a new browser for every action.
- **Data Gap**: `internal/orchestrator/orchestrator.go:565` passes only 3 fields to the AI, while the proto defines 13.
- **Scraping**: `browser/src/crawler.ts` has limited link/form extraction; buttons are ignored.

## Implementation Phases

### Phase 1: Unified Session Management (TS)
- **Goal**: Reuse browser instances/contexts per `scanId`.
- **Steps**:
  1. [ ] Create `browser/src/sessions.ts` with a `SessionManager` class.
  2. [ ] Store `BrowserContext` and `Page` objects in a `Map<string, Session>`.
  3. [ ] Implement `getOrCreateSession(scanId, proxyPort)` method.
  4. [ ] Implement a basic TTL cleanup (e.g., 10 minutes of inactivity).
- **Verification**: 
  - Manual: Send two `/action` requests for the same `scanId` and verify the browser isn't relaunched (log check).

### Phase 2: Structured DOM Scraping (TS)
- **Goal**: Extract detailed metadata for AI consumption.
- **Steps**:
  1. [ ] Create `browser/src/dom.ts` with `scrapePageContext(page)` function.
  2. [ ] Implement link extraction (text, href, selector).
  3. [ ] Implement button extraction (text, selector).
  4. [ ] Implement form extraction (action, method, inputs with selectors).
- **Verification**:
  - Test: Run a script to scrape a sample page and verify JSON output structure matches `ai.proto`.

### Phase 3: Browser Service Endpoint Updates (TS)
- **Goal**: Expose new data and use the session pool.
- **Steps**:
  1. [ ] Refactor `/crawl` in `server.ts` to use `SessionManager`.
  2. [ ] Update `runBrowserCrawl` in `crawler.ts` to accept an existing `Page`.
  3. [ ] Refactor `/action` in `server.ts` to use `SessionManager`.
  4. [ ] Enhance `/action` response to include `currentUrl`, `pageTitle`, and `structuredData` (from Phase 2).
- **Verification**:
  - `curl` POST to `/action` and verify the presence of `links`, `buttons`, and `forms` in JSON response.

### Phase 4: Go Backend Integration (Go)
- **Goal**: Propagate enhanced data to the AI service.
- **Steps**:
  1. [ ] Update `internal/browser/client.go`: `ActionResponse` struct and mapping.
  2. [ ] Update `internal/orchestrator/orchestrator.go`: Map `ActionResponse` fields to `DecideBrowserActionRequest`.
  3. [ ] Ensure `last_action`, `last_selector`, and success/error flags are tracked in the orchestrator loop.
- **Verification**:
  - Run the Go orchestrator in `ModuleAuthDiscovery` mode and observe logs showing AI receiving detailed page context.
