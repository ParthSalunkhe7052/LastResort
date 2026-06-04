# Research: Enhance Browser Service

**Date**: 2026-06-03

## 1. Executive Summary
The Browser Service (Playwright/Express) currently operates in a stateless manner and lacks detailed DOM metadata extraction. Every request to `/crawl` or `/action` initializes a fresh browser instance. The structured data required by the AI service (links, buttons, forms) is partially extracted during `/crawl` but entirely missing from the `/action` response.

## 2. Technical Context
- **Current Browser Launching**: `browser/src/server.ts:25` (crawl) and `browser/src/server.ts:60` (action) both use `chromium.launch` on every request.
- **Scraping Logic**: `browser/src/crawler.ts:145-177` extracts links and forms using `page.evaluate`.
- **Action Response**: `browser/src/server.ts:100-104` returns `screenshot`, `pageSource`, and `success`.
- **Orchestrator Integration**: `internal/orchestrator/orchestrator.go:565` instantiates `DecideBrowserActionRequest` with only three fields: `Url`, `PageSource`, and `CurrentGoal`.

## 3. Findings & Analysis

### 3.1 Session Management
Currently, there is no shared pool for browser contexts. 
- `browser/src/server.ts:25` launches a browser and closes it at the end of `runBrowserCrawl`.
- `browser/src/server.ts:60` launches a browser and closes it at the end of the `/action` handler (`line 107`).
- There is no mechanism to track or reuse a `BrowserContext` or `Page` between subsequent requests.

### 3.2 Structured DOM Scraping
The AI service requires `links`, `buttons`, and `forms` in a structured format as defined in `proto/ai/v1/ai.proto`.
- `links`: `<a>` tags with `href` and text.
- `buttons`: Currently not extracted in any phase.
- `forms`: Extracted in `browser/src/crawler.ts:153-162` but missing inputs and detailed selectors.

### 3.3 Metadata Extraction
The following fields are missing from the current `/action` response in `browser/src/server.ts`:
- `currentUrl`: Available via `page.url()`.
- `pageTitle`: Available via `page.title()`.
- `structuredData`: Not currently implemented for the `/action` path.

### 3.4 Orchestrator Data Gaps
In `internal/orchestrator/orchestrator.go:565`, the `DecideBrowserActionRequest` is populated with minimal data. The following fields defined in `ai.proto` are currently left as default/empty:
- `last_action_success`
- `last_action_error`
- `current_url`
- `page_title`
- `links`
- `buttons`
- `forms`
- `last_action`
- `last_selector`
- `screenshot_base64` (though `actionRes.Screenshot` exists in the Go client's `ActionResponse`).

## 4. Technical Constraints
- **Playwright Execution Context**: DOM scraping must be performed within `page.evaluate`.
- **Go Structs**: `internal/browser/client.go:44` (`ActionResponse`) must be updated to match the new JSON response from the TS service.

## 5. Architecture Documentation
- **Service**: Express API running on port 3010.
- **Client**: Go `browser.Client` in `internal/browser/client.go`.
- **Proto**: `ai.v1.AiService` defines the `DecideBrowserActionRequest` which expects this data.
