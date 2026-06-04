# Research: Update AI Proto for Enhanced Browser Interaction

**Date**: 2026-06-03

## 1. Executive Summary
The task involves enhancing the `AiService` in `proto/ai/v1/ai.proto` to provide the AI model with more context about the browser state and the results of previous actions. This includes tracking action success/failure, current page details (URL and title), and structured elements (links, buttons, forms).

## 2. Technical Context
- **Target File**: `proto/ai/v1/ai.proto`
- **Affected Message**: `DecideBrowserActionRequest` (currently at line 105)
- **Current Structure**:
  ```proto
  message DecideBrowserActionRequest {
    string url = 1;
    string page_source = 2;
    string current_goal = 3;
  }
  ```
- **Generation Tool**: `buf` (v1.70.0)
- **Plugin Configuration**: `buf.gen.yaml` targets `internal/gen` (Go/Connect-Go) and `ui/src/gen` (TS/Connect-ES).

## 3. Findings & Analysis
- The `AiService.DecideBrowserAction` RPC currently only receives the URL, page source, and goal.
- To improve the AI's decision-making, it needs to know if the last action it requested actually worked.
- Structured lists of elements (links, buttons, forms) will allow the AI to reason about interactive elements without parsing raw HTML, reducing token usage and improving reliability.
- `current_url` and `page_title` provide basic state context.

## 4. Technical Constraints
- Must use `buf generate` to sync changes to Go and TypeScript.
- No other files should be modified besides `proto/ai/v1/ai.proto`.

## 5. Architecture Documentation
- The project follows a clear separation between `proto` definitions and generated code in `internal/gen` and `ui/src/gen`.
- Service definitions use the `connect-go` and `connect-es` plugins.
- Package naming follows `ai.v1` and `scan.v1` patterns.
