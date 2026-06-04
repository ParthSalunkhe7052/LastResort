# Update AI Proto Implementation Plan

## Overview
Enhance the `DecideBrowserActionRequest` message in `proto/ai/v1/ai.proto` to include more detailed browser state and feedback from the previous action. This will allow the AI to make more informed decisions during browser automation.

## Scope Definition (CRITICAL)
### In Scope
- Define new messages `BrowserElement` and `BrowserForm` in `proto/ai/v1/ai.proto`.
- Update `DecideBrowserActionRequest` with `last_action_success`, `last_action_error`, `current_url`, `page_title`, and repeated fields for links, buttons, and forms.
- Run `buf generate` to update generated code in Go and TypeScript.

### Out of Scope (DO NOT TOUCH)
- Implementing the logic to populate these fields in the crawler/browser service.
- Modifying any other proto files or service methods.
- Changing existing field numbers in `DecideBrowserActionRequest`.

## Current State Analysis
- `proto/ai/v1/ai.proto:105`: `DecideBrowserActionRequest` has only `url`, `page_source`, and `current_goal`.
- `buf.gen.yaml`: Configured to output to `internal/gen` and `ui/src/gen`.

## Implementation Phases

### Phase 1: Proto Definition
- **Goal**: Update the `.proto` file with new messages and fields.
- **Steps**:
  1. [x] Add `BrowserElement` message to `proto/ai/v1/ai.proto`.
  2. [x] Add `BrowserForm` message to `proto/ai/v1/ai.proto`.
  3. [x] Update `DecideBrowserActionRequest` with new fields (indices 4-10).
- **Verification**: `buf lint` (if available) or manual inspection of the proto file.

### Phase 2: Code Generation
- **Goal**: Synchronize the changes to the rest of the codebase.
- **Steps**:
  1. [x] Run `buf generate`.
- **Verification**: Check if `internal/gen/ai/v1/ai.pb.go` and `ui/src/gen/ai/v1/ai_pb.ts` have been updated with the new fields.
