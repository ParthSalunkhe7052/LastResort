# Research: HOTFIX DecideBrowserActionRequest Missing Fields

**Date**: 2026-06-03

## 1. Executive Summary
The `DecideBrowserActionRequest` message in `proto/ai/v1/ai.proto` is missing three critical fields required for browser automation feedback loop: `last_action`, `last_selector`, and `screenshot_base64`. These fields are necessary for the AI to understand the result of its previous action and the current visual state of the browser.

## 2. Technical Context
- **Proto Definition**: `proto/ai/v1/ai.proto:97`
  ```proto
  message DecideBrowserActionRequest {
    string url = 1;
    string page_source = 2;
    string current_goal = 3;

    bool last_action_success = 4;
    string last_action_error = 5;
    string current_url = 6;
    string page_title = 7;

    repeated BrowserElement links = 8;
    repeated BrowserElement buttons = 9;
    repeated BrowserForm forms = 10;
  }
  ```
- **Generation Logic**: `Taskfile.yml:4`
  - Uses `buf` for Go and TypeScript.
  - Uses `grpc_tools.protoc` for Python.
- **Affected Components**:
  - Go Backend (`internal/gen/ai/v1/ai.pb.go`)
  - TypeScript UI (`ui/src/gen/ai/v1/ai_pb.ts`)
  - Python AI Service (`ai/src/proto/ai/v1/ai_pb2.py`)

## 3. Findings & Analysis
- New fields should be appended to `DecideBrowserActionRequest`:
  - `last_action` (string) -> field 11
  - `last_selector` (string) -> field 12
  - `screenshot_base64` (string) -> field 13
- The Python stubs are located in `ai/src/proto/ai/v1/`.
- The `Taskfile.yml` provides a centralized command to regenerate all stubs.

## 4. Technical Constraints
- Field numbers 1-10 are already in use and should not be changed to maintain backward compatibility (though this is a proto3 repo and we are in early dev, best practice is to append).
- `buf` and `python` (with `grpcio-tools`) must be available to run the regeneration.

## 5. Architecture Documentation
- The project follows a multi-service architecture (Go, Python, TypeScript) sharing the same protobuf definitions.
- Code generation is semi-automated via `Taskfile.yml`.
