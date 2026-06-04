# HOTFIX DecideBrowserActionRequest Implementation Plan

## Overview
Add missing fields to `DecideBrowserActionRequest` in `proto/ai/v1/ai.proto` to improve the browser automation feedback loop and provide visual context (screenshots) to the AI.

## Scope Definition (CRITICAL)
### In Scope
- Update `DecideBrowserActionRequest` with `last_action`, `last_selector`, and `screenshot_base64`.
- Regenerate Go, TypeScript, and Python stubs using existing build infrastructure.

### Out of Scope (DO NOT TOUCH)
- Modifying the AI logic to use these new fields.
- Changing any other proto messages or services.

## Current State Analysis
- Proto file: `proto/ai/v1/ai.proto`
- Affected message: `DecideBrowserActionRequest` (starts at line 97).
- Current field count: 10.

## Implementation Phases

### Phase 1: Proto Modification
- **Goal**: Update the schema definition.
- **Steps**:
  1. [x] Edit `proto/ai/v1/ai.proto` to add:
     - `string last_action = 11;`
     - `string last_selector = 12;`
     - `string screenshot_base64 = 13;`
- **Verification**: Use `grep` to confirm fields exist in the `.proto` file.

### Phase 2: Stub Regeneration
- **Goal**: Synchronize all language-specific implementations.
- **Steps**:
  1. [x] Run Go/TS generation: `buf generate proto` (via the command structure in Taskfile).
  2. [x] Run Python generation: `ai/.venv/Scripts/python.exe -m grpc_tools.protoc -I proto --python_out=ai/src/proto --pyi_out=ai/src/proto --grpc_python_out=ai/src/proto proto/ai/v1/ai.proto`
- **Verification**:
  - [x] `grep last_action internal/gen/ai/v1/ai.pb.go`
  - [x] `grep last_action ui/src/gen/ai/v1/ai_pb.ts`
  - [x] `grep last_action ai/src/proto/ai/v1/ai_pb2.pyi`
