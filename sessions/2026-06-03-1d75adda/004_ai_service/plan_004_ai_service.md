# AI Service: Prompt Engineering & Multimodal Support Implementation Plan

## Overview
This plan upgrades the `DecideBrowserAction` capability of the AI service to be more robust, token-efficient, and visually aware. We will incorporate structured element data, implement HTML cleaning, and enable multimodal screenshot support for the Gemini provider.

## Scope Definition (CRITICAL)
### In Scope
- Refactoring `DecideBrowserAction` in `ai/src/server.py`.
- Updating `LLMProvider` and `GeminiProvider` in `ai/src/llm/provider.py`.
- Creating `ai/src/prompts/browser.py` for structured prompts.
- Implementing HTML cleaning (regex based).
- Incorporating `last_action_success` feedback into the prompt.
### Out of Scope (DO NOT TOUCH)
- Modifying the browser service or orchestrator (they already send the data).
- Updating `MockProvider` or `OllamaProvider` with vision support (keep them text-only for now).
- Changing other AI RPCs (AnalyzeRecon, etc.).

## Current State Analysis
- `DecideBrowserAction` in `ai/src/server.py:276` ignores most fields in `DecideBrowserActionRequest`.
- `GeminiProvider` in `ai/src/llm/provider.py:85` only supports text content.
- Page source truncation is naive (`server.py:293`).

## Implementation Phases

### Phase 1: LLM Provider Multimodal Support
- **Goal**: Enable `LLMProvider` to accept image data.
- **Steps**:
  1. [x] Update `LLMProvider` abstract class in `ai/src/llm/provider.py` to accept an optional `image_data` (bytes) and `image_mime_type` in `generate_json`.
  2. [x] Update `GeminiProvider.generate_json` to handle `image_data`. If present, pass it as a Part to `model.generate_content`.
  3. [x] Update `MockProvider` and `OllamaProvider` to accept the new arguments but ignore them.
- **Verification**: Unit test or script to call `GeminiProvider.generate_json` with a dummy image and verify no crashes.

### Phase 2: Prompt Engineering & HTML Utilities
- **Goal**: Create a dedicated prompt factory for browser actions and HTML cleaning logic.
- **Steps**:
  1. [x] Create `ai/src/prompts/browser.py`.
  2. [x] Implement `clean_html(html: str) -> str` using regex to remove `<script>`, `<style>`, and `<svg>` tags and their content.
  3. [x] Implement `get_decide_action_prompt(request)` that formats the goal, cleaned HTML, links, buttons, forms, and last action status into a structured prompt.
- **Verification**: Run a standalone script to verify `clean_html` correctly strips tags.

### Phase 3: AI Service Integration
- **Goal**: Connect the new prompt logic and multimodal support to `DecideBrowserAction`.
- **Steps**:
  1. [x] Update `AiServiceServicer.DecideBrowserAction` in `ai/src/server.py`.
  2. [x] Decode `screenshot_base64` from the request into bytes.
  3. [x] Call `get_decide_action_prompt` to build the prompt.
  4. [x] Call `provider.generate_json` with the prompt and image data.
- **Verification**: Run `ai/src/server.py` and use a test script (or `grpcurl`) to send a full `DecideBrowserActionRequest` and verify the AI responds using the new data.

### Phase 4: Final Verification & Refactoring
- **Goal**: Ensure no slop and everything is Solenya-tight.
- **Steps**:
  1. [x] Remove old inline prompt and truncation logic from `server.py`.
  2. [x] Ensure all error handling is robust.
- **Verification**: Automated tests pass.
