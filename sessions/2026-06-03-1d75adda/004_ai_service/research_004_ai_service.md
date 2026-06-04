# Research: Update AI Service - Prompt Engineering & Multimodal Support

**Date**: 2026-06-03

## 1. Executive Summary
The AI service currently implements a basic `DecideBrowserAction` RPC that only utilizes the raw page source and current goal. It lacks structured browser data (links, buttons, forms), does not perform HTML cleaning to optimize context usage, and lacks multimodal support for processing screenshots. This research maps the current implementation and identifies the necessary touchpoints for the requested enhancements.

## 2. Technical Context
- **AI Service Entry Point**: `ai/src/server.py:276` implements `DecideBrowserAction`.
- **LLM Provider**: `ai/src/llm/provider.py` manages interactions with Gemini, Ollama, and Mock providers.
- **Proto Definitions**: `proto/ai/v1/ai.proto` (and generated `ai/src/proto/ai/v1/ai_pb2.pyi`) contains the `DecideBrowserActionRequest` with all necessary fields (`links`, `buttons`, `forms`, `last_action_success`, `screenshot_base64`, etc.).
- **Current Behavior**:
    - `DecideBrowserAction` only reads `url`, `page_source`, and `current_goal` from the request.
    - It truncates `page_source` to 5000 characters manually (`server.py:293`).
    - The `GeminiProvider` only supports text-based `generate_json` calls.

## 3. Findings & Analysis

### 3.1. DecideBrowserAction Request Fields
The `DecideBrowserActionRequest` message has been updated with the following key fields that are currently ignored:
- `last_action_success`: Boolean indicating if the previous action worked.
- `last_action_error`: String with error details if the previous action failed.
- `links`, `buttons`, `forms`: Repeated structured elements extracted from the DOM.
- `screenshot_base64`: Base64 encoded PNG of the current viewport.

### 3.2. HTML Cleaning
The current implementation just slices the first 5000 characters of `page_source` (`server.py:293`). This includes `<script>`, `<style>`, and `<svg>` tags which are currently present in the truncated string passed to the LLM.

### 3.3. Multimodal Support in Gemini
The `GeminiProvider` in `ai/src/llm/provider.py` currently only passes string-based prompts to the `model.generate_content` method. It does not handle structured `Part` objects or binary data for multimodal inputs (images).

### 3.4. Prompt Engineering
The current prompt for `DecideBrowserAction` in `server.py:295-300` is minimal. It does not incorporate:
- `last_action_success` or `last_action_error` status.
- Structured elements from `links`, `buttons`, or `forms` fields.
- Detailed action descriptions.

## 4. Technical Constraints
- **Context Window**: Although Gemini has a large window, raw HTML from modern SPAs can still be massive. Cleaning is essential.
- **Image Size**: Base64 encoded screenshots can be large; ensure they are handled as bytes in the Gemini SDK.

## 5. Architecture Documentation
- The project follows a gRPC-based microservice architecture for the AI.
- Providers are abstracted via `LLMProvider` in `ai/src/llm/provider.py`.
- Prompts are being moved to a dedicated `prompts/` directory (e.g., `ai/src/prompts/report.py`).
