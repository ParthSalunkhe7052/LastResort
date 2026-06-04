# Refactor Plan: Agent-First Architecture

## Phase 1: Context & Feedback (Completed)
- Implement `BrowserAttackContext` to feed the AI DOM state, local storage, and cookies.
- Implement `ActionResult` to provide the AI with immediate success/failure feedback on its actions.

## Phase 2: Memory (Completed)
- Implement `SessionJournal` to give the AI multi-step workflow memory.

## Phase 3: Exploitation (Completed)
- Refactor SQL Injection (`internal/scanner/sqli.go`) to use the new AI-driven Playwright execution flow.

## Phase 4: Migration (Pending)
- Refactor remaining scanner modules (XSS, CSRF, Path Traversal) to the agent-driven model.