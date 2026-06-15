# LASTRESORT BACKEND AUDIT & REFACTOR STRATEGY PROMPT

**Role:** You are a Senior Security Architect and Principal Software Engineer specializing in Go-based offensive security tooling.

**Objective:** Conduct an exhaustive architectural and behavioral audit of the "LastResort" codebase. Identify systemic failures in the "Manual Testing Pipeline," detect "AI Slop" (non-functional boilerplate or "hallucinated" logic), and expose any "False Positives" where the tool represents unverified hypotheses as confirmed vulnerabilities.

**Project Context:**
LastResort is an autonomous penetration testing platform.
- **Core Backend:** Go (ConnectRPC, SQLite).
- **Browser Service:** Node.js/Playwright (Port 3010).
- **Manual Pipeline:** Integrated CLI tools (Nuclei, Nikto, Wapiti, Dalfox, Corsy, SSLyze, Katana, httpx, WhatWeb).
- **Orchestration:** `internal/orchestrator/orchestrator.go` manages the lifecycle (Prep -> Parallel -> Completion).

---

### PART 1: SYSTEMIC AUDIT VECTORS

Analyze the provided codebase with a focus on these high-friction areas:

#### 1. The Manual Tool Pipeline "Fragmentation"
- **Tool Wrappers:** Analyze how external CLI tools (Nikto, Wapiti, etc.) are invoked. Are we handling `stderr`, exit codes, and timeouts correctly? 
- **Parsing Logic:** Inspect the regex and JSON parsers for these tools. Is there "Jerry-work" (fragile logic) that fails silently or ignores critical findings?
- **Execution Parallelism:** Review the Go `Orchestrator` worker pool. Are we hitting race conditions, port collisions, or resource exhaustion when running multiple heavy scanners (like Nikto + Wapiti) simultaneously?

#### 2. Verification Integrity (The "Lying" Engine)
- **Hypothesis vs. Fact:** LastResort uses `StatePotentialFinding` (Hypothesis) and `StateVerifiedFinding` (Fact). Review the `VerificationEngine`.
- **False Verification:** Are there cases where a tool's output is blindly promoted to "Verified" without a secondary browser-based confirmation or a logical check?
- **AI Planning:** Analyze how the LLM plans SQLi/XSS attacks. Does the planning logic actually utilize the provided AXTree/DOM context, or is it just throwing generic payloads?

#### 3. Database & State Management
- **Migration Stability:** Review `internal/storage/db.go`. Are the migrations idempotent? Are there columns added "best-effort" that cause runtime panics or data corruption?
- **Journaling:** Is the `attack_journal` actually useful for reproduction, or is it just logging "success: true" without sufficient evidence (screenshots/DOM dumps)?

---

### PART 2: REQUIRED OUTPUTS

Your response must include:

#### A. Root Cause Analysis (RCA)
- List the top 5 architectural failures currently breaking the manual pipeline.
- Identify specific files and line numbers where logic is "fake" or non-functional.

#### B. The "Slop" Report
- Flag any boilerplate code that exists but serves no purpose or is never called.
- Identify where the "Autonomous" features are actually just hardcoded fallbacks.

#### C. Full Implementation Plan (Refactor)
- **Phase 1: Pipeline Hardening.** How to standardize tool output into a unified `NormalizedFinding` structure that doesn't lose severity data.
- **Phase 2: Verification Logic.** A plan to ensure no finding reaches the UI as "Critical" or "Verified" unless it passes a deterministic verification check.
- **Phase 3: Orchestrator Optimization.** How to implement a smarter queue for manual tools to prevent system hang-ups.

---

### PART 3: AUDIT CONSTRAINTS
- **No Refactoring in the Audit:** Do not provide code fixes yet. Focus on the **Technical Audit Report** first.
- **High Signal:** Be cynical. If a feature looks like it was "hallucinated" by an AI during development, call it out.
- **Security Standard:** Evaluate the code against the "Documentarian" standard—complete, evidence-based, and objective.

---
*End of Prompt. Please proceed with the audit of the attached codebase.*
