# LastResort — Autonomous Web Penetration-Testing Agent

> An LLM-driven web security agent that plans attacks, executes them in a **real browser**, and verifies vulnerabilities by **actual DOM/script effect** — not by matching strings in an HTTP response.

Built in Go, with a Playwright execution layer and a React dashboard. LastResort moves past the classic "blind scanner with hardcoded payloads" model: an AI planning loop generates exploit payloads on demand, drives a live browser to execute them, reads back the real page state, and remembers what it learned so it can chain multi-step attacks across stateful navigation flows.

---

## Why this exists

Traditional scanners have two problems:

1. **They match strings, not effects.** If a payload is reflected in the response body, they call it a finding — which produces a flood of false positives from payloads that were escaped, sandboxed, or never actually executed.
2. **They fire hardcoded signatures.** A fixed payload list can't adapt to how a specific app filters, encodes, or routes input.

LastResort inverts both:

- **Verification by real browser effect.** A candidate XSS/SQLi/CSRF is only a finding if Playwright observes the real consequence in the live DOM — a fired `alert()`/dialog, an injected node, a state change — not merely a reflected string. This is what cuts false positives dramatically versus response string-matching.
- **AI-generated, context-aware payloads.** An LLM planning loop (Gemini / OpenRouter) receives a `BrowserAttackContext` — the current accessibility tree, prior action results, and session history — and formulates payloads tailored to what the app is actually doing, then evaluates the feedback and decides the next move.

---

## Architecture

```
┌─────────────┐    ConnectRPC    ┌──────────────────────────────┐
│  React UI   │ ───────────────► │        Go Orchestrator       │
│ (dashboard) │ ◄─────────────── │  plan → execute → verify →   │
└─────────────┘   live events    │        journal → repeat      │
                                  └───────────┬──────────────────┘
                        ┌─────────────────────┼─────────────────────┐
                        ▼                      ▼                     ▼
                 ┌────────────┐        ┌───────────────┐     ┌──────────────┐
                 │  AI Client │        │ Browser (PW)  │     │ SessionJournal│
                 │ Gemini /   │        │ Playwright/TS │     │   SQLite      │
                 │ OpenRouter │        │ exec + DOM    │     │  AXTree + log │
                 └────────────┘        └───────────────┘     └──────────────┘
```

- **Orchestrator (Go)** — runs the agent loop: ask the AI to plan, execute the action in the browser, capture the `ActionResult`, verify by DOM state, persist to the journal, feed context back into the next plan.
- **AI layer (Go)** — wraps the LLM (Gemini / OpenRouter) and injects `BrowserAttackContext` so the model plans with full situational awareness instead of blind guessing.
- **Browser service (TypeScript / Playwright)** — the primary execution environment. Every attack action runs against a live page and returns synchronous feedback (DOM diff, dialogs, script alerts, navigation).
- **SessionJournal (SQLite)** — persistent memory of accessibility-tree (AXTree) nodes, actions, and results. This is what lets the agent execute **multi-step** exploits over stateful flows (login → navigate → inject) rather than one-shot payloads.
- **Attack modules (Go)** — SQLi, XSS, CSRF, path traversal, rate-limit, CORS/header checks, plus a manual-tooling mode for guided testing.
- **React dashboard** — live scan launch, AI pipeline panel, event timeline, findings summary, and a live browser view, streamed over ConnectRPC.

## Tech stack

| Layer | Technology |
|---|---|
| Core / orchestration | **Go** |
| Transport | **ConnectRPC** (Protobuf, streaming) |
| Browser execution | **Playwright** (TypeScript service) |
| AI planning | **Gemini / OpenRouter** LLM loop |
| Persistence | **SQLite** (SessionJournal, findings, evidence) |
| Frontend | **React + Vite + TypeScript** |
| Build / dev | Taskfile, buf (codegen) |

## Key engineering ideas

- **Effect-based verification** over response string-matching — a finding requires an observed browser consequence, which is what keeps false positives low.
- **Agent memory (SessionJournal)** — AXTree + action history in SQLite gives the agent state across steps, enabling exploits that depend on prior navigation.
- **Schema-first RPC** — ConnectRPC/Protobuf contract shared between the Go backend and the TS/React frontend, generated with buf.
- **Separation of planning and execution** — the LLM decides *what* to try; Go + Playwright own *how* it runs and *whether* it worked.

---

## Running locally

> Requires Go, Node.js, and an LLM API key (Gemini or OpenRouter).

```bash
# 1. Browser service (Playwright)
cd browser && npm install && npm run build

# 2. Configure env (LLM key, DB path)
cp .env.example .env   # set GEMINI_API_KEY / OPENROUTER key

# 3. Run the agent server (defaults: SQLite at ./data, port 8443)
go run ./cmd/lastresort serve

# 4. UI
cd ui && npm install && npm run dev
```

See [`docs/`](docs/) for the architecture review, dependency analysis, and testing plan.

---

## Status & scope

Research / portfolio project demonstrating autonomous agent design, browser-based verification, and LLM planning loops. **Use only against systems you own or are explicitly authorized to test.**
