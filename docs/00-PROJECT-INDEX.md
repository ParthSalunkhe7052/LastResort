# LastResort — Design Document Index

> **Autonomous Web Application Security Testing Platform**
> Project Codename: **LastResort**

---

## Document Map

| # | Document | Purpose | Status |
|---|----------|---------|--------|
| 01 | [PRD](./01-PRD.md) | Product Requirements Document — Vision, scope, user stories, requirements | ✅ |
| 02 | [Existing Tool Analysis](./02-EXISTING-TOOL-ANALYSIS.md) | Deep analysis of ZAP, Burp, Nuclei, Caido, etc. | ✅ |
| 03 | [Technology Stack Decision](./03-TECHNOLOGY-STACK.md) | Rust vs Go vs Node vs Python — full tradeoff analysis | ✅ |
| 04 | [System Architecture](./04-SYSTEM-ARCHITECTURE.md) | High-level architecture, component design, data flow | ✅ |
| 05 | [Data Models](./05-DATA-MODELS.md) | Database schema, storage architecture, data flow | ✅ |
| 06 | [AI Agent Design](./06-AI-AGENT-DESIGN.md) | Multi-agent architecture, LLM integration, ReAct patterns | ✅ |
| 07 | [Plugin System](./07-PLUGIN-SYSTEM.md) | WASM-based plugin architecture, extension API | ✅ |
| 08 | [Security Model](./08-SECURITY-MODEL.md) | Platform security, isolation, secrets management | ✅ |
| 09 | [Implementation Plan](./09-IMPLEMENTATION-PLAN.md) | Phased roadmap, MVP → v1 → v2, task breakdown | ✅ |
| 10 | [Risks & Tradeoffs](./10-RISKS-AND-TRADEOFFS.md) | Known risks, mitigations, architectural tradeoffs | ✅ |

---

## Quick Start for Implementers

1. Read **01-PRD.md** to understand what we're building and why
2. Read **03-TECHNOLOGY-STACK.md** to understand the hybrid architecture decision
3. Read **04-SYSTEM-ARCHITECTURE.md** for the component breakdown
4. Read **09-IMPLEMENTATION-PLAN.md** for what to build first
5. Reference other docs as needed during implementation

## Architecture Decision Records

Key decisions are documented inline in each document with `> [!IMPORTANT]` callouts.

## Project Constraints

- **Solo developer** — one cybersecurity engineer
- **Local-first** — no cloud dependencies for core functionality
- **Not for commercialization** — no licensing/billing concerns
- **Long-term (5-10 year)** evolution horizon
- **No source code access** — black-box testing only
