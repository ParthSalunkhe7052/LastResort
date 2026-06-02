# Technology Stack Decision

> **Purpose:** Deep engineering analysis of Rust vs Go vs Node.js vs Python.
> Final recommendation with full tradeoff justification.

---

## 1. Decision Summary

> [!IMPORTANT]
> **Recommended Architecture: Go Core Engine + TypeScript UI + Python AI Modules**
>
> This is a **hybrid architecture** — not a pure-language decision. Each language is chosen for the component where it excels. This matches the pattern used by the most successful modern security tools.

```
┌─────────────────────────────────────────────────────┐
│              TypeScript UI Layer                     │
│   React + Playwright Browser Automation              │
│   WebSocket for real-time updates                    │
├────────────────────┬────────────────────────────────┤
│     gRPC / ConnectRPC / WebSocket IPC                │
├────────────────────┴────────────────────────────────┤
│              Go Core Engine                          │
│   HTTP proxy · Scanner · Crawler · Orchestrator      │
│   Template engine · Storage · OOB server             │
├────────────────────┬────────────────────────────────┤
│     gRPC / subprocess IPC                            │
├────────────────────┴────────────────────────────────┤
│              Python AI Modules                       │
│   LLM integration · Attack planning · Report gen     │
│   Custom scripting · Research agents                 │
└─────────────────────────────────────────────────────┘
```

---

## 2. Why Not Pure Rust?

Rust was seriously considered. Caido (the closest architectural precedent) uses Rust. Here's why we chose Go instead:

### The Case FOR Rust
| Advantage | Impact |
|-----------|--------|
| Memory safety without GC | Eliminates runtime crashes |
| Zero-cost abstractions | Maximum throughput |
| WASM plugin system | Best sandboxed plugin support |
| Caido precedent | Proven viable for security proxy |
| Smallest binary/memory | Minimal footprint |

### The Case AGAINST Rust (for this project)
| Concern | Impact |
|---------|--------|
| **3-4x slower development** | MVP in 6-8 months vs 3-4 months |
| **Solo developer** | No team to absorb learning curve |
| **Security tool ecosystem is Go-dominant** | Nuclei, httpx, ffuf, Katana, subfinder — all Go |
| **Cross-compilation is harder** | Go: `GOOS=linux` / Rust: needs `cross` tool + libc matching |
| **Browser automation immature** | No good Playwright/CDP bindings in Rust |
| **AI/LLM integration painful** | No LangChain equivalent, basic HTTP wrappers only |
| **50K concurrent connections is overkill** | For a local tool, Go's 50K+ is more than sufficient |

### The Numbers That Matter

| Metric | Go | Rust |
|--------|----|----|
| Time to MVP | ~3-4 months | ~6-8 months |
| Max concurrent connections | ~50K+ (sufficient) | ~100K+ (overkill locally) |
| Binary size | ~10-15MB | ~5-8MB |
| Cross-compilation effort | 1 hour CI setup | 1-2 days toolchain |
| Memory (proxy + scanner) | ~30-60MB | ~10-25MB |
| Developer ramp-up | 2-4 weeks | 2-4 months |
| Lines of code (equivalent) | Baseline (1x) | 1.5-2x more |

> [!TIP]
> **Rust is the better long-term choice if you have unlimited time.** Go is the better pragmatic choice when you're a solo developer who needs to ship. You can always rewrite hot paths in Rust later via CGo FFI if needed.

---

## 3. Detailed Language Comparison

### 3.1 Concurrency Model

| Language | Model | HTTP Throughput | Concurrent Connections | Memory Under Load |
|----------|-------|----------------|----------------------|-------------------|
| **Rust (tokio)** | async/await state machines | ~7M+ RPS | ~100K+ | ~2-10MB |
| **Go (goroutines)** | M:N green threads | ~3-5M RPS | ~50K+ | ~10-30MB |
| **Node.js (libuv)** | Single-thread event loop | ~300K-1M RPS | ~5-10K | ~50-150MB |
| **Python (asyncio)** | Single-thread + GIL | ~30-80K RPS | ~1-5K | ~100-300MB |

**For security scanning** (fire 10K requests, collect results):
- Go's goroutine model is a **perfect match** — write sequential-looking code that runs concurrently
- Rust's tokio is more powerful but requires expertise to avoid stalling the runtime
- Node.js is adequate but needs clustering for high concurrency
- Python is insufficient for the scanning engine (fine for AI modules)

### 3.2 Network Stack

| Capability | Rust | Go | Node.js | Python |
|-----------|------|----|---------|---------| 
| HTTP/1.1 | hyper (gold standard) | net/http (excellent) | http module | requests/httpx |
| HTTP/2 | hyper, h2 (native) | net/http (since 1.6) | http2 module | httpx (via h2) |
| HTTP/3 QUIC | quinn, s2n-quic | quic-go | Not mature | Not mature |
| WebSocket | tokio-tungstenite | gorilla/websocket | ws (excellent) | websockets |
| TLS | rustls (pure Rust) | crypto/tls (native) | Built-in | ssl + pyOpenSSL |
| Raw Sockets | Full control | net package | net (limited) | socket module |
| **MITM Proxy** | Hard, no mature lib | goproxy (mature) | http-proxy | mitmproxy (best) |

**Key insight:** Building a MITM proxy is **easiest in Go** (goproxy is mature, goroutines handle concurrency naturally) and **most performant in Rust** (but significantly more work).

### 3.3 Security Tool Ecosystem

| Language | Major Security Tools | Ecosystem Maturity |
|----------|---------------------|-------------------|
| **Go** | Nuclei, ffuf, httpx, Katana, subfinder, Amass, GoBuster, Trivy | ⭐⭐⭐⭐⭐ Dominant |
| **Python** | mitmproxy, sqlmap, Scapy, Volatility, Impacket, Pwntools | ⭐⭐⭐⭐ Legacy king |
| **Rust** | Caido, RustScan, Feroxbuster | ⭐⭐ Emerging |
| **Node.js** | Playwright/Puppeteer, retire.js | ⭐⭐ Niche |

**Go dominates modern offensive security tooling.** The ProjectDiscovery ecosystem alone (Nuclei, httpx, Katana, subfinder, naabu) covers most reconnaissance needs and is entirely Go.

### 3.4 Browser Automation

| Feature | Node.js/TypeScript | Python | Go | Rust |
|---------|-------------------|--------|----|----|
| **Playwright** | ⭐ First-class official | ⭐ First-class official | Community (wraps Node) | Immature |
| **Puppeteer** | ⭐ First-class official | pyppeteer (community) | chromedp (native CDP) | None mature |
| **CDP Direct** | Via Playwright | Via Playwright | **chromedp** (pure Go) | Emerging |
| **Cross-Browser** | Yes (Playwright) | Yes (Playwright) | Playwright-go only | No |

**Decision:** Browser automation lives in the **TypeScript layer** using Playwright (first-class support). The Go core orchestrates browser tasks via IPC but doesn't run Playwright directly.

### 3.5 AI/LLM Integration

| Feature | Python | Node.js/TS | Go | Rust |
|---------|--------|-----------|----|----|
| OpenAI SDK | ⭐ Official, first-class | ⭐ Official, first-class | Official (newer) | Community |
| LangChain/LlamaIndex | ⭐ Native, mature | LangChain.js | Limited | None |
| HuggingFace/PyTorch | ⭐ Only option | Limited | None | tch-rs (complex) |
| Vector Stores | ChromaDB, Qdrant | Qdrant, pgvector | Qdrant client | Qdrant client |
| Local LLM (Ollama) | Trivial | Trivial | Easy (HTTP) | Possible (HTTP) |
| Embeddings | ⭐ First-class | Good | Adequate | Adequate |

**Decision:** AI modules live in **Python**. It's the only language with full access to the AI/ML ecosystem. Communication with Go core via gRPC/subprocess.

### 3.6 Binary Distribution

| Factor | Go | Rust | Node.js | Python |
|--------|----|----|---------|--------|
| Single binary | ⭐ Native default | ⭐ Native | SEA (maturing) | PyInstaller (fragile) |
| Cross-compilation | ⭐ Trivial | Possible, complex | Poor | Very difficult |
| Binary size | ~10-15MB | ~5-8MB | ~50MB+ | ~30-100MB |
| No runtime needed | ✅ | ✅ | ❌ (V8) | ❌ (CPython) |
| AV false positives | Rare | Rare | Sometimes | Common |

**Go wins decisively** for distribution simplicity.

### 3.7 Plugin System

| Approach | Rust | Go | Node.js | Python |
|---------|------|----|---------|--------|
| WASM plugins | ⭐ First-class (smallest binaries) | Possible (large bins) | Via runtimes | Via wasmtime-py |
| Dynamic loading | Complex (no stable ABI) | Broken (`plugin` pkg) | ⭐ Native require | ⭐ Native importlib |
| Scripting embed | Lua (mlua), Rhai | Lua (gopher-lua), JS | ⭐ Native | ⭐ Native |
| Hot reloading | WASM hot-swap | Rebuild required | ⭐ Native | ⭐ Native |

**Decision:** Plugin system uses a **hybrid approach**: 
1. YAML templates (Nuclei-style) for simple vulnerability checks
2. Embedded Lua/JavaScript engine for scripting
3. gRPC-based plugin protocol for complex plugins (HashiCorp go-plugin pattern)

---

## 4. Hybrid Architecture Deep Dive

### 4.1 Component-to-Language Mapping

| Component | Language | Rationale |
|-----------|----------|-----------|
| HTTP proxy engine | **Go** | goproxy mature, goroutines perfect for concurrent proxying |
| Scanner engine | **Go** | Nuclei proves Go is ideal for high-throughput scanning |
| Crawler | **Go** | Katana proves Go + headless browser works |
| Scan orchestrator | **Go** | DAG execution, job queues, rate limiting |
| Template engine | **Go** | YAML parsing, request construction, matcher evaluation |
| Data storage | **Go** | SQLite via go-sqlite3, schema management |
| OOB callback server | **Go** | Simple HTTP/DNS server for blind detection |
| CLI/daemon | **Go** | Single binary, cross-platform |
| Web UI | **TypeScript** | React, modern web framework, rich component libraries |
| Browser automation | **TypeScript** | Playwright first-class support |
| Real-time updates | **TypeScript** | WebSocket server integrated with UI |
| AI agent orchestration | **Python** | LangChain, OpenAI SDK, agent frameworks |
| LLM integration | **Python** | Best model support, embeddings, vector stores |
| Attack planning | **Python** | ReAct loops, chain-of-thought reasoning |
| Report generation | **Python** | Jinja2 templates, Markdown processing |
| Custom user scripts | **Python** | Familiar to security professionals |

### 4.2 IPC Boundaries

```
┌──────────────────────────────────────────────────────────────────┐
│                                                                  │
│  Go Core ←──── ConnectRPC/gRPC ────→ TypeScript UI               │
│     │                                     │                      │
│     │  • Scan status streaming            │  • Config CRUD       │
│     │  • Finding notifications            │  • Scan control      │
│     │  • Proxy traffic feed               │  • HTTP editor       │
│     │  • Log streaming                    │  • Report requests   │
│     │                                     │                      │
│     │  Latency budget: <1ms               │                      │
│     │  Protocol: Protobuf + streaming     │                      │
│     │                                                            │
│  Go Core ←──── gRPC/subprocess ────→ Python AI                   │
│     │                                     │                      │
│     │  • Scan context (endpoints, flows)  │  • Attack hypotheses │
│     │  • Response data for analysis       │  • Confidence scores │
│     │  • Report data                      │  • Report narratives │
│     │                                     │  • Workflow models   │
│     │                                                            │
│     │  Latency budget: <50ms per call     │                      │
│     │  Protocol: Protobuf or JSON         │                      │
│     │                                                            │
│  TypeScript UI ←── Playwright API ──→ Browser Instances           │
│     │                                                            │
│     │  • Page navigation                                         │
│     │  • Form interaction                                        │
│     │  • Network capture (CDP)                                   │
│     │  • Screenshot capture                                      │
│     │  • DOM analysis                                            │
│     │                                                            │
│     │  Latency budget: <100ms             │                      │
│     │  Protocol: CDP + Playwright SDK     │                      │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 4.3 Build System

```
project/
├── go.mod                    # Go module root
├── cmd/
│   └── lastresort/
│       └── main.go           # CLI entry point
├── internal/                 # Go core engine
│   ├── proxy/
│   ├── scanner/
│   ├── crawler/
│   ├── orchestrator/
│   ├── storage/
│   ├── oob/
│   └── api/                  # gRPC/ConnectRPC server
├── proto/                    # Protobuf definitions (shared)
│   ├── scan.proto
│   ├── finding.proto
│   └── proxy.proto
├── ui/                       # TypeScript UI
│   ├── package.json
│   ├── src/
│   │   ├── App.tsx
│   │   ├── components/
│   │   └── services/         # gRPC client, Playwright manager
│   └── vite.config.ts
├── ai/                       # Python AI modules
│   ├── pyproject.toml
│   ├── src/
│   │   ├── agents/
│   │   ├── llm/
│   │   └── report/
│   └── tests/
├── templates/                # YAML vulnerability templates
├── scripts/                  # Build/deployment scripts
├── Makefile                  # Unified build commands
└── Taskfile.yml              # Alternative to Makefile
```

### 4.4 Development Workflow

```bash
# Single command to start everything
make dev

# Which runs:
# 1. Go core engine (air for hot reload)
# 2. TypeScript UI (vite dev server)
# 3. Python AI service (uvicorn with reload)
# 4. Protobuf codegen watcher

# Build for distribution
make build
# Produces:
#   dist/
#   ├── lastresort.exe          # Go binary
#   ├── ui/                     # Static web assets
#   ├── ai/                     # Python wheel or bundled
#   └── templates/              # YAML templates
```

---

## 5. When to Reconsider Rust

Switch to Rust for the core engine if ANY of these become true:

1. **Go's memory footprint becomes problematic** (unlikely for local tool)
2. **You need WASM plugins as a first-class feature** (Go WASM binaries are too large)
3. **Proxy throughput becomes a bottleneck** (unlikely — Go handles 50K+ concurrent)
4. **You hire additional engineers with Rust expertise** (changes cost calculation)
5. **You decide to open-source and need Caido-level performance marketing**

The architecture is designed with clean boundaries so the Go core could be replaced with Rust without touching the UI or AI layers.

---

## 6. Technology Stack Summary

### Core Dependencies

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| **Language (Core)** | Go | 1.22+ | Engine, proxy, scanner |
| **Language (UI)** | TypeScript | 5.x | Web interface, browser automation |
| **Language (AI)** | Python | 3.12+ | AI agents, report generation |
| **Web Framework** | React | 19+ | UI components |
| **Build Tool** | Vite | 6+ | UI bundling |
| **Browser Engine** | Playwright | Latest | Browser automation |
| **Database** | SQLite | 3.45+ | Local data storage |
| **Encryption** | SQLCipher | 4.x | Database encryption at rest |
| **IPC** | ConnectRPC | Latest | Go ↔ TypeScript communication |
| **IPC** | gRPC | Latest | Go ↔ Python communication |
| **Serialization** | Protocol Buffers | 3 | Type-safe cross-language messaging |
| **AI Framework** | LangChain/LangGraph | Latest | Agent orchestration |
| **LLM (Local)** | Ollama | Latest | Offline AI inference |
| **LLM (Cloud)** | OpenAI/Anthropic APIs | Latest | High-quality reasoning |
| **HTTP Proxy** | goproxy | Latest | MITM proxy foundation |
| **TLS** | crypto/tls (Go) | stdlib | TLS interception |
| **Template Engine** | Custom (Nuclei-inspired) | N/A | Vulnerability check definitions |
| **Report Engine** | Jinja2 + WeasyPrint | Latest | PDF report generation |

### Development Dependencies

| Tool | Purpose |
|------|---------|
| **protoc** | Protobuf compiler |
| **buf** | Protobuf linting and codegen |
| **air** | Go hot reloading |
| **golangci-lint** | Go linting |
| **ESLint + Prettier** | TypeScript linting |
| **Ruff** | Python linting |
| **Task** | Task runner (Taskfile.yml) |
| **Docker** | Optional containerized deployment |
