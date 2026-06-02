# LastResort — Product Requirements Document (PRD)

> **Version:** 1.0
> **Date:** 2026-06-02
> **Author:** Principal Security Architect
> **Classification:** Internal — Not for distribution

---

## 1. Executive Summary

**LastResort** is a local-first, AI-augmented, autonomous web application security testing platform designed for a solo cybersecurity engineer to validate SaaS applications before production deployment.

Unlike existing tools that are either:
- **Too passive** (vulnerability scanners that only match signatures)
- **Too manual** (Burp Suite requiring constant human interaction)
- **Too shallow** (DAST tools that miss business logic flaws)

LastResort operates like a **real attacker**: it discovers, crawls, interacts, manipulates, and exploits — all from the outside, with zero source code access. It combines the speed of automated scanning with the intelligence of AI-driven attack planning and the depth of browser-based interaction testing.

### What Makes This Different

| Capability | Traditional Scanners | Burp Suite | LastResort |
|-----------|---------------------|------------|------------|
| Signature-based scanning | ✅ | ✅ | ✅ |
| Browser-based crawling | ❌ | Partial | ✅ Full Playwright |
| Business logic testing | ❌ | Manual only | ✅ AI-assisted |
| Multi-account abuse detection | ❌ | Manual only | ✅ Automated |
| Race condition testing | ❌ | Via extensions | ✅ Native |
| AI attack planning | ❌ | ❌ | ✅ Multi-agent |
| Autonomous operation | Partial | ❌ | ✅ Goal-directed |
| Local-first, no cloud | Varies | ✅ | ✅ |

---

## 2. Product Vision

### 2.1 Vision Statement

> Build a security testing platform that thinks like a penetration tester, operates like an attacker, and reports like a consultant — running entirely on the operator's machine.

### 2.2 Design Principles

1. **Attacker Fidelity** — Every test must replicate real attacker behavior. No synthetic or simulated attacks.
2. **Intelligence Over Speed** — A smart scan that finds business logic flaws is worth more than a fast scan that only finds XSS.
3. **Local-First, Always** — Core functionality must never depend on cloud services. AI APIs are optional enhancers.
4. **Composable Architecture** — Every component should be independently usable and replaceable.
5. **Evidence-Driven** — Every finding must include reproducible proof (request/response, screenshot, replay instructions).
6. **Progressive Autonomy** — Start with human-guided testing, evolve toward autonomous operation.

### 2.3 Non-Goals

- ❌ Source code analysis (SAST)
- ❌ Container/infrastructure scanning
- ❌ Cloud security posture management
- ❌ Compliance auditing
- ❌ Network-level penetration testing (beyond port scanning for web services)
- ❌ Social engineering
- ❌ Commercialization or SaaS delivery
- ❌ Multi-user collaboration features

---

## 3. User Persona

### Primary User: Solo Security Engineer

```
Name:           "The Operator"
Role:           Solo cybersecurity engineer / founder
Experience:     5+ years in application security
Workflow:       Validates SaaS apps before production deployment
Tools Today:    Burp Suite Pro, Nuclei, manual testing, custom scripts
Pain Points:
  - Burp requires constant interaction — can't "set and forget"
  - Business logic testing is entirely manual
  - No tool connects reconnaissance → exploitation → reporting
  - Existing AI tools are cloud-dependent and expensive
  - Testing is ad-hoc, not systematic or repeatable

Desired Outcomes:
  - Point tool at a web app → get a professional pentest report
  - Discover bugs that scanners miss (IDOR, race conditions, auth bypass)
  - Spend time on the hard problems, automate the routine ones
  - Build a testing methodology that improves over time
  - Run everything locally with full control
```

---

## 4. Requirements

### 4.1 Reconnaissance Module

The system shall discover and map the complete attack surface of a target web application.

| ID | Requirement | Priority | Notes |
|----|------------|----------|-------|
| R-001 | Technology fingerprinting (frameworks, servers, CDNs, WAFs) | P0 | Use response headers, HTML patterns, JS libraries, favicon hashes |
| R-002 | Endpoint discovery via crawling | P0 | Both static link extraction and browser-based SPA crawling |
| R-003 | API endpoint discovery | P0 | Detect REST, GraphQL, WebSocket, gRPC-web endpoints |
| R-004 | Route pattern inference | P1 | Infer parameterized routes from observed URLs (e.g., `/users/:id`) |
| R-005 | JavaScript analysis for hidden endpoints | P1 | Parse JS bundles for API calls, hardcoded URLs, WebSocket connections |
| R-006 | Open port discovery (web-relevant) | P1 | TCP scan for common web ports (80, 443, 8080, 8443, 3000, etc.) |
| R-007 | Security header analysis | P0 | CSP, HSTS, X-Frame-Options, Permissions-Policy, etc. |
| R-008 | TLS/SSL configuration analysis | P1 | Certificate chain, protocol versions, cipher suites |
| R-009 | Cookie attribute analysis | P0 | Secure, HttpOnly, SameSite, Path, Domain, Expiry |
| R-010 | Sitemap/robots.txt parsing | P0 | Discover hidden paths and disallowed routes |
| R-011 | CORS configuration analysis | P0 | Test for overly permissive origins, credential handling |
| R-012 | Subdomain enumeration (optional) | P2 | DNS brute-forcing, certificate transparency logs |
| R-013 | GraphQL introspection detection | P0 | Test for enabled introspection, suggest schema dump |
| R-014 | WAF detection and fingerprinting | P1 | Identify CloudFlare, AWS WAF, ModSecurity, etc. |

### 4.2 Web Security Testing Module

The system shall test for common web application vulnerabilities.

| ID | Requirement | Priority | Notes |
|----|------------|----------|-------|
| V-001 | Reflected XSS testing | P0 | Multi-context (HTML, attribute, JS, URL) with WAF bypass payloads |
| V-002 | Stored XSS testing | P0 | Submit payloads, verify persistence across sessions |
| V-003 | DOM-based XSS testing | P0 | Browser-based sink/source analysis via Playwright |
| V-004 | SQL injection testing | P0 | Error-based, blind boolean, blind time-based, UNION-based |
| V-005 | CSRF validation | P0 | Token presence, token validation, SameSite cookie checks |
| V-006 | SSRF testing | P1 | OOB detection via callback server, common bypass techniques |
| V-007 | IDOR testing | P0 | Multi-account parameter comparison, sequential ID testing |
| V-008 | Command injection testing | P1 | OS command injection in various parameter types |
| V-009 | Path traversal testing | P1 | Directory traversal with encoding variations |
| V-010 | File upload testing | P1 | Extension bypass, content-type manipulation, path traversal in filenames |
| V-011 | Open redirect testing | P1 | Parameter-based and header-based redirect testing |
| V-012 | Security misconfiguration | P0 | Debug endpoints, default credentials, verbose errors, directory listing |
| V-013 | HTTP request smuggling | P2 | CL.TE, TE.CL, TE.TE desync attacks |
| V-014 | Server-Side Template Injection (SSTI) | P1 | Template engine detection and exploitation |
| V-015 | XXE (XML External Entity) | P1 | OOB and in-band XXE in XML endpoints |
| V-016 | Insecure deserialization detection | P2 | Java, PHP, Python, .NET deserialization patterns |

### 4.3 Authentication & Session Testing Module

| ID | Requirement | Priority | Notes |
|----|------------|----------|-------|
| A-001 | Authentication mechanism detection | P0 | Identify session-based, JWT, OAuth, API key, etc. |
| A-002 | JWT analysis | P0 | Algorithm confusion, none algorithm, weak secrets, expiry validation |
| A-003 | Session management testing | P0 | Session fixation, session hijacking, concurrent sessions |
| A-004 | Password policy validation | P1 | Brute-force protection, lockout mechanisms, password complexity |
| A-005 | Multi-factor authentication bypass | P1 | MFA fatigue, token reuse, step skipping |
| A-006 | OAuth flow testing | P1 | State parameter validation, token leakage, open redirects in OAuth |
| A-007 | Rate limit validation | P0 | Endpoint-specific rate limit detection and bypass testing |
| A-008 | Account enumeration | P1 | Timing-based and response-based user enumeration |
| A-009 | Password reset flow testing | P1 | Token predictability, token reuse, flow bypass |

### 4.4 API Security Testing Module

| ID | Requirement | Priority | Notes |
|----|------------|----------|-------|
| API-001 | REST API testing | P0 | CRUD operation validation, auth bypass, mass assignment |
| API-002 | GraphQL security testing | P0 | Depth limiting, batch queries, alias-based DoS, field-level auth |
| API-003 | WebSocket testing | P1 | Message injection, authentication validation, origin checks |
| API-004 | API versioning discovery | P1 | Test for accessible deprecated API versions |
| API-005 | Mass assignment testing | P0 | Send extra fields to detect unprotected model binding |
| API-006 | Excessive data exposure | P0 | Analyze response payloads for unnecessary data |
| API-007 | Broken function-level auth | P0 | Test admin endpoints with user-level tokens |
| API-008 | API key/secret detection | P1 | Scan responses and JS for exposed credentials |

### 4.5 Business Logic Testing Module (Major Focus Area)

> [!IMPORTANT]
> This is the primary differentiator from existing tools. Business logic testing requires understanding application context, which is where AI integration becomes critical.

| ID | Requirement | Priority | Notes |
|----|------------|----------|-------|
| BL-001 | Privilege escalation testing | P0 | Horizontal (user→user) and vertical (user→admin) |
| BL-002 | Multi-account abuse detection | P0 | Cross-account data access, referral abuse, invitation abuse |
| BL-003 | Coupon/promo code abuse | P1 | Reuse, stacking, negative values, race conditions |
| BL-004 | Race condition testing | P0 | Single-packet attacks, last-byte synchronization, state manipulation |
| BL-005 | Workflow bypass testing | P0 | Step skipping, out-of-order operations, replay attacks |
| BL-006 | Price/quantity manipulation | P0 | Negative quantities, decimal manipulation, currency rounding |
| BL-007 | Feature flag abuse | P1 | Access to premium features without authorization |
| BL-008 | Data validation bypass | P0 | Client-side validation bypass, type juggling, boundary testing |
| BL-009 | Multi-step transaction manipulation | P1 | TOCTOU attacks, state inconsistency in multi-step flows |
| BL-010 | Referral/invitation abuse | P2 | Self-referral, invitation chain abuse |

### 4.6 Browser-Based Testing Module

| ID | Requirement | Priority | Notes |
|----|------------|----------|-------|
| B-001 | Real browser operation via Playwright | P0 | Chromium engine, full JavaScript execution |
| B-002 | Account registration automation | P0 | Fill forms, handle CAPTCHAs (manual fallback), verify email |
| B-003 | Login flow automation | P0 | Support session, JWT, OAuth flows |
| B-004 | Full application navigation | P0 | SPA-aware crawling with state tracking |
| B-005 | Network traffic capture | P0 | Capture all requests/responses via CDP |
| B-006 | Request replay and modification | P0 | Replay captured requests with modified parameters |
| B-007 | Screenshot capture for evidence | P0 | Automated screenshots at vulnerability confirmation |
| B-008 | DOM mutation monitoring | P1 | Detect XSS payload execution via MutationObserver |
| B-009 | Local storage/session storage analysis | P1 | Scan for sensitive data in browser storage |
| B-010 | Service worker analysis | P2 | Detect and analyze registered service workers |

### 4.7 Reporting Module

| ID | Requirement | Priority | Notes |
|----|------------|----------|-------|
| RPT-001 | Professional pentest report generation | P0 | Executive summary, findings, evidence, remediation |
| RPT-002 | CVSS v3.1/v4.0 scoring | P0 | Automated severity scoring with manual override |
| RPT-003 | Evidence attachment | P0 | Request/response pairs, screenshots, reproduction steps |
| RPT-004 | Multiple export formats | P1 | HTML, PDF, Markdown, JSON |
| RPT-005 | Finding deduplication | P0 | Group similar findings, avoid report noise |
| RPT-006 | Remediation recommendations | P0 | Context-aware fix suggestions per vulnerability type |
| RPT-007 | Trend analysis (cross-scan) | P2 | Track vulnerability trends across multiple scans |
| RPT-008 | Custom report templates | P2 | User-defined report formatting |

### 4.8 AI Integration Requirements

| ID | Requirement | Priority | Notes |
|----|------------|----------|-------|
| AI-001 | LLM-assisted attack hypothesis generation | P0 | Generate test cases from application context |
| AI-002 | AI-driven workflow discovery | P0 | Understand application flows from crawl data |
| AI-003 | Intelligent response analysis | P1 | Detect anomalies and vulnerability indicators in responses |
| AI-004 | Attack chain construction | P1 | Link findings into exploitable chains |
| AI-005 | Report narrative generation | P1 | Generate human-readable finding descriptions |
| AI-006 | Local LLM support | P0 | Ollama integration for fully offline operation |
| AI-007 | Cloud LLM support | P1 | OpenAI, Anthropic, Google APIs for higher quality |
| AI-008 | Cost-aware AI usage | P0 | Budget controls, token tracking, fallback to local models |
| AI-009 | AI confidence scoring | P1 | Confidence levels on AI-generated findings |
| AI-010 | Human-in-the-loop escalation | P0 | Flag low-confidence findings for manual review |

---

## 5. Use Cases

### UC-001: Full Application Security Assessment

```
Trigger:    Operator provides a target URL and credentials
Flow:
  1. System performs passive reconnaissance (headers, cookies, TLS)
  2. System crawls the application (both HTTP and browser-based)
  3. System discovers API endpoints (REST, GraphQL, WebSocket)
  4. System maps the application's authentication model
  5. System runs automated vulnerability scanners (XSS, SQLi, etc.)
  6. System performs browser-based business logic testing
  7. AI agents analyze findings and generate attack chains
  8. System produces a professional pentest report
Duration:   30 minutes to 4 hours depending on application size
Output:     HTML/PDF report with CVSS-scored findings and evidence
```

### UC-002: Targeted Business Logic Testing

```
Trigger:    Operator defines specific business flows to test
Flow:
  1. Operator describes the flow (e.g., "checkout process")
  2. AI agent plans test scenarios (price manipulation, step skipping, race conditions)
  3. Browser automation executes the scenarios
  4. System captures evidence for each anomaly
  5. AI validates findings and scores confidence
Output:     Targeted findings with reproduction steps
```

### UC-003: API Security Audit

```
Trigger:    Operator provides API base URL and authentication
Flow:
  1. System discovers endpoints (OpenAPI spec, crawling, JS analysis)
  2. System maps authentication/authorization model
  3. System tests each endpoint for BOLA, BFLA, mass assignment
  4. System tests GraphQL for depth bombs, introspection, alias DoS
  5. System tests rate limiting
  6. System produces API-specific security report
Output:     API security assessment with endpoint-level findings
```

### UC-004: Authentication/Authorization Deep Dive

```
Trigger:    Operator provides multiple account credentials (admin, user, guest)
Flow:
  1. System maps all endpoints accessible per role
  2. System performs Autorize-style cross-role testing
  3. System tests for horizontal privilege escalation (user A → user B)
  4. System tests for vertical privilege escalation (user → admin)
  5. System tests JWT/session security
  6. System validates MFA implementation
Output:     Access control matrix with violations highlighted
```

### UC-005: Continuous Security Monitoring

```
Trigger:    Operator schedules recurring scans
Flow:
  1. System runs configured scan profile on schedule
  2. System compares results against baseline
  3. System alerts on new findings or regressions
  4. System maintains historical trend data
Output:     Delta report showing new/resolved findings
```

---

## 6. User Interface Requirements

### 6.1 UI Architecture

The platform uses a **web-based local UI** accessible via browser at `localhost`.

```
┌──────────────────────────────────────────────────────┐
│                    LastResort UI                       │
│                                                       │
│  ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐│
│  │Dashboard │  │ Scan     │  │ Findings │  │Reports ││
│  │         │  │ Config   │  │ Browser  │  │        ││
│  └─────────┘  └──────────┘  └──────────┘  └────────┘│
│                                                       │
│  ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐│
│  │Proxy    │  │ HTTP     │  │ AI       │  │Settings││
│  │History  │  │ Editor   │  │ Console  │  │        ││
│  └─────────┘  └──────────┘  └──────────┘  └────────┘│
└──────────────────────────────────────────────────────┘
```

### 6.2 Key UI Views

| View | Purpose |
|------|---------|
| **Dashboard** | Active scans, recent findings, system health |
| **Target Configuration** | Add targets, credentials, scope, scan profiles |
| **Scan Control** | Start/stop/pause scans, view progress, phase indicators |
| **Proxy History** | Intercepted request/response browser (like Burp Proxy History) |
| **HTTP Editor** | Manual request crafting and replay (like Burp Repeater) |
| **Findings Browser** | All discovered vulnerabilities with filtering and search |
| **AI Console** | AI agent activity log, hypothesis display, human-in-the-loop prompts |
| **Report Generator** | Configure and generate reports |
| **Settings** | API keys, proxy config, AI model selection, plugin management |

### 6.3 UI Technology

- **Framework:** React with TypeScript (rich ecosystem, component libraries)
- **Styling:** Modern dark theme with glassmorphism (matches security tool aesthetic)
- **Communication:** WebSocket for real-time scan updates, REST for CRUD
- **State:** React Query for server state, Zustand for client state

---

## 7. Performance Requirements

| Metric | Target |
|--------|--------|
| Concurrent HTTP requests | 500+ simultaneous connections |
| Request throughput | 1,000+ requests/second for fuzzing |
| Scan startup time | < 5 seconds from config to first request |
| Browser automation sessions | 5+ concurrent Playwright instances |
| Database write throughput | 10,000+ HTTP transactions/second |
| UI responsiveness | < 100ms for all interactions |
| Memory footprint (idle) | < 200MB |
| Memory footprint (active scan) | < 2GB |
| Report generation | < 30 seconds for 100-finding report |

---

## 8. Constraints

| Constraint | Details |
|-----------|---------|
| **Platform** | Windows primary, Linux/macOS secondary |
| **Network** | Local execution, no cloud dependency for core functions |
| **Storage** | SQLite for structured data, filesystem for large blobs |
| **AI** | Must work fully offline with Ollama; cloud APIs optional |
| **Browser** | Playwright with Chromium (most compatible) |
| **Single User** | No multi-tenancy, no authentication on the local UI |
| **Authorized Targets Only** | All targets owned/authorized by operator |

---

## 9. Success Metrics

| Metric | MVP Target | v1.0 Target |
|--------|-----------|-------------|
| Vulnerability classes covered | 10+ | 25+ |
| False positive rate | < 30% | < 15% |
| Business logic bugs found (vs manual) | 30% of manual | 60% of manual |
| Time to complete full scan | < 2 hours | < 1 hour |
| Report quality (vs manual pentest report) | Functional | Professional-grade |
| Scan coverage (endpoints tested / discovered) | > 80% | > 95% |

---

## 10. Glossary

| Term | Definition |
|------|-----------|
| **BOLA** | Broken Object-Level Authorization (= IDOR) |
| **BFLA** | Broken Function-Level Authorization |
| **CDP** | Chrome DevTools Protocol |
| **CVSS** | Common Vulnerability Scoring System |
| **DAST** | Dynamic Application Security Testing |
| **IDOR** | Insecure Direct Object Reference |
| **OOB** | Out-of-Band (callback-based detection) |
| **SPA** | Single Page Application |
| **SSRF** | Server-Side Request Forgery |
| **SSTI** | Server-Side Template Injection |
| **TOCTOU** | Time-of-Check to Time-of-Use |
| **WAF** | Web Application Firewall |
