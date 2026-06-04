# Migration Plan

## Bypassed Attack Audit
The following attacks currently bypass Playwright and use `net/http` directly. They must be migrated to the Agent-Driven model.

| Attack Type | File | Risk Level | Estimated Effort | Priority |
| :--- | :--- | :--- | :--- | :--- |
| **XSS** | `internal/scanner/xss.go` | High | 2 Days | P0 |
| **CSRF** | `internal/scanner/csrf.go` | High | 2 Days | P0 |
| **Path Traversal** | `internal/scanner/recon.go` | Medium | 1 Day | P1 |
| **Rate Limiting** | `internal/scanner/ratelimit.go` | Low | 1 Day | P2 |

## Migration Steps
1. **Deprecate Hardcoded Payloads**: Remove static payloads from the scanner package.
2. **Implement Hypothesis Generation**: Route the attack intent through the AI.
3. **Browser Execution**: Execute the payload via Playwright DOM interactions.
4. **DOM Verification**: Verify the exploit within the browser context (e.g., checking for alerts in XSS).