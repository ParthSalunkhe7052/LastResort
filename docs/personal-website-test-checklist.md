# Personal Website Security Testing Checklist

This guide provides a step-by-step checklist and best practices for performing local security assessments on your personal website using **LastResort**. Following these rules ensures that scans run safely, legally, and without disrupting your site's availability or third-party integrations.

---

## 1. Scoping & Authorization Checklist

Before launching any active scanner, verify that you have permission and control over all endpoints:

- [ ] **Confirm Sole Ownership**: Ensure you own or are explicitly authorized to test the domain. Never scan corporate, school, or other public websites without a written authorization/consent form.
- [ ] **Define Scan Boundaries**: Ensure only your domain host is targeted. LastResort automatically limits crawling and active fuzzing to the target hostname, but double-check that you haven't included third-party domains in active repeaters.
- [ ] **Identify Mutative Forms**: Locate any contact forms, newsletter sign-ups, or comment sections. Active CSRF/XSS scanning will attempt to submit form fields, which can lead to email spam or DB bloat. Exclude these forms or monitor them closely.
- [ ] **Verify Third-Party APIs**: Ensure the application doesn't trigger SMS/email notifications or external billing APIs (Stripe, Twilio) when forms are fuzzed.

---

## 2. Scan Execution Best Practices

To protect your host resource limits and avoid false positives:

### A. Phase-by-Phase Rollout
1. **QUICK Profile**: Always start with a `QUICK` scan profile first. This executes passive analysis on headers and cookies and builds your initial endpoint map.
2. **STANDARD Profile**: Once the site's structure is crawled successfully, run `STANDARD` active checks on individual routes.
3. **DEEP Profile**: Execute business logic checks (multi-account, race condition) only if the application uses session management or authentication.

### B. Rate-Limiting & WAFs
- Set the maximum concurrency limits to a low tier (e.g., 5 requests per second) to avoid triggering hosting provider rate-limit bans (e.g., Cloudflare, Vercel).
- If your personal site is behind a CDN/WAF (like Cloudflare), add your local public IP address to the temporary WAF bypass/whitelist rule during the scan to prevent getting your IP blocked.

---

## 3. Local Proxy Setup Checklist

To capture traffic and perform manual analysis through the proxy:

- [ ] **Trust CA Certificate**: If manually intercepting HTTPS traffic with a browser, export the generated CA certificate from `data/certs/ca.crt` and trust it *only* in your testing browser/profile. Never install development CAs into your system-wide root trust store.
- [ ] **Use a Separate Browser Profile**: Configure proxy settings (`127.0.0.1:8080`) inside a dedicated browser profile (like Firefox with FoxyProxy) to keep personal traffic separate from security logs.
- [ ] **Check Scope Warnings**: If non-scope URLs appear in your Proxy History, double-check your target URL configuration.

---

## 4. Remediation Checklist

When the scan finishes and you review the generated report:

- [ ] **Deduplicate Findings**: Review matching fingerprints to see if multiple parameters suffer from the same root bug.
- [ ] **Run AI Narrative Enhancer**: Boot the Python AI service to get detailed explanations and tailored fixing codes for your language/stack.
- [ ] **Check Security Headers**: Add missing security headers (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`) identified in passive analysis.
- [ ] **Verify Fixes**: Re-run the specific active probe using the HTTP Repeater to verify that your code changes successfully patched the vulnerability.
