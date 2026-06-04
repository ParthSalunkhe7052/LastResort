# Dependency Analysis & Flow Map

## Current Flow (Deprecated)
`AI -> (Discovery) -> Orchestrator -> Scanner (net/http) -> (Blind Exploit) -> Reporter`

## Desired Flow (Implemented)
`AI -> (Plan Attack) -> Orchestrator -> Browser (Playwright) -> (Execute Exploit) -> Verifier (DOM Check) -> Evidence -> Reporter`

## Key Interfaces
1. **AttackPlanner**: Now driven by the AI service via `GenerateAttackPayload`.
2. **AttackExecutor**: Refactored to utilize the `BrowserService` (Playwright).
3. **AttackVerifier**: Now utilizes `ActionResult` from the DOM to determine exploit success.
4. **SessionJournal**: New dependency added to Orchestrator to maintain workflow state.