# LastResort Architecture Review

## 1. Current State
LastResort was a hybrid security scanner acting as a blind crawler with AI summarization. 
- **AI**: Handled discovery and reporting, but lacked direct attack execution capabilities.
- **Scanner**: Handled exploitation blindly using `net/http` and hardcoded payloads.
- **Playwright**: Used as a screenshot collector.

## 2. Desired State (Agent-Driven)
The architecture has been unified into an autonomous agent model:
- **AI**: Now plans attacks, formulates payloads, and evaluates feedback.
- **Playwright (Browser)**: The primary execution environment.
- **Verification**: Occurs via DOM inspection, not string reflection.

## 3. Implemented Changes
- **BrowserAttackContext**: Injected into the AI prompt for deep situational awareness.
- **ActionResult**: Synchronous feedback loop for every browser action.
- **SessionJournal**: Persistent memory layer for complex, multi-step workflows.
- **Agent-Driven SQLi**: Hardcoded scanner logic removed. Playwright now executes AI-generated payloads.