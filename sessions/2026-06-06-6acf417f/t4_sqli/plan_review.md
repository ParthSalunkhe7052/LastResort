# Plan Review: Fix Duplicate SQLi Execution Implementation Plan

**Status**: ✅ APPROVED
**Reviewed**: 2026-06-06

## 1. Structural Integrity
- [x] **Atomic Phases**: Phasing from shared logic -> Agent implementation -> Orchestrator cleanup -> Test verification is logical and safe.
- [x] **Worktree Safe**: The plan operates on specific files and doesn't rely on uncommitted state.

*Architect Comments*: The migration of logic to `internal/scanner` is the correct way to avoid circular dependencies between `attack` and `orchestrator`.

## 2. Specificity & Clarity
- [x] **File-Level Detail**: Specific files like `internal/orchestrator/phase.go`, `internal/attack/sql_agent.go`, and `internal/orchestrator/orchestrator_test.go` are targeted.
- [x] **No "Magic"**: Steps are clear about what to remove and what to add.

*Architect Comments*: The logic for "static payload fallback" in Phase 2 is clearly defined as a baseline that runs before AI planning.

## 3. Verification & Safety
- [x] **Automated Tests**: Every phase has build or test commands.
- [x] **Manual Steps**: Log verification is mentioned.
- [x] **Rollback/Safety**: No database migrations required; changes are code-only and easily reversible.

*Architect Comments*: Ensure that `go test ./internal/attack/...` is run to verify `AgentSQLiExecutor` changes.

## 4. Architectural Risks
- **Redundancy**: Consolidating modules reduces target load and simplifies findings management.
- **Dependency**: Moving verification to `internal/scanner` is a clean architectural move.
- **Browser Health**: Adding the check in `Start` prevents downstream failures in all browser-dependent modules.

## 5. Recommendations
- Proceed to implementation. Ensure the `IsOnline` check in `orchestrator.go` includes a user-facing log message via `onLog` or similar if available, or just standard logging if not.
