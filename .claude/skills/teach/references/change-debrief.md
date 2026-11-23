# Learning from implementation changes

Use for a concrete code-change debrief or comprehension gate. Keep the learner-facing lesson staged; the durable report can hold the overall map without dumping every future stage into chat.

## Establish what actually landed

Infer the target from the request and session: working tree, staged changes, a named commit/range, or branch against a verified base. Read repository instructions and `git status --short` first. Useful read-only tools include `git diff`, `git diff --cached`, `git show`, and `git log`; inspect untracked source separately because ordinary diffs omit it. Avoid silently choosing HEAD~1 or a guessed base branch. If the range is genuinely ambiguous, ask one focused question and inspect available source meanwhile.

Record the baseline and whether it includes staged, unstaged, or untracked work. Separate the assistant's work from unrelated changes when evidence allows; do not attribute every dirty file to the assistant. If an earlier passed gate exists, include all relevant behavior changes since its recorded baseline. A changed working tree invalidates only affected evidence, but a gate verdict applies only to its assessed snapshot.

Without a usable diff, inspect current source for a codebase lesson. Ask for the missing baseline before claiming a before/after comparison. Without source access, label a conceptual lesson as such and request the artifact needed for code-specific verification; never reconstruct landed code from conversation alone.

Read changed logic, relevant tests, callers, callees, configuration, and data contracts. Find behavior affected in unchanged code: a different branch becomes reachable, a default starts applying, execution order shifts, or an existing consumer receives new data. Read relevant implementation notes, especially deviations and spec gaps, if present. Do not invent design history from the final code.

For a large change, shortlist roughly three to seven files or subsystems with the highest learning value. Prioritize business logic, state ownership, boundaries, failure handling, and tests. Record what the shortlist excludes so a sampling exercise does not become a claim about the full change.

## Build the debrief in the learning record

Group by intent. Cover these ideas, combining sections for small changes:

1. **Why:** the concrete old failure or new requirement, affected behavior, and constraints. Use an old/new input-output example when possible.
2. **Mental model:** the key mechanism in a short explanation, trace, diagram, or analogy. Explicitly map it to the real code.
3. **What changed:** a few meaningful behavior changes and the key files/functions to understand first.
4. **What it depends on:** pre-existing paths, interfaces, ownership, ordering, formats, and invariants; this is often the part the diff hides.
5. **Choices and limits:** observed architecture, real alternatives, accepted tradeoffs, deviations from the plan, and what remains out of scope.
6. **Where it can break and how to check:** evidence from inspected tests and paths, plus tests not run or cases not covered. Keep proposed checks distinct from executed results.

For each significant decision, connect behavior, source location, rationale, tradeoff, and one consequence. Label inferred intent explicitly. A concept map is useful when there are several abstractions: concept → source evidence → structural reason → practical consequence. If no named pattern helps, explain the local shape plainly.

Consider edge cases, performance, security/privacy, and technical debt. Mention a concern only when grounded in inspected code, or state that no obvious concern was found in the inspected scope. Do not invent hazards to fill a report or claim this educational pass is a comprehensive audit.

Use one progress document by default. Split a long report into a linked local file only when navigation warrants it or the learner requests it. Put report artifacts alongside the durable learning record. A standalone HTML report is optional when requested, not a prerequisite for teaching.

## Turn the debrief into ownership checks

Select questions about decisions the learner will need to defend or behavior they may need to debug. A substantial change should normally cover an unchanged dependency, an execution trace, a realistic failure/boundary, and a real design tradeoff. Test plan deviations, test placement, or deliberate limits when they are material. Omit inapplicable categories rather than padding.

For an explicit gate, define the criteria and assessed snapshot before asking. Use the grading and override rules in [question-design.md](question-design.md). Passing this learning assessment does not authorize a commit or establish production safety.
