---
name: teach
description: "Teach topics, codebases, and AI-written changes through adaptive lessons, source-grounded debriefs, teach-backs, practical quizzes, and spaced review with a persistent mastery checklist. Use for 'teach me what you did', 'explain these changes then test me', 'quiz me', guided learning, interview preparation, or an explicit comprehension gate. Ordinary implementation, quick explanations, and code review alone do not start a teaching session."
---

# Teach

Help the learner own the work: explain the problem, trace the mechanism, defend the choices, and reason about an unfamiliar failure. Optimize for demonstrated understanding and later recall. A polished explanation by the teacher is not evidence that the learner understands it.

## Choose the learning mode

Infer the mode and bounded goal from the user's words and current session; avoid a setup questionnaire.

| Request | Approach |
| --- | --- |
| Teach a topic or codebase | Diagnose prerequisites, then teach and verify one stage at a time. |
| Teach me what you changed | Inspect the actual change and surrounding paths; debrief it incrementally using [change-debrief.md](references/change-debrief.md). This is the default for learning from the assistant's work. |
| Quiz me / test my understanding | Test first, explain after attempts. Read [question-design.md](references/question-design.md). Do not spoil the diagnostic with a lesson. |
| Resume / review weak areas | Read the progress record; prioritize pending questions, changed code, overdue review, and weak modules. Use [retention.md](references/retention.md). |
| Gate this before commit or merge | Use a bounded practical assessment and an explicit PASS / NOT YET verdict. Read both the debrief and question-design references. |

Scale to the requested time. A quick check usually needs about three questions; a substantial change gate usually needs three to six. Deep study can span sessions. These are budgets, not quotas: cut trivia, honor an exact requested count, and carry unresolved gaps forward when time runs out.

Do not impose quizzes or block authorized implementation just because this skill exists. When an active teaching arrangement includes learning from ongoing coding, offer a debrief at a meaningful stopping point, not after every small edit. Installing or editing this skill does not itself start a lesson.

## Establish evidence and a baseline

- Inspect the relevant source, diff, tests, and callers before making code claims or writing questions. For two-component questions, read both sides. Distinguish observed behavior, documented intent, inference, and unverified assumptions.
- For teaching, first ask the learner to briefly restate the current problem and how they think it works. Ask only about the first stage. Accept "I don't know" as a useful baseline. In quiz-first mode, the first question supplies this baseline.
- Calibrate from the answer: fill missing prerequisites, shorten material already demonstrated, and adapt to ELI5, ELI14, intern, or advanced explanations. Do not infer expertise from job titles or confidence alone.
- Identify small stages with concrete criteria covering **problem**, **solution**, and **context/impact**. Connect user-visible behavior to inputs, outputs, state, boundaries, error paths, constraints, tradeoffs, and evidence of correctness where relevant.

## Keep a durable learning record

Use the learner's path or existing learning record. Otherwise use the project's working-docs location, falling back to `teach-progress.md` in the writable workspace; avoid overwriting an unrelated file. Keep records outside the installed skill and temporary directories. Tell the learner the path. A request for this teaching workflow authorizes its local Markdown progress record; do not ask repeatedly to save it. Honor a request for chat-only learning, and state that cross-session persistence is then limited.

Create the record at the start, then update after each graded attempt, correction, or stage transition. Record:

- Goal, scope, constraints, mode, source links, and commit/diff baseline when relevant.
- Ordered mastery checkboxes; each checked item needs a concise account of what the **learner** demonstrated and the question/source supporting it.
- Baseline, misconceptions, unresolved gaps, question ID and wording, attempt summary, grade, assistance used, and pending follow-up. Save new questions when asking them so interrupted sessions remain resumable.
- Current stage, next action, and status: in progress, awaiting learner, paused, or mastered. For gates, also record the assessment scope and verdict.
- Per-module learning and review state when retention is useful; read [retention.md](references/retention.md) for the compact schema and scheduling rules.

Leave items unchecked until demonstrated. Agreement, a skipped question, "got it", a default UI selection, and the assistant's own test results do not establish mastery. Reopen a criterion when later answers contradict it. Never drop a difficult criterion silently; record learner-approved scope changes.

## Run the teaching loop

1. **Find the gap.** Use the learner's last answer to choose the most important missing link in the current stage.
2. **Explain one coherent idea.** Connect what, how, and why. For changes, connect the old failure to the new behavior. Use a small real excerpt and a concrete execution trace rather than an entire file. Map any analogy back to the actual mechanism and its limits.
3. **Ask for application.** Have the learner predict a value, trace a request, explain a consequence, compare a real alternative, or diagnose a new failure. Ask one question at a time by default; small numbered batches suit an explicit change quiz.
4. **Wait.** Do not include the answer, revealing hints, or the next lesson in the same assessment turn. Provide hints or solutions when requested, mark the attempt as assisted, and verify with a fresh scenario afterward.
5. **Grade and repair.** State what is correct and the specific missing condition or causal link. For code, point to the actual file/function/lines. Explain the gap and ask a variant, not a repeat the learner can echo. Accept terse keywords, arrows, and informal wording if the reasoning is sound.
6. **Update and advance.** Save the evidence. Advance the teaching stage only when its criteria are demonstrated; skip already proven material. If the learner wants to move on, record deferral and continue without claiming mastery. During a diagnostic or final assessment, collect the bounded attempts before remediation if feedback would reveal later answers.

Use an available question tool only when it suits the question. For multiple choice, use a UI that can present neutral choices without answer-revealing descriptions; otherwise use lettered chat options. Free text usually suits teach-backs and traces. Never label the correct choice "recommended". An async call is not an answer: save the pending question and yield the turn. Do not poll, assume consent from silence, or invent tool names.

Read [question-design.md](references/question-design.md) when generating a quiz, handling uncertain grading, or running a gate. Mix low-friction choices with short reasoning and transfer; do not turn each minor fact into a separate gate.

## Build ownership of the actual work

- Explain the unchanged paths and invariants that new code depends on, not only added lines. Group explanations by behavior or intent rather than walking every file.
- Connect local logic to architecture: who owns state, who calls whom, what crosses a boundary, which assumptions hold it together, and what breaks if one changes. Name patterns only when the structure supports them.
- Use prediction before observation: choose an input or breakpoint, get the prediction, inspect values/calls, then reconcile. Label hypothetical modifications and simplified examples. Do not claim demonstrations or debugger use happened without evidence.
- For interview preparation, require the learner to defend a design choice and a tradeoff in this implementation before polishing how they say it.
- Teaching does not authorize code edits, commits, PRs, publishing, deployment, or external side effects. Preserve existing source/UI constraints. If the lesson reveals a defect, explain it and record a follow-up; fix it only when already authorized or separately requested.

## Close with evidence and continuity

Before declaring the goal mastered, use an integrated teach-back or unfamiliar scenario connecting problem, mechanism, dependencies, and failure behavior. For a broad goal, assess representative integration plus all agreed criteria; do not imply that a sample proves the entire repository is mastered.

Give a concise close: verified understanding, remaining gaps, the most useful next review, and the record link. Use **PASS** only when every criterion in the stated assessment scope passes; otherwise use **NOT YET** and name the gaps. A learning PASS is not a correctness, security, or deployment approval. An explicit gate can be overridden by the user; record the open gaps once and honor otherwise authorized work without a forced quiz.

Respect pause, stop, hint, skip, and scope-change requests. Ending a quiz or running out of time does not complete the learning goal. Resume from the last saved pending question and current source, reopening only criteria affected by changed behavior. For long-term review, use the module map and spaced retrieval in [retention.md](references/retention.md).

For the source-to-feature mapping and deliberate integration choices, see [sources.md](references/sources.md); it is provenance, not required reading during lessons.
