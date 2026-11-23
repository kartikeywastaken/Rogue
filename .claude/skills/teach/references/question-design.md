# Questions, grading, and comprehension gates

## Choose the question for the evidence needed

Use increasing depth as demonstrated understanding grows:

| Type | Evidence sought | Example shape |
| --- | --- | --- |
| Explain | Purpose and local mechanism | What problem does this block solve, and how? |
| Predict or trace | Execution and state transitions | Given this input, what runs and what reaches the caller? |
| Debug or test | Failure reasoning and falsifiable checks | If this event arrives twice, what changes and where would a test expose it? |
| Connect | Dependencies across components | How does this caller's state reach that consumer, and which invariant must hold? |
| Defend or transfer | Design judgment on a new case | What would removing this boundary break, and when would an alternative be better? |

Ground every code question in source already read. Show a focused real excerpt, file location, and feature context where useful. Ask about behavior, not recall of identifiers or line numbers. Avoid hypothetical alternatives that were never meaningful for the actual constraints.

For a quick change quiz, favor multiple choice with misconception-based distractors, plus a short trace or reasoning check. Permit one-line answers such as `1B 2D 3: caller → validator → store`; do not require essays. Use free-form teach-backs when causal reasoning is the criterion. Vary correct choice positions and avoid cues from length, jargon, obviously silly distractors, or preselected/recommended options. Respect an explicitly requested format.

A multiple-choice selection can establish a narrow prediction; it cannot alone establish that the learner can explain or defend the mechanism. Request a brief reason or a new application for that broader criterion. Keep follow-ups within the requested budget; if the budget ends, record the unresolved criterion.

Do not display an answer key alongside unanswered questions, including in the progress record. Record the question, source, and criterion instead; derive grading from inspected evidence. If the user asks for a solution, give it and label the attempt assisted. Practice is allowed to be open-book; reasoning still matters. A requested closed-book gate should use fresh variants after answer exposure.

## Grade precisely, allow disagreement

- **Pass:** correct causal reasoning and the conditions/consequences material to this criterion, even in informal or terse wording.
- **Partial:** the main direction is right but a material condition, dependency, or consequence is missing. Keep the criterion open.
- **Fail:** incorrect reasoning or no demonstrated understanding. "I don't know" is useful diagnostic information; teach without shame.
- **Assisted:** a revealing hint or solution was provided; record what was learned, but require an independent fresh application before checking mastery.
- **Skipped/deferred:** no mastery evidence; respect the choice without surprise spot-checks or lowering previously demonstrated knowledge solely for skipping.

For a partial or fail, acknowledge what was correct, name the exact gap, explain it with source evidence, and ask a variant that changes the input, condition, or component. Repetition of the supplied answer is not verification. Do not inflate a grade for effort, agreement, confidence, or good prose.

If the learner disputes a grade, reread the relevant code and assumptions. Correct an ambiguous question or incorrect assessment, amend the recorded evidence, and avoid penalizing the learner for the teacher's mistake. If behavior cannot be established from the artifacts, leave the criterion unverified rather than guessing an answer key.

For a multi-question diagnostic or integrated challenge, avoid feedback that gives away unanswered dependent questions: gather attempts first, then grade and repair. In ordinary teaching, feedback and a fresh check happen before stage advancement.

## Gate and integrated challenge

Use an integrated challenge at the end of a stage group or goal: a bounded sequence connecting purpose, a realistic input, a failure, a dependency, and a changed assumption. A learner-requested "boss fight" is this same practical challenge with optional game presentation; it does not need a separate engine.

An explicit change gate normally asks three to six high-value questions, fewer for a small conceptual surface. Before presenting them, name the assessed scope without revealing solutions. After answers, grade each as pass/partial/fail and attach assistance status where applicable.

- **PASS —** every agreed criterion in this assessment was independently demonstrated. State the bounded scope.
- **NOT YET —** list the open topics and the next repair/recheck. Partial answers, stopping early, and promises to study later do not clear a gate.

The verdict certifies understanding of the assessed material, not bug freedom or permission to ship. Preserve PASS / NOT YET in English; teach and explain verdicts in the learner's language. A user can decline or override the gate: record the open learning gaps once and continue work already authorized. Do not transform a learning preference into control of their repository or demand another approval for an authorized action.
