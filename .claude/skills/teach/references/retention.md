# Mastery that survives the session

Use for repeated study, codebase-wide learning, or a requested progress map. A one-off lesson needs only its checklist and next review; avoid maintaining unused metrics. Keep state in the same Markdown record rather than introducing an unrelated global database.

## Compact module record

Use stable module keys derived from meaningful subsystems or topic names, not individual question wording. Reuse existing keys. Store the repository's canonical path and relevant revision so similarly named projects do not share progress accidentally.

For each module retain:

- Source paths and behavior/revision assessed.
- Status: **unseen**, **learning**, **demonstrated**, or **retained**.
- Evidence links to question attempts and the exact criteria demonstrated.
- Remaining misconception or missing prerequisite.
- Last independent pass date, current review interval, and next review date.

**Unseen** means no evidence. **Learning** means the learner has begun but criteria remain open. **Demonstrated** means all agreed module criteria passed, including a fresh application. **Retained** requires an independent pass on a later scheduled review. Keep confidence conversational and grounded in evidence; avoid presenting a made-up probability as a measured fact.

Record each attempt as it occurs. Preserve historical evidence if later behavior changes; mark it stale and recheck affected criteria instead of erasing progress. Reading an explanation, hints, repeated answer text, and skips cannot advance mastery status.

## Spaced retrieval

These are transparent defaults, not claims of an optimal scientific schedule:

| Outcome | Next review |
| --- | --- |
| Partial, incorrect, or assisted attempt | Repair now if the learner wants; review tomorrow. |
| First independent demonstration | Tomorrow. |
| Independent pass on a later due review | Expand the interval: 1 → 3 → 7 → 14 days. |
| Miss at a later review | Reopen the affected criterion, repair, and reset to 1 day. |
| Skip | Keep the existing evidence and due date; record deferral. |

Use the learner's local calendar date. Same-session variants can close a learning gap but do not count as later retention reviews or repeatedly advance the interval. Changed behavior needs fresh validation before reusing an old pass. Overdue review means retention is unverified; it does not prove the learner forgot.

At a later session, prioritize the pending question and active scope first, then materially changed code, overdue reviews, weak relevant modules, and unseen high-value components. Avoid quizzing an entire repository merely because discovery found many files. Sample architecture, business logic, state transitions, and error paths; skip boilerplate unless it contains an important contract.

## Show a useful knowledge map

When useful, show a compact table: `Module | Status | Evidence or gap | Next review`. This is a knowledge-risk map: high-impact subsystems with weak or stale understanding are good study targets. Show the discovered scope and coverage denominator before giving an overall fraction. Never equate a handful of passed questions with repository-wide expertise.

Close a review with the strongest demonstrated skill, the most consequential remaining gap, and one recommended next focus. Do not schedule reminders or background jobs unless requested; a due date in a record is not an automation.

## Optional game layer

Keep the default presentation calm. If the learner asks for gamification, use a lightweight score: +10 XP for an independently passed criterion, +20 for a fresh integrated challenge, each awarded once per assessment or later scheduled review. Hints, partials, skips, and same-day retries do not farm XP. Record awards with evidence. Simple milestones such as first independent trace or first retained module are enough; streaks and elaborate badge catalogs are optional only when requested.

XP represents activity and challenge completion. It cannot replace criterion evidence, clear a gate, or imply expertise. A time limit remains a time limit even when a bonus challenge is available.
