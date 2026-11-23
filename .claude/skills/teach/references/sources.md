# Synthesis and provenance

The `teach` skill is a synthesis, not four separate skills loaded together. Its original staged lessons, learner restatements, Markdown checklist, and evidence-based advancement remain the backbone. Source behavior was inspected on 2026-11-23; this skill does not require upstream installation, runtime downloads, or updates.

| Source | Core contribution | Where it lives |
| --- | --- | --- |
| [nessielabs/codequiz](https://github.com/nessielabs/codequiz), [skill source](https://github.com/nessielabs/codequiz/blob/main/SKILL.md) | Real-code questions at increasing depths, stable module mastery, spaced repetition, knowledge-risk mapping, integrated challenges, and optional game rewards. | Main learning loop, question-design.md, retention.md. |
| [quiz-gate listing](https://www.claudepluginhub.com/skills/nbbaier-skills/quiz-gate), [upstream skill](https://github.com/nbbaier/agent-skills/blob/main/skills/quiz-gate/SKILL.md) | Defend the work in review: decisions, failure modes, deviations, boundaries, honest pass/partial/fail grading, gap repair, and user override. | change-debrief.md and question-design.md. |
| [debriefing listing](https://skillsmp.com/creators/agent-engineer-master/skill-engineer/engineering-debriefing-code-changes), [upstream skill](https://github.com/Agent-Engineer-Master/skill-engineer/blob/main/engineering/debriefing-code-changes/SKILL.md) | Git-grounded debriefs, high-value file selection, architecture and pattern evidence, tradeoffs, caveats, and practical application. Its debrief-rubric.md and concept-map.md references were also inspected. | change-debrief.md and the source-grounding rules. |
| [lusipad/zhizhi quiz-me](https://github.com/lusipad/zhizhi/blob/main/skills/quiz-me/SKILL.md), [requested raw source](https://raw.githubusercontent.com/lusipad/zhizhi/main/skills/quiz-me/SKILL.md) | Explain why and the mental model; inspect unchanged dependencies beyond the diff; keep durable context; use low-friction quizzes, variant retests, and trustworthy PASS / NOT YET verdicts. | Durable record, change-debrief.md, question-design.md. |

The two marketplace pages were unavailable to direct fetch; their corresponding upstream GitHub skill files supplied the actual instructions. The upstream primary sources were read rather than inferring content from listing descriptions.

## Deliberate integration choices

- Preserve incremental teaching. A change report maps the whole system, but instruction and verification proceed in small stages; quiz-first mode avoids a spoiler lesson.
- Preserve strict mastery evidence. Partial work is learning, not a pass; fresh applications and later reviews establish stronger evidence than a numerical confidence increment.
- Combine easy quiz entry with real reasoning. Multiple choice reduces friction, while traces and teach-backs verify the mechanism where needed. No fixed multiple-choice ratio overrides the learning goal.
- Keep one durable Markdown record. The original teach workflow already authorizes local progress tracking; do not import repeated save-approval prompts from the debrief source. Respect chat-only requests and existing file conventions.
- Keep gates scoped and overridable. A comprehension verdict concerns assessed understanding and does not confer deployment safety or new action permissions.
- Keep games optional. Do not import mandatory XP banners, surprise random spot-checks, automatic upstream fetching, a separate global state directory, or mandatory discovery subagents. Those are implementation choices, not the teaching mechanisms this synthesis needs.

The guidance is newly written around the combined workflow. These links document the ideas used and support future maintenance; no copied upstream implementation or external service is required.
