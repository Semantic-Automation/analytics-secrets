# Development Log — Guidelines & Format

How to keep the per-repo development log. Mirrors the style used in the
original monorepo (`development_log_*.md`) so logs read consistently across
all five `Semantic-Automation` repos.

## File naming

One file per workday, named `development_log_YYYY-MM-DD.md` (e.g.
`development_log_2026-08-14.md`). Multiple sessions on one day → append
sections to the same file; do not overwrite.

## Scope of detail (the rule)

- **Very detailed** — when the change does **not** have its own dedicated doc:
  walk through the problem, the root cause, what you tried, what merged, and
  what's pending. Include enough that a reader can reproduce the reasoning
  without the code open.
- **Summarized + linked** — when a dedicated doc exists (a plan, a design doc,
  a runbook, a test report): write a short summary of *what changed and why*
  and link the doc. Do not duplicate the doc's content.

  Dedicated docs live in `docs/`. Examples: `docs/network-hardening.md`,
  `docs/ops-runbooks.md`, `docs/onboarding-cleanroom.md`, `docs/repo-split.md`.
  If in doubt, the log is the summary + link, the doc is the detail.

## Format

```markdown
# Development Log — YYYY-MM-DD

One-line session title: what this session covered.

This session's goals, in order:
1. ...
2. ...

---

## 1. Section heading (the work)

### A. Sub-part
- concrete finding, decision, or change
- reference file paths (`path/to/file.py`) and line numbers when useful

### B. Landmine / incident
- what happened, the root cause, how it was fixed

---

## 2. Next section

...

---

## Files Changed

- `dir/file.py` — what changed and why (one line each)

## Notes / Follow-ups

- deferred items, flagged risks, open decisions

## Session wrap

Short recap: what merged / was verified this session, what's next.
```

## Styling guidelines

- **Headings:** `## N.` for major work, `### A./B.` for sub-parts. Use `---`
  horizontal rules between major sections.
- **The goal list** at the top is numbered and mirrors the original dev log
  convention ("Goals, in order").
- **Be concrete:** cite file paths, function names, line numbers, and measured
  results (row counts, timings, token counts). Prefer "the proxy's
  health-routing 503 saturation race" over "fixed a bug".
- **Record decisions and their reasoning**, not just outcomes — future you will
  want the *why*.
- **Landmines get their own sub-section** with root cause + fix.
- **Log the uncommitted too:** note what's pending a design decision, like the
  original logs did ("Uncommitted (pending design decision): …").
- **End with "Session wrap"** — one recap paragraph + what's next.
- **Link, don't duplicate:** if a dedicated doc covers a topic, the log entry
  summarizes and links it. This keeps the log skimmable and the doc authoritative.

## Relationship to git history

The dev log is *prose around* the commits — the git log records *what*,
the dev log records *why, what was tried, and what's next*. Commit messages
stay one-liners; the log holds the narrative.
