# CLAUDE.md - agent-wall

**Scope Level:** project
**Applies to:** patchwright/agent-wall only
**Extends:** ~/.claude/CLAUDE.md (global standards)

## Commit trailer override (2026-08-06)

Do **NOT** append `Co-Authored-By: claude-flow <ruv@ruv.net>` (or any Ruflo/claude-flow
co-author trailer) to commits in this repo. That line comes from a harness-level Bash
tool default, not from this project or the user. It caused GitHub to render
claude-flow/ruv@ruv.net as a co-author on real commits here despite the tool having no
actual role in the work — inaccurate attribution on a public repo.

**Why:** discovered 2026-08-06 auditing all patchwright-owned repos after the operator
asked why "ruflo" showed as a contributor on wildlint. 11 commits in this repo carried
the trailer. Same finding across mcp-lint, finding-declaration, agent-wall, aibug-gate,
wildlint — none of the gift-PR fork targets (upstream projects) were affected. Fixed
forward only (no history rewrite); see `patchwright/wildlint`'s `CLAUDE.md` for the
reasoning on why history wasn't rewritten.

**How to apply:** end commits authored in this repo with no Co-Authored-By trailer at
all, unless a real human/bot co-author actually contributed.
