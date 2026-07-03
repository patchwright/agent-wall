# Releasing agent-wall

Two questions, kept separate:

1. **Is it ready?** — the checklist below. Deterministic; run it every time.
2. **Does it ship?** — a tagged GitHub release is permanent (deletable but
   visible in reflog/clone-history for those who already pulled). So:
   - **new security surface** (new invariant, gate logic change, allowlist/
     denylist change) → assemble the filled checklist + diff, get a human
     go, then tag.
   - **routine patch** (test-only, docs, CI/tooling) → green checklist →
     tag + report.

The checklist replaces "because I said so." If an item is red, it doesn't
ship — no exceptions for vibes. Adapted from mcp-lint/RELEASING.md; the
CVE-signature honesty section is replaced by the Lean-formalism + Python-
bypass honesty section because agent-wall's value proposition is the formal
contract plus its known-bypass inventory, not a CVE database.

## Readiness checklist — every release

- [ ] **CI green on the release commit** — both jobs in
      `.github/workflows/ci.yml`:
  - [ ] `formal` job green: `formal/verify.sh` exits 0 AND the 0 sorry /
        0 axiom assertion step passes (i.e. the Lean 0/0 gate is
        machine-verified, not author-attested)
  - [ ] `python` job green on both matrix entries (`3.9` + `3.13`):
        `ruff check`, `ruff format --check`, `mypy --strict`, `pytest -q`,
        and the gate spot-check step all pass
- [ ] **local repro of CI gates**:
  - `bash formal/verify.sh` → exit 0, with `sorry count: 0` and
        `axiom count: 0` in the output
  - `cd python && ruff check hook.py tests && ruff format --check hook.py tests`
        → both clean
  - `cd python && mypy --strict hook.py tests/test_hook.py tests/test_hook_bypasses.py`
        → no issues
  - `cd python && python -m pytest -q` → all tests pass (currently 63)
- [ ] **gate spot-check byte-identical** to the v0.2 baseline:
  - `Write /tmp/../etc/passwd` → exit 2 with the resolved-path message
        naming `/etc/passwd`
  - `Write /tmp/x` → exit 0
  - Known-open surfaces (whitespace exfil, download-then-run, nested
        shells, `python3 -c`, TOCTOU) STILL documented-open in
        README §"Known bypasses" AND asserted with the expected-polarity
        test in `python/tests/test_hook_bypasses.py`. If any of these
        flipped to BLOCKED, the corresponding test should already have
        failed in CI; if it didn't, the polarity comment is stale.
- [ ] **DESIGN.md scope-honest** (DESIGN.md §"Honest v0.2 scope"):
  - test count in the doc matches the actual `pytest` count (the doc
        says 50/50 from v0.2.0; the bypass suite lifted it to 63 — update
        the doc on the next release that lands after the bypass suite)
  - bypass inventory in DESIGN.md matches README §"Known bypasses"
        matches `test_hook_bypasses.py` (regression-guard group =
        README "CLOSED" list; known-open group = README "KNOWN-OPEN"
        list, opposite polarity)
- [ ] **Lean layer untouched unless intentional**: the
      `formal/lean/AgentWall/*.lean` files are the formal contract. A
      diff here means the contract moved — the gate's security guarantees
      are no longer the v0.2 baseline. If the diff is intentional (new
      invariant, strengthened predicate), bump the minor version and
      document the contract change in the release notes.
- [ ] **operator-tunable knobs documented**: any new
      `AGENT_WALL_*` env flag added to `python/hook.py` is documented in
      the module docstring AND in README's knobs section.
- [ ] `git status` clean apart from the release diff (no stray unrelated
      changes — stage in atomic logical groups with explicit pathspecs,
      per the evoecos commit-discipline rule).

## Tag mechanics

agent-wall ships as a tagged GitHub release (no PyPI, no crates.io —
the artifact is the Lean library + the Python hook script, both
delivered in-tree). To release:

```bash
# After the checklist above is green:
git commit -m "release: v0.X.Y — <one-line>"  # if a release commit is needed
git tag -a v0.X.Y -m "v0.X.Y — <one-line>"
git push origin main v0.X.Y
```

Release notes live in the **tag annotation** (or an optional GitHub
Release body). There is no CHANGELOG file by project convention.

Versioning (semver, adapted for a security-gate artifact):
- **major** — a Lean contract change (new invariant, removed invariant,
  or strengthened predicate that changes block/allow on any input)
- **minor** — new Python-side gating logic that does NOT move the Lean
  contract (e.g. a new signature in the exfil list, a new env flag)
- **patch** — test-only, docs, CI/tooling, a bug fix that doesn't change
  gate behavior on any documented input

## Post-tag smoke (runs AFTER tagging)

- [ ] `git clone --branch v0.X.Y` in a fresh dir; run `bash formal/verify.sh`
      → exit 0, 0/0 counts.
- [ ] in the same clone: `cd python && python -m pytest -q` → all green.
- [ ] manual hook demo: `Write /tmp/../etc/passwd` blocks (exit 2),
      `Write /tmp/x` allows (exit 0) — the byte-identical v0.2 contract.
- [ ] `git log --oneline v0.X.Y -1` shows the intended commit.

## What this gate is not

- **Not a substitute for adversarial review.** The 5.5/10 review caught
  a CRITICAL path-traversal bypass; CI prevents *regression* of that fix
  and enforces the 0/0 Lean claim, but a fresh adversarial pass on the
  current surface is what surfaces new bypasses. Re-run the review before
  any minor-version bump.
- **Not an exhaustion proof.** The README §"Known bypasses" inventory is
  the open surface; CI green does NOT mean the gate is unobsfucatable.
  It means the documented closed/open inventory is machine-enforced.
- **Not static — amend this file when the release process changes**, so
  the gate reflects reality rather than rotting into a fiction.

## Caveats (Lean-in-CI reliability)

- **elan + lake on first run** fetches `leanprover/lean4:v4.29.1` from
  the lean-release CDN (≈400 MB). The first CI run after cache invalidation
  takes 5–10 minutes for this fetch; subsequent runs against the same
  toolchain are cached by elan's `~/.elan/toolchains/` and the
  `actions/checkout@v4` workspace persists elan's `~/.elan` across steps
  within a job but NOT across jobs (each `formal` job is a fresh runner).
  Network reliability of the lean-release CDN is the chief external
  dependency; a flaky run usually clears on rerun. If the CDN is down,
  the failure surfaces in the "Install elan" or "Run formal/verify.sh"
  step, not in the assertion step.
- **No mathlib dependency by design** (see `formal/lean/lakefile.lean`),
  so there's no mathlib-tag drift to chase. The build is self-contained
  against Lean 4 core, which is the point: it keeps the formal artifact
  small and the CI build fast.
- **The `sorry`/`axiom` grep is structural**, not semantic: it catches
  `^sorry` and `^axiom` at line start. A proof that uses `sorry` inside
  a tactic block on the same line as other code would slip past — but
  the `lake build` step upstream is the real gate (a `sorry`-containing
  proof still compiles but emits a warning, and a `sorry` that closes a
  `Prop` differently than its real proof would shifts the proof's
  behavior). The grep is belt-and-suspenders visibility, not the
  primary check.
