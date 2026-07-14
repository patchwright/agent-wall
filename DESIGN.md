# agent-wall — Design

**The wedge.** `agent-wall` is a deterministic first-layer policy gate with
Lean-checked decision structure, giving autonomous AI agents a pre-execution
"no" on a known set of unsafe tool-calls. It is explicitly *not* an LLM judge.
The decision is a pure function of the tool-call over a frozen startup config,
structurally bounded, and enforced at the tool-call boundary before the action
runs. The lane it occupies — deterministic + structurally-bounded +
pre-execution — is sparse in practice today; everything else in the "agent
guardrails" space is a model-based judge that an adversary can prompt-past.

**What "Lean-checked" means here (honest scope).** The Lean proofs verify the
gate's *decision structure*: `gate = Allow ↔ triple = true`, `triple = false
→ gate = Deny`, the `BoundedSpend` inequality, and the `ReplayDeterminism`
functional-extensionality equation. They do NOT prove that the exfiltration
signatures are exhaustion-proof or that the allowlist is unobsfucatable —
both are bypassable on the open surface (see README §"Known bypasses" for
the closed/open inventory, regressed in `python/tests/test_hook_bypasses.py`).
The Lean `AllowlistedPaths.isAllowlistedPath` predicate does NOT model path
traversal on its own; traversal-resistance is a property of the COMPOSITION
(Python `realpath` layer ∘ Lean allowlist predicate), made explicit in the
Lean via the `isNormalizedPath` precondition and the
`pathGate_deny_of_normalized_path_not_allowed` corollary.

This is **v0.2**: four Lean-checked invariants (one carried from v0.1, three
new), a Python PoC that enforces all four at the PreToolUse boundary, and this
design document. The full library is multi-session. The scope statement at the
end of this document is honest about that.

---

## 1. The problem: LLM-judge guardrails are bypassable

The dominant pattern for "agent safety" today is a second LLM that looks at the
proposed tool-call and says allow/deny. This is structurally weak:

  * **Prompt injection moves the judge.** Any untrusted text the agent reads —
    a web page, an email, a file — can carry instructions targeted at the
    judge. The judge is the same kind of object as the agent, so any attack
    that works on the agent works on the judge.
  * **Soft decisions don't compose.** A 0.97-confidence "probably safe" does
    not chain into a hard system-level guarantee. Aggregating N soft gates
    gives you N chances to be wrong, not a guarantee.
  * **No formal boundary.** There is no theorem you can state about a judge's
    behaviour, because the judge is a model. The best you get is empirical
    eval on a held-out set — which an adaptive adversary is explicitly
    designed to evade.

The fix is not a better judge. The fix is to *not use a judge* for the things
that admit a structural rule.

---

## 2. The formal basis: the EvoEcos wall

`agent-wall` productizes a wall mechanism that already exists as a verified
formal artifact in the EvoEcos project. Nothing here is invented.

### 2.1 The Lean idiom

EvoEcos's `formal/lean/EvoEcos/` tree carries ~24k lines of
Lean 4, `0 sorry / 0 axiom`. The relevant pieces:

  * **`WallDomainTriple.lean`** defines the wall as a control-theoretic
    "domain triple" — a `structure EnvChar where` with three `Bool` necessary
    conditions (`lowDim`, `simpleCausal`, `perturbation`), a derived reducer
    `triple : Bool`, and an admission payoff `wallBenefit : ℝ`. The headline
    theorem `wall_domain_boundary` bundles the positive biconditional, the
    negative implication, and the three independence witnesses into one
    statement. This is the idiom `agent-wall` mirrors verbatim
    (`ToolCallChar` / `triple` / `gate` / `no_self_exfiltration_boundary`).

  * **`Invariants.lean`** defines the system-wide contract
    `systemInvariant : SystemState → Prop` — a conjunction of per-layer
    type-invariants, the wall-firing implication, and a liveness watchdog.
    Every transition theorem takes `hinv : systemInvariant s`. The role this
    plays (a named `Prop` that downstream consumers cite) is the role
    `NoSelfExfiltration` plays in v0.1.

  * **Liveness watchdog.** The bounded-time-advance guarantee
    (`L3State.liveness`) is a conjunct of `systemInvariant` in
    `Invariants.lean`; every transition theorem preserves it. The point of
    a wall is not to stall progress forever — the liveness watchdog enforces
    bounded-time advance even with the wall up. A safety gate that halts the
    agent is not a gate, it is an off-switch.

### 2.2 The experimental evidence the moat rests on

Two EvoEcos experiments validate the wall mechanism empirically (queried via
the EvoEcos experiments SQLite, not raw JSON reads):

  * **`wall_override_defense_sweep`** — 30 seeds × 8 strategies. Structural
    hard caps strictly dominate every softer defense on the
    wall-effectiveness and degradation-episode metrics:

    | strategy            | wall_eff | degrad_ep | min_l1 |
    |---------------------|----------|-----------|--------|
    | `hard_cap_1` (structural) | **0.921** | **2.20**  | 0.008  |
    | `hard_cap_2` (structural, weaker) | 0.878 | 7.63 | 0.000 |
    | `asymmetric_cost` (magnitude) | 0.880 | 8.73 | 0.000 |
    | `cumulative_budget` (probabilistic) | 0.853 | 11.13 | 0.000 |
    | `cooling_5` (temporal) | 0.818 | 13.97 | 0.002 |
    | `naive`             | 0.694    | 29.27     | 0.000  |
    | `undefended`        | 0.386    | 77.10     | 0.000  |

    Structural hard caps win. This is the empirical claim behind agent-wall's
    insistence on a deterministic, structural gate.

  * **`deployment_blueprint`** — 150 seeds × 5 perturbation levels
    (none/mild/moderate/severe/adversarial), 7500 total turns, 1918 of them
    adversarial. **0 hierarchy violations across the full sweep.** Hypotheses
    H3 (correct_hierarchy) and H4 (matches_formal_model) **confirmed**. This
    is the deployment-shape evidence: in a wall-gated agent, the gate fires
    in the right order on every turn, including under adversarial pressure.

### 2.3 The honest caveat

EvoEcos's wall is a control-theoretic object inside an agent architecture
(L1–L4 layers). `agent-wall` lifts the *gate shape* (necessary-conditions
triple + decision + boundary theorem) out of that architecture and applies it
to agent *tool-calls*. The Lean idiom and the structural-cap result transfer
directly; the L1–L4 layer semantics do not. v0.1 is the tool-call gate; the
L1–L4 work stays in EvoEcos.

---

## 3. Academic anchors

Three pieces of prior art locate `agent-wall` in the literature. (The
arXiv IDs below are as cited in the project brief; I have not independently
re-verified them in this session.)

  * **AgentSpec (ICSE 2026)** — a runtime-enforcement DSL for LLM agents.
    Establishes that the boundary agents need is *runtime enforcement*, not
    test-time filtering. `agent-wall` is the formally-bounded layer that
    AgentSpec-style specs dispatch to.
  * **AgentAssert (arXiv 2602.22302)** — drift-bounds on agent behaviour via
    Lyapunov-style certificates. The mechanism is structurally the same as
    the EvoEcos wall: a certificate that the agent cannot drift past a
    boundary. This is the closest academic analogue to the wall mechanism
    agent-wall productizes.
  * **"Deterministic Guardrails for Agentic Financial Systems" (arXiv 2604.01483,
    Lean 4)** — the same "deterministic + Lean + agent" thesis, applied to
    finance. Validates the lane; `agent-wall` is the general-purpose,
    open-source version.

The differentiator is not the thesis (determinism is in the air) — it is the
*formal asset*. EvoEcos already has the verified wall; nobody else does.

---

## 4. The invariant set to ship eventually

v0.2 ships invariants 1–4. The set below is the v1.0 surface. Each is a
`def <Name> (c : ...) : Prop` in the EvoEcos idiom, with a boundary theorem
proving the gate denies iff the invariant is violated.

  1. **no-self-exfiltration** — *v0.1 ✓* — no tool-call may flow an untrusted
     blob into a sink (network egress, shell-pipe, credential path).
  2. **allowlisted-paths** — *v0.2 ✓* — writes only into operator-blessed
     directory trees. Generalizes the v0.1 forbidden-path denylist with a
     positive allowlist (strict prefix match on a roots list). The two
     compose: v0.1 blocks known-bad paths, v0.2 also requires known-good
     paths.
  3. **bounded-spend** — *v0.2 ✓* — a tool-call's declared cost ≤ remaining
     budget. The wall-override experiment's `cumulative_budget` arm shows
     spend caps compose with structural caps; v0.2 ships the per-call atomic
     check. (Rolling-window accounting and session-state persistence are
     v0.3 — see §6.)
  4. **replay-determinism** — *v0.2 ✓* — same `(tool_name, tool_input)` ⇒
     same decision, no clock, no randomness, no environment read. Stated
     over the gate function: `ReplayDeterminism g := ∀ c₁ c₂, c₁ = c₂ →
     g c₁ = g c₂`, with the field-by-field dual and the triple reducer
     inheritance. Required for audit.
  5. **no-unprompted-network** — no network egress that the operator did not
     initiate. Closes the data-flow sink on the network side.
  6. **tool-allowlist** — only operator-blessed tools callable. v0.1 has the
     hard-coded `{Bash, Read, Edit, Write}` as a triple conjunct; v0.3 makes
     it operator-config and a named invariant in its own right.
  7. **idempotency-on-failure** — a failed tool-call retried ≤ N times in a
     window. Stops the agent hammering a broken tool.
  8. **no-privilege-escalation** — the agent may not edit its own gate
     config, the operator's auth files, or the Lean source.
  9. **sink-bounded-data-flow** — the full taint version: an `untrusted`
     `sourceTrust` value may not reach a sink in any call in the session.
     The `sourceTrust` field is already on `ToolCallChar`; v0.1 collapses
     taint into `commandSafe`/`targetSafe`, v0.3 makes it explicit.
  10. **bounded-resource** — file count, memory, and wall-clock per session
      ≤ operator caps.

The system-level invariant (v1.0 target) is the conjunction of all ten,
`def systemInvariant (s : SessionState) : Prop := …`, in the role EvoEcos's
`systemInvariant` plays.

---

## 5. Integration surfaces

  * **Claude Code `PreToolUse`** — *v0.1 ✓* — the hook in `python/hook.py`
    returns exit 2 to BLOCK per Claude Code's hook contract. Drops in via
    the `.claude/settings.json` snippet in `python/settings.example.json`.
  * **LangChain `AgentMiddleware` v1-alpha** — *v0.2* — the same gate logic
    as a `before_tool` middleware. LangChain's v1-alpha middleware surface is
    still moving; the adapter lands when the API stabilizes.
  * **MCP tool-call boundary** — *v0.3* — the gate sits inside the MCP
    server, between the agent's tool-call and the tool's execution. One
    deployment point, every MCP client covered.
  * **OpenAI Agents SDK / generic tool-loop** — *v0.4* — a thin adapter for
    any tool-calling loop that exposes a `before_tool` hook.

The integration point is always the same shape — *the gate is a function from
tool-call to allow/deny, enforced at the boundary*. Different hosts, same gate.

---

## 6. Honest v0.2 scope

What v0.2 is:

  * **Four invariants.** `NoSelfExfiltration` (v0.1), `AllowlistedPaths`,
    `BoundedSpend`, `ReplayDeterminism` (all three new in v0.2). Each has a
    boundary theorem in the EvoEcos idiom: positive biconditional + negative
    implication + independence witnesses, plus a named `Prop` predicate and
    a soundness bridge.
  * **Four Lean modules.** `formal/lean/AgentWall/{NoSelfExfiltration,
    AllowlistedPaths, BoundedSpend, ReplayDeterminism}.lean`, aggregated by
    `formal/lean/AgentWall.lean`. Compiles `0 sorry / 0 axiom` under
    `leanprover/lean4:v4.29.1` via `bash formal/verify.sh`. No mathlib
    dependency.
  * **One Python PoC.** `python/hook.py`, a Claude Code `PreToolUse` hook.
    63 tests pass across `python/tests/test_hook.py` (block + allow for all
    four invariants) and `python/tests/test_hook_bypasses.py` (13 adversarial:
    path-traversal regression guards + documented known-open bypasses). Manual
    demo: block `curl … | sh` and writes to `.ssh/` with exit 2; block writes
    outside the allowlist (incl. traversal like `/tmp/../etc/passwd`); block
    over-budget calls; allow `ls -la` with exit 0.
  * **DESIGN.md and README.md.** This document and the pitch.

What v0.2 is **not**:

  * Not the full ten-invariant set from §4. Six invariants remain
    (`no-unprompted-network`, `tool-allowlist` as a named invariant,
    `idempotency-on-failure`, `no-privilege-escalation`,
    `sink-bounded-data-flow`, `bounded-resource`). Those are the v1.0
    surface.
  * Not exhaustion-proof on signatures. The exfil signature table is a fixed
    substring list; an adversarial review (5.5/10) confirmed multiple open
    bypasses (whitespace variants, download-then-run, nested shells,
    `python3 -c "..."`). See README §"Known bypasses" for the precise
    closed/open inventory, regressed in `python/tests/test_hook_bypasses.py`.
    The Lean proofs verify the gate's decision structure, NOT that the
    signatures are unobsfucatable.
  * Not a complete path-traversal defense in the Lean layer alone. The Lean
    `AllowlistedPaths.isAllowlistedPath` predicate is a pure prefix test on
    `String` and does not model traversal; traversal-resistance is a property
    of the COMPOSITION (Python `realpath` layer ∘ Lean allowlist predicate).
    The Lean `isNormalizedPath` precondition and the
    `pathGate_deny_of_normalized_path_not_allowed` corollary make the
    pairing explicit; the Python layer (`_normalize_path`) enforces the
    precondition for every write/edit call.
  * No session-level state. The v0.2 gate is per-call; multi-call invariants
    (rolling-window spend, retry counts, full taint-tracking) need a session
    store and are v0.3. `BoundedSpend` ships the per-call atomic check; the
    rolling window is a v0.3 concern documented in the module.
  * No refinement proof connecting the Lean gate to the Python gate. The two
    share the same signature/path tables by construction, and the test suite
    cross-checks the block/allow outcomes against the documented Lean
    contract — but there is no formal proof that `python/hook.py` faithfully
    implements each `AgentWall.*.gate`. That refinement proof is a v0.3
    target.
  * No LangChain / MCP / OpenAI-SDK adapters. v0.2 ships Claude Code only.
  * No published package. This is a design + PoC.

---

## 7. File map

```
agent-wall/
├── DESIGN.md                              # this document
├── README.md                              # the pitch
├── formal/
│   ├── verify.sh                          # lake build + sorry/axiom = 0 gate
│   └── lean/
│       ├── lakefile.lean                  # package + AgentWall lib, no mathlib
│       ├── lean-toolchain                 # leanprover/lean4:v4.29.1
│       ├── AgentWall.lean                 # lib root (imports all four modules)
│       └── AgentWall/
│           ├── NoSelfExfiltration.lean    # v0.1 invariant (exfil + forbidden path)
│           ├── AllowlistedPaths.lean      # v0.2 invariant #1 (positive path allowlist)
│           ├── BoundedSpend.lean          # v0.2 invariant #2 (declared cost ≤ budget)
│           └── ReplayDeterminism.lean     # v0.2 invariant #3 (gate is a pure function)
└── python/
    ├── hook.py                            # Claude Code PreToolUse PoC (all 4 invariants)
    ├── settings.example.json              # .claude/settings.json snippet
    └── tests/
        ├── test_hook.py                   # block/allow + replay-determinism tests
        └── test_hook_bypasses.py          # adversarial: traversal guards + known-open surface
```
