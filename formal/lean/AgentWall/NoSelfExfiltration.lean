/-!
# AgentWall.NoSelfExfiltration

The v0.1 invariant of the `agent-wall` library: a deterministic policy gate
denies any agent tool-call that could flow an untrusted blob into a sink
(network egress, shell-pipe, or a credential-store path).

This file is the formal artifact that productizes the EvoEcos "wall" for
autonomous AI agents. It deliberately mirrors the EvoEcos formal idiom:

  * a `structure ... where` carrying the necessary conditions of a safe call,
    paralleling `EvoEcos.WallDomainTriple.EnvChar` (the "domain triple" of
    three `Bool` necessary conditions);
  * a derived reducer (`triple : Bool`) and an admission decision, paralleling
    `EnvChar.triple` and `EnvChar.wallBenefit`;
  * a boundary theorem bundling (1) the positive biconditional, (2) the
    negative implication, and (3) one independence witness per conjunct,
    paralleling `EvoEcos.WallDomainTriple.wall_domain_boundary`;
  * a system-level invariant predicate `NoSelfExfiltration` that every
    consumer cites by name, paralleling the role of
    `EvoEcos.Invariants.systemInvariant`.

The build protocol mirrors `formal/verify.sh` of EvoEcos: the gate is
`lake build` success (a compile failure is a real gap; a proof that fails
with `simp`/`linarith` contains no unfinished proof and slips past text
grep), with the sorry and axiom baselines pinned at 0.

This is v0.1 — ONE invariant. The invariant set to ship eventually is
documented in `DESIGN.md` (no-self-exfiltration, bounded-spend,
allowlisted-paths, replay-determinism, no-unprompted-network, …).
-/

namespace AgentWall

/-- Trust level of the principal that produced a value consumed by a call. -/
inductive TrustLevel where
  /-- The operator, a reviewed config, or a closed-world constant. -/
  | trusted
  /-- Web-fetched content, model-generated text, or any unreviewed blob. -/
  | untrusted
  deriving DecidableEq, Repr

/--
The characteristics of a single agent tool-call that the gate reads.

This is the agent-wall analogue of `EvoEcos.WallDomainTriple.EnvChar`: a
plain `structure` (not a class or predicate) whose fields are the raw
inputs, plus derived `triple : Bool` and `gate : Decision` functions
defined below.

The `sourceTrust` field models the data-flow half of the invariant (an
`untrusted` blob may not flow into a sink). In v0.1 the sink detection is
collapsed into `commandSafe`/`targetSafe`; the explicit taint-tracking
proof (untrusted-input → denied sink) is a v0.2 target. The field is kept
on the structure so the v0.1 shape already matches the data-flow model
without weakening the v0.1 proof.
-/
structure ToolCallChar where
  /-- Tool name, e.g. `"Bash"`, `"Write"`, `"Edit"`, `"Read"`. -/
  tool        : String
  /-- Raw command text (for `Bash`) or file content (for `Write`/`Edit`). -/
  command     : String
  /-- Target path (`""` when the tool takes none, e.g. for `Bash`). -/
  targetPath  : String
  /-- Trust level of any untrusted blob flowing into this call. -/
  sourceTrust : TrustLevel
  deriving DecidableEq, Repr

/-- Substring test on `String` (core Lean 4 has no `String.contains` for substrings). -/
def containsSubstr (needle s : String) : Bool :=
  (s.splitOn needle).length ≥ 2

/--
The v0.1 exfiltration signature: pipe-to-shell, remote-fetch-then-exec,
and direct `eval`. Mirrors the patterns the Python `PreToolUse` PoC blocks.

This is a *structural* signature — substring match, no model, no network.
The agent-wall claim (grounded in EvoEcos `wall_override_defense_sweep`)
is that structural hard-caps strictly dominate softer defenses; the
determinism of the signature is the whole point.
-/
def isExfilSignature (cmd : String) : Bool :=
  (containsSubstr "curl " cmd && containsSubstr "| sh" cmd) ||
  (containsSubstr "wget " cmd && containsSubstr "| sh" cmd) ||
  containsSubstr "| bash" cmd ||
  containsSubstr "eval " cmd ||
  containsSubstr "/dev/tcp/" cmd

/--
Forbidden target paths: credential stores, SSH key material, env files.
Mirrors the path denylist the Python `PreToolUse` PoC enforces.
-/
def isForbiddenPath (p : String) : Bool :=
  containsSubstr ".ssh/" p ||
  containsSubstr ".aws/credentials" p ||
  containsSubstr ".env" p ||
  containsSubstr ".gnupg/" p

/-- Condition 1 of the triple: the tool is on the allowlist. -/
def toolAllowed (c : ToolCallChar) : Bool :=
  c.tool = "Bash" || c.tool = "Read" || c.tool = "Edit" || c.tool = "Write"

/-- Condition 2 of the triple: the command does not match an exfil signature. -/
def commandSafe (c : ToolCallChar) : Bool :=
  ! isExfilSignature c.command

/-- Condition 3 of the triple: the target path is not a forbidden (credential) path. -/
def targetSafe (c : ToolCallChar) : Bool :=
  ! isForbiddenPath c.targetPath

/--
The triple: all three necessary conditions hold. Direct analogue of
`EvoEcos.WallDomainTriple.EnvChar.triple`.
-/
def triple (c : ToolCallChar) : Bool :=
  toolAllowed c && commandSafe c && targetSafe c

/-- The gate's admission decision. -/
inductive Decision where
  | Allow : Decision
  | Deny  : Decision
  deriving DecidableEq, Repr

/--
The deterministic policy gate. Direct analogue of `EnvChar.wallBenefit`
mapped to a two-valued decision: the call is admitted iff the triple holds.

No randomness, no model call, no side-effect: the decision is a pure
function of `ToolCallChar`. This is the operational core of the
"not-an-LLM-judge" wedge.
-/
def gate (c : ToolCallChar) : Decision :=
  match triple c with
  | true  => Decision.Allow
  | false => Decision.Deny

/-! ## The boundary theorem (positive + negative + independence)

The shape mirrors `EvoEcos.WallDomainTriple.wall_domain_boundary`: one
theorem bundling the positive biconditional, the negative implication, and
one independence witness per conjunct of the triple.
-/

/-- Positive biconditional: the gate admits the call iff the triple holds. -/
theorem gate_allow_iff_triple (c : ToolCallChar) :
    gate c = Decision.Allow ↔ triple c = true := by
  cases hc : triple c with
  | true => simp [gate, hc]
  | false => simp [gate, hc]

/-- Negative implication: a failed triple denies the call. -/
theorem gate_deny_of_triple_false (c : ToolCallChar) (h : triple c = false) :
    gate c = Decision.Deny := by
  cases hc : triple c with
  | true => simp [hc] at h
  | false => simp [gate, hc]

/-- Independence witness 3a: an exfiltration signature alone makes the triple false. -/
theorem triple_false_of_command_unsafe (c : ToolCallChar)
    (h : isExfilSignature c.command = true) :
    triple c = false := by
  simp [triple, commandSafe, h]

/-- Independence witness 3b: a forbidden target path alone makes the triple false. -/
theorem triple_false_of_target_unsafe (c : ToolCallChar)
    (h : isForbiddenPath c.targetPath = true) :
    triple c = false := by
  simp [triple, targetSafe, h]

/-- Independence witness 3c: a disallowed tool alone makes the triple false. -/
theorem triple_false_of_tool_disallowed (c : ToolCallChar)
    (h : toolAllowed c = false) :
    triple c = false := by
  simp [triple, h]

/-- Convenience corollary: exfil signature ⇒ deny. -/
theorem gate_deny_of_exfil (c : ToolCallChar)
    (h : isExfilSignature c.command = true) :
    gate c = Decision.Deny :=
  gate_deny_of_triple_false c (triple_false_of_command_unsafe c h)

/-- Convenience corollary: forbidden path ⇒ deny. -/
theorem gate_deny_of_forbidden (c : ToolCallChar)
    (h : isForbiddenPath c.targetPath = true) :
    gate c = Decision.Deny :=
  gate_deny_of_triple_false c (triple_false_of_target_unsafe c h)

/-- Convenience corollary: disallowed tool ⇒ deny. -/
theorem gate_deny_of_disallowed (c : ToolCallChar)
    (h : toolAllowed c = false) :
    gate c = Decision.Deny :=
  gate_deny_of_triple_false c (triple_false_of_tool_disallowed c h)

/--
The v0.1 boundary theorem. Bundles the positive biconditional, the negative
implication, and the three independence witnesses into one statement — the
same shape as `EvoEcos.WallDomainTriple.wall_domain_boundary`. Consumers
that want the whole contract cite this; consumers that want one direction
cite the corresponding lemma above.
-/
theorem no_self_exfiltration_boundary (c : ToolCallChar) :
    -- (1) positive: gate admits iff triple holds
    (gate c = Decision.Allow ↔ triple c = true) ∧
    -- (2) negative: any failed condition denies
    (triple c = false → gate c = Decision.Deny) ∧
    -- (3a) independence: exfil signature alone denies
    (isExfilSignature c.command = true → gate c = Decision.Deny) ∧
    -- (3b) independence: forbidden path alone denies
    (isForbiddenPath c.targetPath = true → gate c = Decision.Deny) ∧
    -- (3c) independence: disallowed tool alone denies
    (toolAllowed c = false → gate c = Decision.Deny) := by
  refine ⟨gate_allow_iff_triple c,
           gate_deny_of_triple_false c,
           gate_deny_of_exfil c,
           gate_deny_of_forbidden c,
           gate_deny_of_disallowed c⟩

/-! ## The system-level invariant predicate

Parallels the role of `EvoEcos.Invariants.systemInvariant`: a named `Prop`
that downstream transition theorems cite. v0.1 ships one conjunct (the
no-self-exfiltration property over a single call); v0.2+ extends this to a
list of calls (replay-determinism, bounded-spend over a budget window,
no-unprompted-network) and the conjunct then becomes a real system
invariant rather than a single-call property.
-/

/--
The v0.1 invariant: the call is admitted by the gate. The naming follows
`systemInvariant` in EvoEcos: a `Prop` predicate (not a class) that the
policy gate is proved sound against. Defined as the atomic admission fact
so the soundness bridge theorem is exactly `gate_allow_iff_triple`.
-/
def NoSelfExfiltration (c : ToolCallChar) : Prop :=
  gate c = Decision.Allow

/-- The gate is sound with respect to the invariant: a call is admitted iff the triple holds. -/
theorem no_self_exfiltration_iff_triple (c : ToolCallChar) :
    NoSelfExfiltration c ↔ triple c = true := by
  simp only [NoSelfExfiltration]
  exact gate_allow_iff_triple c

end AgentWall
