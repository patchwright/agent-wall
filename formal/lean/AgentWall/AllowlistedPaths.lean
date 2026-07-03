import AgentWall.NoSelfExfiltration

/-!
# AgentWall.AllowlistedPaths

v0.2 invariant #1 of the `agent-wall` library: a deterministic policy gate
admits a write/edit tool-call only if its target path lies under one of the
operator-blessed directory roots.

This is the positive-allowlist dual of `NoSelfExfiltration`'s negative
denylist (`isForbiddenPath`). The two compose: v0.1 blocks known-bad paths,
v0.2 also requires known-good paths. Together they make the write-target
space both closed (denylist) and bounded (allowlist) — the same
defence-in-depth pattern the wall-override experiment validates.

Mirrors the EvoEcos `WallDomainTriple` idiom: `structure` → `triple` →
`gate` → boundary theorem (positive biconditional + negative implication +
independence witnesses) → named `Prop` predicate → soundness bridge.
-/

open AgentWall (Decision)

namespace AgentWall.AllowlistedPaths

/--
The path-relevant slice of a tool-call. A separate structure (not the v0.1
`ToolCallChar`) keeps this invariant self-contained: the field set is exactly
what the gate reads. The system-level invariant (v1.0 target) composes the
slices; v0.2 ships them side-by-side.
-/
structure PathCallChar where
  /-- Tool name (`"Write"`, `"Edit"`, etc.). -/
  tool       : String
  /-- Target path of the write/edit. -/
  targetPath : String
  deriving DecidableEq, Repr

/--
Operator-blessed write roots. A path is allowlisted iff it has one of these
roots as a strict prefix (`String.startsWith`, not substring — substring
match would let `/home/user/repo/../../../../etc/passwd` through, so the
gate uses the strict prefix test).

The roots are hard-coded in v0.2 exactly as the v0.1 forbidden-path list is
hard-coded: structural, deterministic, no config, no model. Operator-config
is a v0.3 target (and the v0.1 DESIGN.md §4 documents `allowlisted-paths`
item 3 with this scope).
-/
def ALLOWED_ROOTS : List String :=
  ["/tmp/", "/home/user/", "/home/fredde/", "/var/tmp/"]

/--
A path is allowlisted iff it starts with one of the allowed roots.
The use of `String.startsWith` (not substring) makes this a strict prefix
test; the conservative direction for an allowlist.
-/
def isAllowlistedPath (p : String) : Bool :=
  ALLOWED_ROOTS.any (fun r => p.startsWith r)

/--
Condition 1 of the triple: the tool is a write/edit tool (the only tools
that have a target path worth gating).
-/
def isWriteTool (t : String) : Bool :=
  t = "Write" || t = "Edit"

/-- Condition 2 of the triple: the target path is under an allowed root. -/
def pathAllowed (c : PathCallChar) : Bool :=
  isAllowlistedPath c.targetPath

/--
The triple: write-tool AND allowlisted path. Direct analogue of
`AgentWall.triple` for the path-allowlist invariant.
-/
def pathTriple (c : PathCallChar) : Bool :=
  isWriteTool c.tool && pathAllowed c

/--
The deterministic policy gate. Mirrors `AgentWall.gate` mapped to the
path-allowlist invariant: Allow iff the triple holds. Pure function of
`PathCallChar`; no model, no IO, no randomness.
-/
def pathGate (c : PathCallChar) : Decision :=
  match pathTriple c with
  | true  => Decision.Allow
  | false => Decision.Deny

/-! ## The boundary theorem (positive + negative + independence)

Same shape as `AgentWall.no_self_exfiltration_boundary`.
-/

/-- Positive biconditional: the gate admits the call iff the triple holds. -/
theorem pathGate_allow_iff_triple (c : PathCallChar) :
    pathGate c = Decision.Allow ↔ pathTriple c = true := by
  cases h : pathTriple c with
  | true  => simp [pathGate, h]
  | false => simp [pathGate, h]

/-- Negative implication: a failed triple denies the call. -/
theorem pathGate_deny_of_triple_false (c : PathCallChar)
    (h : pathTriple c = false) :
    pathGate c = Decision.Deny := by
  cases h' : pathTriple c with
  | true  => simp [h'] at h
  | false => simp [pathGate, h]

/-- Independence witness 3a: a non-write tool alone makes the triple false. -/
theorem pathTriple_false_of_non_write_tool (c : PathCallChar)
    (h : isWriteTool c.tool = false) :
    pathTriple c = false := by
  simp [pathTriple, h]

/-- Independence witness 3b: a non-allowlisted path alone makes the triple false. -/
theorem pathTriple_false_of_path_not_allowed (c : PathCallChar)
    (h : pathAllowed c = false) :
    pathTriple c = false := by
  simp [pathTriple, h]

/-- Corollary: non-write tool ⇒ deny. -/
theorem pathGate_deny_of_non_write_tool (c : PathCallChar)
    (h : isWriteTool c.tool = false) :
    pathGate c = Decision.Deny :=
  pathGate_deny_of_triple_false c (pathTriple_false_of_non_write_tool c h)

/-- Corollary: non-allowlisted path ⇒ deny. -/
theorem pathGate_deny_of_path_not_allowed (c : PathCallChar)
    (h : pathAllowed c = false) :
    pathGate c = Decision.Deny :=
  pathGate_deny_of_triple_false c (pathTriple_false_of_path_not_allowed c h)

/--
The v0.2 boundary theorem for the path-allowlist invariant. Bundles the
positive biconditional, the negative implication, and one independence
witness per conjunct of the triple — same shape as
`AgentWall.no_self_exfiltration_boundary`.
-/
theorem allowlisted_paths_boundary (c : PathCallChar) :
    (pathGate c = Decision.Allow ↔ pathTriple c = true) ∧
    (pathTriple c = false → pathGate c = Decision.Deny) ∧
    (isWriteTool c.tool = false → pathGate c = Decision.Deny) ∧
    (pathAllowed c = false → pathGate c = Decision.Deny) := by
  refine ⟨pathGate_allow_iff_triple c,
           pathGate_deny_of_triple_false c,
           pathGate_deny_of_non_write_tool c,
           pathGate_deny_of_path_not_allowed c⟩

/-! ## The invariant predicate + soundness bridge -/

/--
The v0.2 invariant predicate. Parallels the role of
`AgentWall.NoSelfExfiltration`: a named `Prop` that downstream consumers
cite by name.
-/
def AllowlistedPaths (c : PathCallChar) : Prop :=
  pathGate c = Decision.Allow

/-- Soundness bridge: the invariant holds iff the triple holds. -/
theorem allowlisted_paths_iff_triple (c : PathCallChar) :
    AllowlistedPaths c ↔ pathTriple c = true := by
  simp only [AllowlistedPaths]
  exact pathGate_allow_iff_triple c

end AgentWall.AllowlistedPaths
