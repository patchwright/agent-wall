import AgentWall.NoSelfExfiltration

/-!
# AgentWall.ReplayDeterminism

v0.2 invariant #3 of the `agent-wall` library: the policy gate is
replay-deterministic — identical inputs produce identical decisions, with no
clock, no randomness, and no environment read in the loop.

This is a property of the *gate function*, not of a single call, so it is
stated as `ReplayDeterminism g` over `g : ToolCallChar → Decision`. The v0.1
gate is proved to satisfy it; any future gate (LangChain middleware, MCP
boundary, OpenAI SDK adapter) must satisfy it too, or it cannot claim to be
an `agent-wall` gate. This is the formal contract that the deterministic
wedge rests on.

The "no clock, no randomness, no environment read" part is implicit but
load-bearing: the gate's type `ToolCallChar → Decision` has no `IO`, no
`StateM`, no `Rand` — it is a pure function in the deepest sense Lean can
enforce. A gate that read the wall clock would have type `ToolCallChar → IO
Decision` and would not typecheck as a `ReplayDeterminism` candidate.

Mirrors the EvoEcos idiom: named `Prop` predicate → boundary theorem →
soundness bridge.
-/

open AgentWall (ToolCallChar Decision gate triple)

namespace AgentWall.ReplayDeterminism

/--
The replay-determinism property: a gate `g` is replay-deterministic iff for
every pair of equal calls, the decision is equal. This is the operational
contract that an `agent-wall` gate satisfies — the audit property that lets
an operator replay a session log and observe the same allow/deny sequence.
-/
def ReplayDeterminism (g : ToolCallChar → Decision) : Prop :=
  ∀ c₁ c₂ : ToolCallChar, c₁ = c₂ → g c₁ = g c₂

/--
The v0.1 gate is replay-deterministic.

The proof is `rw [h]` — by substitution. This is exactly the point: the
determinism is *definitional*, not an empirical claim. The gate is a pure
function of `ToolCallChar`, so two equal calls produce equal decisions by
Lean's definitional equality.
-/
theorem gate_replay_deterministic : ReplayDeterminism gate := by
  intro c₁ c₂ h
  rw [h]

/--
Field-by-field version: the gate's decision depends only on the four
`ToolCallChar` fields. This is the operational statement auditors cite —
"same `(tool, command, targetPath, sourceTrust)` ⇒ same decision." It is
the dual of `ReplayDeterminism` for callers that hold the four field
equalities rather than a structural equality.
-/
theorem gate_replay_deterministic_fields (c₁ c₂ : ToolCallChar)
    (h_tool : c₁.tool = c₂.tool)
    (h_cmd : c₁.command = c₂.command)
    (h_path : c₁.targetPath = c₂.targetPath)
    (h_trust : c₁.sourceTrust = c₂.sourceTrust) :
    gate c₁ = gate c₂ := by
  cases c₁; cases c₂
  simp_all

/--
The triple reducer inherits replay-determinism from the gate: identical
fields ⇒ identical triple. Cited by the audit property that an
`agent-wall` gate's reducer is itself deterministic.
-/
theorem triple_replay_deterministic_fields (c₁ c₂ : ToolCallChar)
    (h_tool : c₁.tool = c₂.tool)
    (h_cmd : c₁.command = c₂.command)
    (h_path : c₁.targetPath = c₂.targetPath)
    (h_trust : c₁.sourceTrust = c₂.sourceTrust) :
    triple c₁ = triple c₂ := by
  cases c₁; cases c₂
  simp_all

/--
The v0.2 boundary theorem for the replay-determinism invariant. Bundles:
  (1) the predicate holds for the v0.1 gate,
  (2) the field-by-field version for the gate,
  (3) the field-by-field version for the triple reducer.

Same shape as `AgentWall.no_self_exfiltration_boundary` and the other v0.2
boundary theorems — one bundled statement consumers cite by name.
-/
theorem replay_determinism_boundary :
    ReplayDeterminism gate ∧
    (∀ c₁ c₂ : ToolCallChar,
        c₁.tool = c₂.tool →
        c₁.command = c₂.command →
        c₁.targetPath = c₂.targetPath →
        c₁.sourceTrust = c₂.sourceTrust →
        gate c₁ = gate c₂) ∧
    (∀ c₁ c₂ : ToolCallChar,
        c₁.tool = c₂.tool →
        c₁.command = c₂.command →
        c₁.targetPath = c₂.targetPath →
        c₁.sourceTrust = c₂.sourceTrust →
        triple c₁ = triple c₂) := by
  refine ⟨gate_replay_deterministic,
           gate_replay_deterministic_fields,
           triple_replay_deterministic_fields⟩

end AgentWall.ReplayDeterminism
