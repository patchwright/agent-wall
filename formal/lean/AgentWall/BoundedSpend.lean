import AgentWall.NoSelfExfiltration

/-!
# AgentWall.BoundedSpend

v0.2 invariant #2 of the `agent-wall` library: a deterministic policy gate
admits a tool-call only if its declared cost is within the operator's
remaining budget.

Composes with `NoSelfExfiltration` (v0.1) and `AllowlistedPaths` (v0.2 #1):
the v0.1 wall stops exfil, the path-allowlist bounds the write target, this
invariant bounds the spend. The wall-override experiment's
`cumulative_budget` arm shows spend caps compose with structural caps; this
module formalizes the per-call atomic check that composes into the rolling
window (the rolling-window accounting is a v0.3 session-state concern).

Mirrors the EvoEcos idiom: `structure` → condition → `gate` → boundary
theorem → named `Prop` predicate → soundness bridge.

The `withinBudget` test is defined via `decide (c.declaredCost ≤
c.remainingBudget)` so the Bool/Prop bridge is `decide_eq_true_iff` /
`decide_eq_false_iff` — clean, no boolean-reflection friction on `Nat.le`.
-/

open AgentWall (Decision)

namespace AgentWall.BoundedSpend

/--
The spend-relevant slice of a tool-call. Carries the two `Nat` fields the
gate reads; everything else (tool name, command, path) is handled by other
invariants and omitted here to keep the proof surface small. The system
invariant (v1.0 target) composes the slices.
-/
structure SpendCallChar where
  /-- Tool name (carried for the system-level invariant composition in v1.0). -/
  tool            : String
  /-- Cost the call declares it will incur, in operator-chosen units
  (USD cents, tokens, API calls). The unit is opaque to the gate. -/
  declaredCost    : Nat
  /-- Budget remaining in the current rolling window. -/
  remainingBudget : Nat
  deriving DecidableEq, Repr

/--
The within-budget condition: declared cost ≤ remaining budget.

Implemented via `decide (...)` on the `Prop` inequality so the proof bridge
is the standard `decide_eq_true_iff` / `decide_eq_false_iff`, avoiding
boolean-reflection friction on `Nat.le`. The decision procedure for
`Nat.le` is in Lean 4 core (no mathlib needed).
-/
def withinBudget (c : SpendCallChar) : Bool :=
  decide (c.declaredCost ≤ c.remainingBudget)

/--
The deterministic spend gate. Allow iff within budget. Pure function of
`SpendCallChar`; no model, no IO, no randomness.
-/
def spendGate (c : SpendCallChar) : Decision :=
  match withinBudget c with
  | true  => Decision.Allow
  | false => Decision.Deny

/-! ## The boundary theorem (positive + negative + independence)

Same shape as `AgentWall.no_self_exfiltration_boundary`.
-/

/-- Positive biconditional: the gate admits iff within budget. -/
theorem spendGate_allow_iff_withinBudget (c : SpendCallChar) :
    spendGate c = Decision.Allow ↔ withinBudget c = true := by
  cases h : withinBudget c with
  | true  => simp [spendGate, h]
  | false => simp [spendGate, h]

/-- Negative implication: a failed within-budget check denies the call. -/
theorem spendGate_deny_of_withinBudget_false (c : SpendCallChar)
    (h : withinBudget c = false) :
    spendGate c = Decision.Deny := by
  cases h' : withinBudget c with
  | true  => simp [h'] at h
  | false => simp [spendGate, h]

/--
Bool/Prop bridge: `withinBudget` holds iff the cost is ≤ the budget.
Useful for downstream consumers that want to reason in `Prop`.
-/
theorem withinBudget_iff_le (c : SpendCallChar) :
    withinBudget c = true ↔ c.declaredCost ≤ c.remainingBudget := by
  simp only [withinBudget, decide_eq_true_iff]

/--
The over-budget condition expressed directly as a `Nat` strict inequality
`remainingBudget < declaredCost` (i.e. `declaredCost > remainingBudget`).
This is the natural-language form of the independence witness.

The Bool/Prop bridge goes through `Bool.eq_false_iff` + `decide_eq_true_iff`
+ `Nat.not_le` because Lean 4 core (no mathlib) lacks the composite
`decide_eq_false_iff` lemma — the explicit chain makes the proof auditable
without the mathlib dependency.
-/
theorem spendGate_deny_of_cost_gt_budget (c : SpendCallChar)
    (h : c.remainingBudget < c.declaredCost) :
    spendGate c = Decision.Deny := by
  apply spendGate_deny_of_withinBudget_false
  -- Goal: withinBudget c = false
  -- withinBudget c unfolds to decide (c.declaredCost ≤ c.remainingBudget).
  -- Bridge: b = false ↔ b ≠ true (Bool.eq_false_iff), unfold ≠ via ne_eq,
  -- then ¬decide p = true ↔ ¬p (decide_eq_true_iff), then ¬(a ≤ b) ↔ b < a
  -- (Nat.not_le). Lean 4 core (no mathlib) lacks the composite
  -- `decide_eq_false_iff`, so the chain is explicit.
  simp only [withinBudget, Bool.eq_false_iff, ne_eq,
             decide_eq_true_iff, Nat.not_le]
  exact h

/--
Independence witness — degenerate case: zero remaining budget denies any
positive cost. Useful as the simplest concrete deny instance and the
building block for the "spend cap at zero" corollary.
-/
theorem spendGate_deny_of_zero_budget_positive_cost (c : SpendCallChar)
    (hcost : c.declaredCost > 0)
    (hbudget : c.remainingBudget = 0) :
    spendGate c = Decision.Deny := by
  apply spendGate_deny_of_cost_gt_budget
  rw [hbudget]
  exact hcost

/--
The v0.2 boundary theorem for the bounded-spend invariant. Bundles the
positive biconditional, the negative implication, and two independence
witnesses (one general, one degenerate) — same shape as
`AgentWall.no_self_exfiltration_boundary`.
-/
theorem bounded_spend_boundary (c : SpendCallChar) :
    (spendGate c = Decision.Allow ↔ withinBudget c = true) ∧
    (withinBudget c = false → spendGate c = Decision.Deny) ∧
    (c.remainingBudget < c.declaredCost → spendGate c = Decision.Deny) ∧
    (c.declaredCost > 0 → c.remainingBudget = 0 → spendGate c = Decision.Deny) := by
  refine ⟨spendGate_allow_iff_withinBudget c,
           spendGate_deny_of_withinBudget_false c,
           spendGate_deny_of_cost_gt_budget c,
           spendGate_deny_of_zero_budget_positive_cost c⟩

/-! ## The invariant predicate + soundness bridge -/

/-- The v0.2 invariant predicate. -/
def BoundedSpend (c : SpendCallChar) : Prop :=
  spendGate c = Decision.Allow

/--
Soundness bridge: the invariant holds iff the declared cost is within the
remaining budget. Consumers that want the `Prop` form cite
`BoundedSpend c`; consumers that want the arithmetic form cite this lemma.
-/
theorem bounded_spend_iff_le (c : SpendCallChar) :
    BoundedSpend c ↔ c.declaredCost ≤ c.remainingBudget := by
  simp only [BoundedSpend]
  rw [spendGate_allow_iff_withinBudget, withinBudget_iff_le]

end AgentWall.BoundedSpend
