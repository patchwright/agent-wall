import Lake
open Lake DSL

/-!
# agent-wall Lean library

Deliberately *no* `require mathlib` — the v0.1 invariants are pure
Bool/String reasoning and must compile against Lean 4 core alone, so the
formal artifact stays small, the build is fast, and there is no mathlib
pin to drift against. (EvoEcos's `formal/lean/lakefile.lean` carries
mathlib because its proofs need it; this library does not.)
-/

package «agent_wall»

@[default_target]
lean_lib «AgentWall» where
