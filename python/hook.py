#!/usr/bin/env python3
"""
agent-wall: Claude Code PreToolUse hook (v0.2 PoC).

Deterministic, formally-bounded safety gate for autonomous AI agents.
This is the Python runtime that mirrors the Lean invariants in
`formal/lean/AgentWall/`:

  * `NoSelfExfiltration.lean`   (v0.1) ↔ exfil signature + forbidden-path denylist
  * `AllowlistedPaths.lean`     (v0.2) ↔ positive write-target allowlist
  * `BoundedSpend.lean`         (v0.2) ↔ declared-cost ≤ remaining-budget
  * `ReplayDeterminism.lean`    (v0.2) ↔ the gate is a pure function of its inputs

Each Python check below MUST stay in lock-step with the corresponding Lean
definition. The block/allow outcomes are cross-checked against the Lean
contract in `python/tests/test_hook.py`. No LLM judge, no network call.

Determinism contract (the `ReplayDeterminism` invariant): the gate is a
pure function of `(tool_name, tool_input)` OVER A FROZEN STARTUP CONFIG.
Feature flags (`AGENT_WALL_ALLOWLIST_ENABLED`, `AGENT_WALL_SPEND_ENABLED`)
are read ONCE at module import — not per call — so within a single
process the same inputs always yield the same decision. The path gates
additionally call `os.path.realpath()` to close path-traversal bypasses;
that call resolves symlinks via a filesystem read, so two calls with
identical `tool_input` can differ iff the filesystem state changed
between them (a deliberate security-property choice — see README
§"Known bypasses"). The Lean `ReplayDeterminism` invariant is stated
over the pure Lean gate `ToolCallChar → Decision` (no IO); the Python
gate matches it modulo the realpath resolution, which is documented
here and in the gate's docstring.

Claude Code PreToolUse hook contract
(https://docs.claude.com/en/docs/claude-code/hooks):
  * stdin: a single JSON object with at least
        {"hook_event_name": "PreToolUse",
         "tool_name": "<Bash|Write|Edit|Read|...>",
         "tool_input": { ... }}
  * exit 0  -> allow the tool-call
  * exit 2  -> BLOCK the tool-call; stderr is shown to Claude so it can correct
  * other   -> error (non-blocking; the tool-call still proceeds)

Usage in .claude/settings.json:
  {
    "hooks": {
      "PreToolUse": [
        {
          "matcher": "Bash|Write|Edit",
          "hooks": [
            {"type": "command",
             "command": "python3 /abs/path/to/agent-wall/python/hook.py"}
          ]
        }
      ]
    }
  }

Operator-tunable knobs (all default to v0.2 hardening ON):
  * AGENT_WALL_ALLOWLIST_ENABLED=0  disables the path-allowlist invariant
                                     (reverts to v0.1 denylist-only behaviour)
  * AGENT_WALL_SPEND_ENABLED=0       disables the bounded-spend invariant
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from typing import Any, Callable

# ---------------------------------------------------------------------------
# Deterministic signature + path policy.
#
# These MUST stay in lock-step with the Lean definitions in
# formal/lean/AgentWall/*.lean:
#
#   NoSelfExfiltration.lean:
#     - isExfilSignature      (Lean)  <-> EXFIL_SIGNATURES  (here)
#     - isForbiddenPath       (Lean)  <-> FORBIDDEN_PATHS   (here)
#     - toolAllowed           (Lean)  <-> ALLOWED_TOOLS     (here)
#
#   AllowlistedPaths.lean:
#     - isAllowlistedPath     (Lean)  <-> ALLOWED_ROOTS + is_allowlisted_path
#     - isWriteTool           (Lean)  <-> WRITE_TOOLS
#     - isNormalizedPath      (Lean)  <-> _normalize_path (realpath precondition)
#
#   BoundedSpend.lean:
#     - withinBudget          (Lean)  <-> spend_gate (declared_cost ≤ remaining_budget)
#
# Any divergence between the two is a contract bug; the test suite
# (python/tests/test_hook.py) cross-checks the block/allow behaviour against
# the documented Lean contract.
#
# PATH-TRAVERSAL DEFENSE: every path the gates inspect is first resolved
# through `os.path.realpath()` (see `_normalize_path`). This closes
# `/tmp/../etc/passwd`-style bypasses against the allowlist invariant
# (the Lean `isAllowlistedPath` predicate is a pure prefix test on
# `String` and does not model traversal on its own — see the
# `isNormalizedPath` precondition in `AllowlistedPaths.lean`).
# ---------------------------------------------------------------------------

ALLOWED_TOOLS = frozenset({"Bash", "Read", "Edit", "Write"})

# Tools that have a target path worth gating on the allowlist invariant.
# Mirrors Lean `AgentWall.AllowlistedPaths.isWriteTool`.
WRITE_TOOLS = frozenset({"Write", "Edit"})

# Exfiltration / shell-pipe signatures. Each entry is a tuple of substrings
# that must ALL be present (conjunction), or a single substring (matches if
# present). Mirrors Lean `isExfilSignature`.
EXFIL_SIGNATURES: tuple[tuple[str, ...], ...] = (
    ("curl ", "| sh"),
    ("wget ", "| sh"),
    ("| bash",),
    ("eval ",),
    ("/dev/tcp/",),
)

# Forbidden credential-store path substrings. Mirrors Lean `isForbiddenPath`.
FORBIDDEN_PATHS = (
    ".ssh/",
    ".aws/credentials",
    ".env",
    ".gnupg/",
)

# Bash commands that write into a forbidden path (covers `echo ... > ~/.ssh/...`,
# `cat ... >> ~/.ssh/authorized_keys`, etc.) even without an exfil pipe.
FORBIDDEN_PATH_REDIRECT = (">", ">>", "tee ")

# v0.2 invariant #1: operator-blessed write roots. A path is allowlisted iff
# one of these is a strict prefix (mirror of Lean `String.startsWith`, NOT
# substring — substring would let `/home/user/repo/../../../etc/passwd`
# through, so the strict prefix test is the conservative direction for an
# allowlist). Mirrors Lean `AgentWall.AllowlistedPaths.ALLOWED_ROOTS`.
ALLOWED_ROOTS: tuple[str, ...] = (
    "/tmp/",
    "/home/user/",
    "/home/fredde/",
    "/var/tmp/",
)


# ---------------------------------------------------------------------------
# Pure decision logic
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Decision:
    """Mirrors `AgentWall.Decision`."""
    allow: bool
    reason: str = ""


def contains_all(cmd: str, needles: tuple[str, ...]) -> bool:
    """Mirrors Lean `containsSubstr` lifted to a conjunction of substrings."""
    return all(n in cmd for n in needles)


def is_exfil_signature(cmd: str) -> bool:
    """Mirrors Lean `isExfilSignature`."""
    return any(contains_all(cmd, sig) for sig in EXFIL_SIGNATURES)


def is_forbidden_path(p: str) -> bool:
    """
    Mirrors Lean `isForbiddenPath`. Assumes `p` has already been
    normalized via `_normalize_path` (realpath) — substring match on a
    raw unnormalized path could miss traversal-obscured variants like
    `/home/u/.ssh/../authorized_keys` (which realpath collapses to
    `/home/u/authorized_keys`, no longer matching `.ssh/`).
    """
    return any(seg in p for seg in FORBIDDEN_PATHS)


def is_allowlisted_path(p: str) -> bool:
    """
    Mirrors Lean `AgentWall.AllowlistedPaths.isAllowlistedPath`.

    Strict prefix match (NOT substring) against `ALLOWED_ROOTS`. Conservative
    direction for an allowlist — a path is allowed only if it begins with
    one of the operator-blessed roots.

    PRECONDITION: `p` MUST be realpath-normalized before this check fires.
    The Lean `isAllowlistedPath` predicate is a pure prefix test on
    `String` and does NOT model path traversal: a literal like
    `/tmp/../etc/passwd` would pass the `/tmp/` prefix test on its own.
    The Python layer enforces the normalization via `_normalize_path`
    (which calls `os.path.realpath()`) so the predicate is only ever
    evaluated on the resolved form. See `AllowlistedPaths.lean`'s
    `isNormalizedPath` and the README §"Known bypasses".
    """
    return any(p.startswith(root) for root in ALLOWED_ROOTS)


def _normalize_path(p: str) -> str:
    """
    Resolve `p` to a canonical absolute path before the allowlist and
    forbidden-path gates inspect it. Closes path-traversal bypasses:
    `/tmp/../etc/passwd` resolves to `/etc/passwd`, which is not under
    `/tmp/` → denied by the allowlist invariant (regression test in
    `python/tests/test_hook_bypasses.py`).

    Mirrors the Lean `isNormalizedPath` precondition on
    `AllowlistedPaths.isAllowlistedPath`: the Lean predicate assumes a
    normalized path; the Python layer enforces that precondition.

    `realpath` also resolves symlinks, so a symlink under `/tmp/` that
    points outside `/tmp/` is correctly resolved to its target before
    the allowlist check (closes symlink-based traversal at the cost of
    a filesystem read — see the determinism caveat in `gate()`'s
    docstring and README §"Known bypasses" for the TOCTOU note).
    """
    if not p:
        return p
    try:
        return os.path.realpath(p)
    except (OSError, ValueError):
        # Path cannot be resolved (e.g. embedded null bytes). Fall back
        # to lexical normalization only; both gates still run on the
        # lexical form. realpath raising on a non-existent path is rare
        # (Python ≥3.6 returns the resolved path even when the file is
        # missing) but the try/except keeps the gate non-blocking on
        # exotic inputs.
        return os.path.normpath(p)


def is_write_tool(tool_name: str) -> bool:
    """Mirrors Lean `AgentWall.AllowlistedPaths.isWriteTool`."""
    return tool_name in WRITE_TOOLS


def tool_allowed(tool_name: str) -> bool:
    """Mirrors Lean `toolAllowed`."""
    return tool_name in ALLOWED_TOOLS


def within_budget(declared_cost: int, remaining_budget: int) -> bool:
    """
    Mirrors Lean `AgentWall.BoundedSpend.withinBudget`.

    True iff the declared cost is ≤ the remaining budget. Pure function of
    two `Nat`-equivalent ints; no side effects, no randomness.
    """
    return declared_cost <= remaining_budget


def spend_gate(declared_cost: int, remaining_budget: int) -> Decision:
    """
    Mirrors Lean `AgentWall.BoundedSpend.spendGate`.

    Allow iff within budget. Returns Decision(allow=True/False, reason).
    Pure function — the bounded-spend invariant's atomic check.
    """
    if within_budget(declared_cost, remaining_budget):
        return Decision(True, "within budget")
    return Decision(
        False,
        f"declared_cost {declared_cost} > remaining_budget {remaining_budget}",
    )


def _bash_writes_into_forbidden(cmd: str) -> str | None:
    """If a Bash command redirects into a forbidden path, return that path."""
    # Split on redirect operators and inspect the right-hand side target.
    for op in FORBIDDEN_PATH_REDIRECT:
        if op in cmd:
            for piece in cmd.split(op)[1:]:
                # Strip leading whitespace and quotes; take the first token.
                token = piece.strip().strip("'\"").split()[0] if piece.strip() else ""
                if not token:
                    continue
                # Defense-in-depth: substring-denylist on BOTH the raw token
                # (preserves the v0.1 contract — `~/.ssh/../authorized_keys`
                # still matches `.ssh/` in the raw form) AND the realpath-
                # resolved form (catches absolute-traversal variants).
                if is_forbidden_path(token):
                    return token
                ntoken = _normalize_path(token)
                if ntoken != token and is_forbidden_path(ntoken):
                    return ntoken
    return None


# ---------------------------------------------------------------------------
# Feature flags — all v0.2 hardening ON by default. Set to "0" to revert.
#
# Determinism (ReplayDeterminism invariant): these flags are read ONCE at
# module import into module-level bool constants, NOT on every gate call.
# Within a single process the gate is therefore a pure function of
# `(tool_name, tool_input)`; cross-process runs differ iff the operator
# changes the env (a legitimate config change, not a determinism bug).
# Pre-fix the flags were per-call lambdas, which made the gate implicitly
# depend on env-mutation mid-session — that broke the invariant's
# "pure function of inputs" contract. Module-level constants restore it.
# ---------------------------------------------------------------------------

def _flag(name: str, default: bool = True) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip() not in ("0", "false", "False", "")


ALLOWLIST_ENABLED: bool = _flag("AGENT_WALL_ALLOWLIST_ENABLED", True)
SPEND_ENABLED: bool = _flag("AGENT_WALL_SPEND_ENABLED", True)


def gate(tool_name: str, tool_input: dict[str, Any]) -> Decision:
    """
    The deterministic policy gate. Mirrors `AgentWall.gate` extended for v0.2:
      triple = toolAllowed && commandSafe && targetSafe
      v0.2 adds: && pathAllowlisted (for write tools)
                 && withinBudget (when tool_input declares cost/budget)
      gate c = if triple then Allow else Deny

    Returns Decision(allow=True) iff every enabled condition holds.

    Determinism contract (mirrors `AgentWall.ReplayDeterminism`):
      * Feature flags (`AGENT_WALL_ALLOWLIST_ENABLED`,
        `AGENT_WALL_SPEND_ENABLED`) are read ONCE at module import, so
        within a single process the gate is a pure function of
        `(tool_name, tool_input)` over the frozen startup config.
      * Caveat — realpath filesystem read: the Write/Edit path gate and
        the Bash redirect-inspection both call `os.path.realpath()` on
        the target path before the allowlist / forbidden-path checks.
        `realpath` resolves symlinks via a filesystem read, so two
        calls with identical `tool_input` can differ iff the filesystem
        state changed between them. This is a deliberate security-choice
        (closes symlink-based path traversal) at the cost of strict
        referential purity; the Lean `ReplayDeterminism` invariant is
        stated over the pure Lean gate, and the Python gate matches it
        modulo this documented filesystem dependency. See README
        §"Known bypasses" for the corresponding TOCTOU note.
    """
    # Condition 1: allowlisted tool.
    if not tool_allowed(tool_name):
        return Decision(False, f"tool '{tool_name}' not on allowlist {sorted(ALLOWED_TOOLS)}")

    # Condition 2 (Bash): no exfiltration signature in the command.
    if tool_name == "Bash":
        cmd = str(tool_input.get("command", ""))
        if is_exfil_signature(cmd):
            return Decision(False, f"command matched exfiltration signature: {cmd!r}")
        # Also block Bash writes into forbidden paths (echo > ~/.ssh/..., etc.).
        hit = _bash_writes_into_forbidden(cmd)
        if hit is not None:
            return Decision(False, f"Bash writes into forbidden path {hit!r}")

    # Condition 3 (Write/Edit): target path is not a credential store (v0.1),
    # AND is under an operator-blessed root (v0.2 #1). Both checks run on the
    # REALPATH-NORMALIZED form so traversal-obscured variants
    # (`/tmp/../etc/passwd`, `/home/u/.ssh/../authorized_keys`) are caught.
    #
    # Defense-in-depth on the forbidden-path denylist: the substring check
    # runs on BOTH the raw input AND the normalized form. The raw check
    # preserves the v0.1 substring contract (so `.ssh/../authorized_keys`
    # still matches `.ssh/` in the raw form even though realpath collapses
    # it); the normalized check catches paths whose resolution lands on a
    # forbidden target via symlink or absolute traversal.
    if is_write_tool(tool_name):
        raw_path = str(tool_input.get("file_path", tool_input.get("path", "")))
        norm_path = _normalize_path(raw_path)
        if is_forbidden_path(raw_path):
            return Decision(False, f"write to forbidden path {raw_path!r}")
        if is_forbidden_path(norm_path):
            return Decision(False, f"write to forbidden path {norm_path!r} (resolved from {raw_path!r})")

        # v0.2 invariant #1 — AllowlistedPaths: target must be under an
        # operator-blessed root. This is the positive-list dual of condition 3.
        # The prefix test is what's vulnerable to traversal, so it runs on
        # the normalized form only. Hardening: ON by default; disable via
        # AGENT_WALL_ALLOWLIST_ENABLED=0.
        if ALLOWLIST_ENABLED and not is_allowlisted_path(norm_path):
            return Decision(
                False,
                f"write target {norm_path!r} (resolved from {raw_path!r}) "
                f"not under any allowed root {list(ALLOWED_ROOTS)}",
            )

    # v0.2 invariant #2 — BoundedSpend: when the tool_input declares a cost
    # and remaining budget (no Claude Code tool does this natively today; the
    # PoC accepts the fields for composability with future spend-tracking
    # adapters), the spend gate runs. Mirrors `AgentWall.BoundedSpend.spendGate`.
    if SPEND_ENABLED and "declared_cost" in tool_input and "remaining_budget" in tool_input:
        try:
            cost = int(tool_input["declared_cost"])
            budget = int(tool_input["remaining_budget"])
        except (TypeError, ValueError) as e:
            # Treat malformed cost/budget as a non-blocking parse error; do not
            # silently allow or silently block. Surface and skip the spend check.
            sys.stderr.write(
                f"agent-wall: malformed declared_cost/remaining_budget ({e}); skipping spend gate\n"
            )
        else:
            spend = spend_gate(cost, budget)
            if not spend.allow:
                return Decision(False, f"bounded-spend: {spend.reason}")

    # All enabled conditions hold.
    return Decision(True)


# ---------------------------------------------------------------------------
# PreToolUse hook entry point
# ---------------------------------------------------------------------------

def main() -> int:
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as e:
        # Malformed input is a non-blocking error (exit non-2) — never silently
        # allow, never silently block. Surface the parse failure and let the
        # tool-call proceed (the harness will report the hook error).
        sys.stderr.write(f"agent-wall: malformed PreToolUse JSON ({e}); skipping\n")
        return 1

    tool_name = str(payload.get("tool_name", ""))
    tool_input = payload.get("tool_input", {}) or {}

    decision = gate(tool_name, tool_input)
    if decision.allow:
        return 0

    # Exit 2 == BLOCK. Claude sees this stderr and can correct course.
    # Structured-ish line so logs are greppable.
    sys.stderr.write(
        f"agent-wall BLOCK: {decision.reason}\n"
        f"  (deterministic gate; see formal/lean/AgentWall/*.lean)\n"
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
