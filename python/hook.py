#!/usr/bin/env python3
"""
agent-wall: Claude Code PreToolUse hook (v0.1 PoC).

Deterministic, formally-bounded safety gate for autonomous AI agents.
This is the Python runtime that mirrors `formal/lean/AgentWall/NoSelfExfiltration.lean`:
the same exfiltration signature and the same forbidden-path denylist that the
Lean invariant proves the gate denies on. No LLM judge, no network call, no
randomness — the decision is a pure function of (tool_name, tool_input), exactly
like `AgentWall.gate : ToolCallChar -> Decision`.

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
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# Deterministic signature + path policy.
#
# These MUST stay in lock-step with the Lean definitions in
# formal/lean/AgentWall/NoSelfExfiltration.lean:
#   - isExfilSignature      (Lean)  <-> EXFIL_SIGNATURES  (here)
#   - isForbiddenPath       (Lean)  <-> FORBIDDEN_PATHS   (here)
#   - toolAllowed           (Lean)  <-> ALLOWED_TOOLS     (here)
# Any divergence between the two is a contract bug; the test suite
# (python/tests/test_hook.py) cross-checks the block/allow behaviour against
# the documented Lean contract.
# ---------------------------------------------------------------------------

ALLOWED_TOOLS = frozenset({"Bash", "Read", "Edit", "Write"})

# Exfiltration / shell-pipe signatures. Each entry is a (a, b) pair where both
# substrings must be present (conjunction), or a single substring (matches if
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
    """Mirrors Lean `isForbiddenPath`."""
    return any(seg in p for seg in FORBIDDEN_PATHS)


def tool_allowed(tool_name: str) -> bool:
    """Mirrors Lean `toolAllowed`."""
    return tool_name in ALLOWED_TOOLS


def _bash_writes_into_forbidden(cmd: str) -> str | None:
    """If a Bash command redirects into a forbidden path, return that path."""
    # Split on redirect operators and inspect the right-hand side target.
    for op in FORBIDDEN_PATH_REDIRECT:
        if op in cmd:
            for piece in cmd.split(op)[1:]:
                # Strip leading whitespace and quotes; take the first token.
                token = piece.strip().strip("'\"").split()[0] if piece.strip() else ""
                if token and is_forbidden_path(token):
                    return token
    return None


def gate(tool_name: str, tool_input: dict[str, Any]) -> Decision:
    """
    The deterministic policy gate. Mirrors `AgentWall.gate`:
      triple = toolAllowed && commandSafe && targetSafe
      gate c = if triple then Allow else Deny

    Returns Decision(allow=True) iff all three conditions hold.
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

    # Condition 3 (Write/Edit): target path is not a credential store.
    if tool_name in ("Write", "Edit"):
        path = str(tool_input.get("file_path", tool_input.get("path", "")))
        if is_forbidden_path(path):
            return Decision(False, f"write to forbidden path {path!r}")

    # All three conditions hold.
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
        f"  (deterministic gate; see formal/lean/AgentWall/NoSelfExfiltration.lean)\n"
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
