#!/bin/bash
# agent-wall Formal Verification Script
# =======================================
# Mirrors the EvoEcos `formal/verify.sh` protocol, scaled down for v0.1.
#
# The gate is `lake build` success: a proof that fails with `simp` or
# `linarith` contains no `sorry` and slips past a text grep, so the
# compile is the real check. sorry/axiom baselines are pinned at 0 (the
# same baseline EvoEcos maintains after the CSTRMapping axiom discharge).

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LEAN_DIR="${SCRIPT_DIR}/lean"

echo "=== agent-wall Formal Verification (Lean 4) ==="
echo ""

if ! command -v lake &> /dev/null; then
    echo "Lean 4 toolchain not found!"
    echo ""
    echo "Install Lean 4:"
    echo "  curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh"
    echo "  source ~/.elan/env"
    exit 1
fi

echo "Lean version: $(lean --version 2>&1 | head -1)"
echo ""

# Build the library. agent-wall has no mathlib dependency by design, so the
# build is self-contained and fast.
cd "$LEAN_DIR"

echo "Running 'lake build'..."
echo ""
lake build AgentWall

echo ""
echo "=== Checking for proof debt ==="

SORRY_COUNT=$(grep -rP '^\s*sorry\b' AgentWall/ AgentWall.lean --include="*.lean" 2>/dev/null | wc -l)
AXIOM_COUNT=$(grep -rP '^\s*axiom\b' AgentWall/ AgentWall.lean --include="*.lean" 2>/dev/null | wc -l)

echo "sorry count: ${SORRY_COUNT}"
echo "axiom count: ${AXIOM_COUNT}"
echo "(NOTE: the lake build above is the real gate — sorry/axiom counts are"
echo " informational, mirroring EvoEcos's protocol.)"

AXIOM_MAX=0
FAIL=0
if [ "$SORRY_COUNT" -gt 0 ]; then
    echo ""
    echo "FAIL: sorry regression (baseline 0, found ${SORRY_COUNT})."
    grep -rnP '^\s*sorry\b' AgentWall/ AgentWall.lean --include="*.lean" | head -10
    FAIL=1
fi
if [ "$AXIOM_COUNT" -gt "$AXIOM_MAX" ]; then
    echo ""
    echo "FAIL: axiom regression (baseline ${AXIOM_MAX}, found ${AXIOM_COUNT})."
    grep -rnP '^\s*axiom\b' AgentWall/ AgentWall.lean --include="*.lean" | head -10
    FAIL=1
fi

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi

echo ""
echo "=== Verification Complete ==="
