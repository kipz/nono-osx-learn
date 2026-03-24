#!/usr/bin/env bash
#
# Permission Groups Demo Walkthrough
# ===================================
#
# This script guides you through the permission groups feature.
# Run it from the repo root in the worktree.
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
NONO="$ROOT/target/debug/nono"
GUI="$ROOT/apps/nono-privileges/.build/arm64-apple-macosx/debug/NonoPrivileges"
# Use absolute path — worktrees don't share untracked files with the main repo
PROFILE="$(cd "$ROOT" && pwd)/profiles/demo-groups.json"
if [ ! -f "$PROFILE" ]; then
    red "Profile not found: $PROFILE"
    exit 1
fi
CLIENT="$ROOT/tests/e2e/control-socket-client.sh"

bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m%s\033[0m\n' "$*"; }
dim()   { printf '\033[2m%s\033[0m\n' "$*"; }

wait_for_enter() {
    echo ""
    read -rp "$(printf '\033[2m[Press Enter to continue]\033[0m ')"
    echo ""
}

# ─── Preflight ────────────────────────────────────────────────────────
bold "Permission Groups Demo"
echo "═══════════════════════════════════════════════════"
echo ""

if [ ! -x "$NONO" ]; then
    red "nono binary not found at $NONO — run 'cargo build --workspace' first"
    exit 1
fi

echo "Profile:  $PROFILE"
echo "Binary:   $NONO"
echo "GUI:      $GUI"
echo ""

# ─── Step 1: Show the profile ────────────────────────────────────────
bold "Step 1: Review the demo profile"
echo ""
echo "The profile defines 3 permission groups:"
echo ""
blue "  git-readonly     No auth needed, no expiry"
echo "                    Allows: git status, log, diff, fetch, branch"
echo ""
blue "  git-write        Requires TouchID, 5min timeout"
echo "                    Allows: git push, git remote add"
echo ""
blue "  network-access   Requires TouchID, 2min timeout"
echo "                    Allows: curl (any args)"
echo ""
echo "Mediated commands:"
echo "  - curl: blocked entirely by default (intercept with empty prefix)"
echo "  - git push / git remote add: blocked by default"
echo "  - git status, log, etc: pass through normally (no intercept rule)"
echo ""
wait_for_enter

# ─── Step 2: Launch the GUI ──────────────────────────────────────────
bold "Step 2: Launch the menu bar app"
echo ""
echo "Starting nono-privileges in the background..."
"$GUI" &
GUI_PID=$!
echo "GUI launched (PID $GUI_PID). Look for the key icon in your menu bar."
echo ""
dim "The menu bar app polls for nono sessions every 5 seconds."
dim "It will show 'No active sessions' until we start one."
wait_for_enter

# ─── Step 3: Start a nono session ────────────────────────────────────
bold "Step 3: Start a nono session with the demo profile"
echo ""
echo "Running: nono run --profile $PROFILE -- bash"
echo ""
dim "This opens an interactive bash shell inside the sandbox."
dim "The mediation server starts and the GUI will discover the session."
echo ""
bold "In the sandboxed shell, try these commands:"
echo ""
echo "  1. git status          (should work — not intercepted)"
echo "  2. git push             (should be blocked — intercepted)"
echo "  3. curl https://example.com  (should be blocked — intercepted)"
echo ""
bold "Then use the GUI menu bar app to:"
echo ""
echo "  4. Click the key icon in the menu bar"
echo "  5. You should see the session with 3 permission groups"
echo "  6. Click 'git-readonly' — no auth needed, activates instantly"
echo "  7. Try 'git push' again in the shell — still blocked (not in git-readonly)"
echo "  8. Click 'git-write' — TouchID prompt appears"
echo "  9. After auth, try 'git push' — now passes through (5min timer shown)"
echo " 10. Click 'network-access' — TouchID prompt, then curl works"
echo " 11. Click an active group again to deactivate it"
echo " 12. Try 'Enable YOLO Mode' — everything passes through"
echo ""
bold "Starting the sandboxed shell now..."
echo ""
# Use --norc --noprofile to prevent macOS path_helper from rearranging
# PATH and pushing the shim dir behind /opt/homebrew/bin.
# -s suppresses all nono output (banner, skill scan, diagnostics).
# The extra echo before bash ensures a newline before the prompt.
"$NONO" run -s --profile "$PROFILE" -- bash --norc --noprofile -c 'echo; exec bash --norc --noprofile' || true

# ─── Cleanup ─────────────────────────────────────────────────────────
echo ""
bold "Session ended."
echo ""
echo "Cleaning up GUI..."
kill "$GUI_PID" 2>/dev/null || true
green "Done! Demo complete."
