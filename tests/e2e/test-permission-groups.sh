#!/usr/bin/env bash
# End-to-end test for permission groups via the control socket.
#
# Creates a nono mediation session with groups defined, then exercises
# the control socket protocol: enable group, check status, disable.
#
# Prerequisites:
#   - nono built and on PATH (or in ../target/debug/)
#   - python3 available (for control-socket-client.sh)
#
# Usage:
#   ./tests/e2e/test-permission-groups.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$SCRIPT_DIR/control-socket-client.sh"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; ((PASS++)); }
fail() { echo "  FAIL: $1"; ((FAIL++)); }

echo "=== Permission Groups E2E Test ==="
echo ""

# Find a running nono session
SESSION_DIR=$(ls -d /private/tmp/nono-session-* 2>/dev/null | head -1 || true)
if [ -z "$SESSION_DIR" ]; then
    echo "No active nono session found. Start one with a mediation profile that has groups."
    echo "Example: nono run --profile my-profile -- sleep 300"
    exit 1
fi

SESSION_JSON="$SESSION_DIR/session.json"
if [ ! -f "$SESSION_JSON" ]; then
    echo "session.json not found in $SESSION_DIR"
    exit 1
fi

SOCKET=$(python3 -c "import json; d=json.load(open('$SESSION_JSON')); print(d['control_socket'])")
TOKEN=$(python3 -c "import json; d=json.load(open('$SESSION_JSON')); print(d['control_token'])")
GROUPS=$(python3 -c "import json; d=json.load(open('$SESSION_JSON')); print(json.dumps(d.get('groups', [])))")

echo "Session dir: $SESSION_DIR"
echo "Groups in session.json: $GROUPS"
echo ""

# Test 1: Status shows groups
echo "Test 1: Status response includes groups"
STATUS=$("$CLIENT" "$SOCKET" "$TOKEN" status)
if echo "$STATUS" | python3 -c "import sys, json; d=json.load(sys.stdin); assert 'groups' in d, 'no groups key'" 2>/dev/null; then
    pass "status response contains groups"
else
    fail "status response missing groups"
fi

# Test 2: Status starts disabled
echo "Test 2: Initial status is disabled"
if echo "$STATUS" | python3 -c "import sys, json; d=json.load(sys.stdin); assert d['status'] == 'disabled'" 2>/dev/null; then
    pass "initial status is disabled"
else
    fail "initial status is not disabled"
fi

# Test 3: Enable unknown group returns error
echo "Test 3: Enabling unknown group returns error"
RESP=$("$CLIENT" "$SOCKET" "$TOKEN" enable "nonexistent_group_xyz" || true)
if echo "$RESP" | python3 -c "import sys, json; d=json.load(sys.stdin); assert not d['ok']" 2>/dev/null; then
    pass "unknown group rejected"
else
    fail "unknown group was not rejected"
fi

# Get the first group name (if any)
FIRST_GROUP=$(python3 -c "
import json
groups = json.loads('$GROUPS')
if groups:
    print(groups[0]['name'])
else:
    print('')
")

if [ -n "$FIRST_GROUP" ]; then
    # Test 4: Enable a group
    echo "Test 4: Enable group '$FIRST_GROUP'"
    RESP=$("$CLIENT" "$SOCKET" "$TOKEN" enable "$FIRST_GROUP" 60)
    if echo "$RESP" | python3 -c "import sys, json; d=json.load(sys.stdin); assert d['status'] == 'group' and d['active_group'] == '$FIRST_GROUP'" 2>/dev/null; then
        pass "group enabled successfully"
    else
        fail "group enable failed: $RESP"
    fi

    # Test 5: Status reflects active group
    echo "Test 5: Status shows active group"
    STATUS=$("$CLIENT" "$SOCKET" "$TOKEN" status)
    if echo "$STATUS" | python3 -c "import sys, json; d=json.load(sys.stdin); assert d['status'] == 'group' and d['active_group'] == '$FIRST_GROUP'" 2>/dev/null; then
        pass "status shows active group"
    else
        fail "status does not show active group: $STATUS"
    fi

    # Test 6: Disable
    echo "Test 6: Disable privilege mode"
    RESP=$("$CLIENT" "$SOCKET" "$TOKEN" disable)
    if echo "$RESP" | python3 -c "import sys, json; d=json.load(sys.stdin); assert d['status'] == 'disabled'" 2>/dev/null; then
        pass "disabled successfully"
    else
        fail "disable failed: $RESP"
    fi
fi

# Test 7: Enable YOLO mode
echo "Test 7: Enable YOLO mode"
RESP=$("$CLIENT" "$SOCKET" "$TOKEN" enable "" 30)
if echo "$RESP" | python3 -c "import sys, json; d=json.load(sys.stdin); assert d['status'] == 'yolo'" 2>/dev/null; then
    pass "YOLO mode enabled"
else
    fail "YOLO mode enable failed: $RESP"
fi

# Test 8: Disable YOLO
echo "Test 8: Disable YOLO mode"
RESP=$("$CLIENT" "$SOCKET" "$TOKEN" disable)
if echo "$RESP" | python3 -c "import sys, json; d=json.load(sys.stdin); assert d['status'] == 'disabled'" 2>/dev/null; then
    pass "YOLO mode disabled"
else
    fail "YOLO disable failed: $RESP"
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] || exit 1
