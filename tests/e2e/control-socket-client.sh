#!/usr/bin/env bash
# Lightweight control socket client for nono mediation sessions.
#
# Sends length-prefixed JSON requests to a control socket and prints
# the JSON response. Used by other e2e test scripts.
#
# Usage:
#   control-socket-client.sh <socket_path> <token> status
#   control-socket-client.sh <socket_path> <token> enable [group_name] [duration_secs]
#   control-socket-client.sh <socket_path> <token> disable
set -euo pipefail

SOCKET="$1"
TOKEN="$2"
ACTION="$3"
GROUP="${4:-}"
DURATION="${5:-600}"

case "$ACTION" in
    status)
        PAYLOAD=$(printf '{"token":"%s","action":"status"}' "$TOKEN")
        ;;
    enable)
        if [ -n "$GROUP" ]; then
            PAYLOAD=$(printf '{"token":"%s","action":"enable","group":"%s","duration_secs":%s,"granted_by":"e2e-test"}' "$TOKEN" "$GROUP" "$DURATION")
        else
            PAYLOAD=$(printf '{"token":"%s","action":"enable","duration_secs":%s,"granted_by":"e2e-test"}' "$TOKEN" "$DURATION")
        fi
        ;;
    disable)
        PAYLOAD=$(printf '{"token":"%s","action":"disable","granted_by":"e2e-test"}' "$TOKEN")
        ;;
    *)
        echo "Unknown action: $ACTION" >&2
        exit 1
        ;;
esac

# Send length-prefixed request and read length-prefixed response using python
python3 -c "
import socket, struct, sys, json

payload = b'''$PAYLOAD'''
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(10)
sock.connect('$SOCKET')

# Write: u32 big-endian length + payload
sock.sendall(struct.pack('>I', len(payload)) + payload)

# Read: u32 big-endian length + response
resp_len_bytes = b''
while len(resp_len_bytes) < 4:
    resp_len_bytes += sock.recv(4 - len(resp_len_bytes))
resp_len = struct.unpack('>I', resp_len_bytes)[0]

resp_bytes = b''
while len(resp_bytes) < resp_len:
    resp_bytes += sock.recv(resp_len - len(resp_bytes))

sock.close()
print(json.dumps(json.loads(resp_bytes), indent=2))
"
