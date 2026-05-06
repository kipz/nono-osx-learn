#!/usr/bin/env bash
# nono-trajectory.sh - emit trajectory-spec JSONL from Claude Code hook events.
# Version: 0.0.1
#
# Installed to ~/.claude/hooks/ by the claude-code profile. Fires for
# SessionStart, UserPromptSubmit, PreToolUse, PostToolUse, and SessionEnd.
# Exits silently when not running inside a nono sandbox or when required
# tooling is missing, so it is safe to leave registered outside nono.
#
# Output: one JSONL line per event appended to
#   $HOME/.nono/trajectory/session-<claude_session_id>.jsonl
#
# Spec: DataDog/trajectory-spec v0.1 (standard capture level).
# Deliberate non-conformance (see docs/2026-04-23-adopt-trajectory-spec.md §6):
# this first pass emits 5 of 8 event types; Stop/SubagentStop/PreCompact are
# follow-ups.
#
# Privacy: this hook deliberately strips two content fields that "standard"
# capture would otherwise carry, to avoid logging user-typed natural language
# or per-tool output to disk:
#   - input_prompt.content (the user's prompt) is NOT emitted.
#   - tool_use(post).output_summary is NOT emitted.
# Tool-call args (tool_use(pre).input) and structural metadata stay.

set -u

# Only run when nono is active. NONO_CAP_FILE is the established marker.
if [ -z "${NONO_CAP_FILE:-}" ]; then
    exit 0
fi

if ! command -v jq >/dev/null 2>&1; then
    exit 0
fi

payload=$(cat)
if [ -z "$payload" ]; then
    exit 0
fi

event_name=$(printf '%s' "$payload" | jq -r '.hook_event_name // empty' 2>/dev/null)
session_id=$(printf '%s' "$payload" | jq -r '.session_id // empty' 2>/dev/null)

if [ -z "$event_name" ] || [ -z "$session_id" ]; then
    exit 0
fi

# Validate session_id shape: hex / dash only, max 128 chars. Guards against
# path traversal via a malicious hook payload.
case "$session_id" in
    *[!a-zA-Z0-9_-]*) exit 0 ;;
esac
if [ "${#session_id}" -gt 128 ]; then
    exit 0
fi

traj_root="$HOME/.nono/trajectory"
out="$traj_root/session-$session_id.jsonl"

mkdir -p "$traj_root" || exit 0
chmod 700 "$traj_root" 2>/dev/null || true

# Serialize reads and writes of the counters and output file so sequence_number
# is strictly increasing across concurrent hook invocations (trajectory-spec I9).
# flock(1) ships on Linux but not BSD/macOS, so fall back to a portable
# mkdir-based lock when it is unavailable. Either way, time out and drop the
# event rather than block Claude Code's hook dispatch on a stale lock owner.
lock_held=""
lock_dir="$traj_root/.lockd-$session_id"
if command -v flock >/dev/null 2>&1; then
    lock="$traj_root/.lock-$session_id"
    if exec 9>"$lock" 2>/dev/null && flock -w 5 9; then
        lock_held="flock"
    else
        exit 0
    fi
else
    attempts=0
    while ! mkdir "$lock_dir" 2>/dev/null; do
        attempts=$((attempts + 1))
        if [ "$attempts" -gt 50 ]; then
            exit 0
        fi
        sleep 0.1
    done
    lock_held="mkdir"
fi

# Always release the lock on exit, even on early return below.
release_lock() {
    case "$lock_held" in
        mkdir) rmdir "$lock_dir" 2>/dev/null || true ;;
        flock) exec 9>&- 2>/dev/null || true ;;
    esac
}
trap release_lock EXIT

# Derive sequence_number and turn_id from the output JSONL itself rather
# than from sidecar files. Earlier revisions kept .seq-<sid>, .turn-<sid>,
# and .pending-tool-<sid> dotfiles next to the JSONL; under real Claude
# Code + nono they were silently being lost between hook invocations
# (sequence_number stayed at 0 across every event in every session — see
# PR #18 review). Root cause was never RCA'd. The output JSONL itself is
# what we ultimately care about and *does* persist (because it is opened
# O_APPEND, never truncated), so making it the single source of truth is
# self-healing and immune to whatever was wiping the dotfiles.
#
# We hold the per-session lock around both the read (line count) and the
# write (emit), so concurrent invocations cannot observe the same count
# and produce a duplicate sequence_number.
seq=0
turn=0
if [ -s "$out" ]; then
    seq=$(wc -l < "$out" | tr -d ' \t')
    turn=$(grep -c '"event_type":"input_prompt"' "$out" 2>/dev/null || true)
fi
case "$seq" in ''|*[!0-9]*) seq=0 ;; esac
case "$turn" in ''|*[!0-9]*) turn=0 ;; esac

# RFC 3339 UTC timestamp with millisecond precision. BSD `date` (macOS) does
# not support %3N / %N, so fall back to python when available. Capture the
# datetime once — splitting the seconds and sub-second components across two
# datetime.now() calls produces an inconsistent timestamp when the two reads
# straddle a millisecond boundary.
if date -u +"%Y-%m-%dT%H:%M:%S.%3NZ" 2>/dev/null | grep -qv 'N'; then
    ts=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
else
    ts=$(python3 -c '
from datetime import datetime, timezone
n = datetime.now(timezone.utc)
print(n.strftime("%Y-%m-%dT%H:%M:%S.") + f"{n.microsecond // 1000:03d}Z")
' 2>/dev/null)
    if [ -z "$ts" ]; then
        ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    fi
fi

# emit <event_type> <extra-json-object>
# Composes the base fields with an event-specific JSON fragment and appends
# one line to the output file. session_id is included on every event so
# downstream log search can filter a single Claude Code session out of the
# combined stream — the JSONL filename also encodes it, but Datadog log
# pipelines key off message fields, not filenames.
emit() {
    local et="$1"
    local extra="$2"
    printf '%s' "$payload" | jq -c \
        --arg et "$et" \
        --arg ts "$ts" \
        --arg sid "$session_id" \
        --argjson sn "$seq" \
        --argjson extra "$extra" \
        '{event_type: $et, timestamp: $ts, sequence_number: $sn, session_id: $sid} + $extra' \
        >> "$out"
}

case "$event_name" in
    SessionStart)
        # Claude Code's SessionStart payload (session_id / transcript_path / cwd /
        # hook_event_name / source) does not carry the agent model. Read it from
        # NONO_AGENT_MODEL when the launcher exports it; emit "unknown" otherwise.
        model="${NONO_AGENT_MODEL:-unknown}"
        cwd=$(printf '%s' "$payload" | jq -r '.cwd // ""')
        source=$(printf '%s' "$payload" | jq -r '.source // ""')
        # session_id comes from the base emit fields; no need to repeat it here.
        extra=$(jq -nc \
            --arg started "$ts" \
            --arg model "$model" \
            --arg cwd "$cwd" \
            --arg source "$source" \
            '{
                format_version: 1,
                started_at: $started,
                model: ("nono-sandbox/" + $model),
                capture_level: "standard",
                project_dir: $cwd,
                client_source: (if $source == "" then null else $source end)
            } | del(..|nulls)')
        emit session_start "$extra"
        ;;

    UserPromptSubmit)
        # Each new user prompt starts a new turn. `turn` was derived from the
        # JSONL above as the count of input_prompt events already on disk;
        # bumping by one assigns this prompt the next turn_id and the
        # tool_use events Claude emits while responding will read the same
        # value (since they re-count the JSONL, which now includes this
        # prompt). The prompt text itself is not captured — see privacy
        # note in header.
        turn=$((turn + 1))
        extra=$(jq -nc --argjson tid "$turn" '{turn_id: $tid}')
        emit input_prompt "$extra"
        ;;

    PreToolUse)
        tool=$(printf '%s' "$payload" | jq -r '.tool_name // "unknown"')
        # tool_use_id: prefer Claude-provided id if present, else synthesize.
        tuid=$(printf '%s' "$payload" | jq -r '.tool_use_id // empty')
        if [ -z "$tuid" ]; then
            tuid="$session_id:$seq"
        fi
        input=$(printf '%s' "$payload" | jq -c '.tool_input // {}')
        extra=$(jq -nc \
            --argjson tid "$turn" \
            --arg tuid "$tuid" \
            --arg tn "$tool" \
            --argjson inp "$input" \
            '{turn_id: $tid, tool_use_id: $tuid, tool_name: $tn, phase: "pre", input: $inp}')
        emit tool_use "$extra"
        ;;

    PostToolUse)
        tool=$(printf '%s' "$payload" | jq -r '.tool_name // "unknown"')
        tuid=$(printf '%s' "$payload" | jq -r '.tool_use_id // empty')
        # Pair with the most recent pre tool_use in the JSONL when Claude
        # does not echo tool_use_id on the post event. With concurrent
        # tools in flight, the *last* pre line is the right one to match —
        # Claude fires post events in completion order, and we only fall
        # through to this branch when no id was provided.
        if [ -z "$tuid" ] && [ -s "$out" ]; then
            tuid=$(grep '"phase":"pre"' "$out" 2>/dev/null | tail -1 \
                | jq -r '.tool_use_id // empty' 2>/dev/null)
        fi
        if [ -z "$tuid" ]; then
            tuid="$session_id:$seq"
        fi
        # Heuristic: treat absence of tool_response.error / presence of a result as success.
        success=$(printf '%s' "$payload" | jq -c '
            if (.tool_response // .tool_result // null) == null then true
            elif (.tool_response.error? // .tool_result.error? // null) != null then false
            elif (.tool_response.is_error? // false) == true then false
            else true end')
        # output_summary intentionally omitted — see privacy note in header.
        extra=$(jq -nc \
            --argjson tid "$turn" \
            --arg tuid "$tuid" \
            --arg tn "$tool" \
            --argjson succ "$success" \
            '{turn_id: $tid, tool_use_id: $tuid, tool_name: $tn, phase: "post", success: $succ}')
        emit tool_use "$extra"
        ;;

    SessionEnd)
        reason=$(printf '%s' "$payload" | jq -r '.reason // "unknown"')
        exit_reason="task_complete"
        case "$reason" in
            clear|logout|user_exit) exit_reason="user_exit" ;;
            error|crash) exit_reason="error" ;;
            *) exit_reason="task_complete" ;;
        esac
        extra=$(jq -nc \
            --arg er "$exit_reason" \
            --argjson tt "$turn" \
            '{exit_reason: $er, total_turns: $tt}')
        emit session_end "$extra"
        # Lock file is released and removed by the EXIT trap. JSONL stays.
        rm -f "$traj_root/.lock-$session_id" 2>/dev/null || true
        ;;

    *)
        # Unknown event: drop silently. Spec compliance requires no action.
        exit 0
        ;;
esac
