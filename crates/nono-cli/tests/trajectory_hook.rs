//! Integration test for `data/hooks/nono-trajectory.sh`.
//!
//! Drives the dispatcher with a scripted sequence of Claude Code hook
//! payloads and asserts the emitted JSONL matches trajectory-spec v0.1
//! (standard capture level). Skipped when `jq` is not available — the
//! script gates on it and would simply exit 0.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data/hooks/nono-trajectory.sh")
}

/// Resolve jq's containing directory once. Used both to gate the test and to
/// build the subprocess PATH, so detection and execution agree on whether
/// jq is reachable. Without this, on a typical macOS dev machine (Homebrew
/// jq at `/opt/homebrew/bin/jq` or `/usr/local/bin/jq`) the parent-PATH
/// `which jq` returns true while the subprocess's `PATH=/bin:/usr/bin`
/// can't reach jq — the hook silently exits 0 and `read_lines` panics.
///
/// Skips nono mediation shims. When this test runs inside a nono sandbox,
/// the parent PATH starts with `/private/tmp/nono-session-*/shims/`, and
/// `which jq` would otherwise return the shim — which can't operate
/// without `NONO_MEDIATION_SOCKET` set in the (env_clear'd) subprocess.
fn jq_dir() -> Option<PathBuf> {
    which::which_all("jq")
        .ok()?
        .find(|p| {
            let s = p.to_string_lossy();
            !s.contains("nono-session-") && !s.contains("/shims/")
        })
        .and_then(|p| p.parent().map(Path::to_path_buf))
}

fn jq_available() -> bool {
    jq_dir().is_some()
}

/// Build the subprocess PATH so the hook can find jq deterministically,
/// regardless of where it is installed on the host.
fn sandbox_path() -> String {
    match jq_dir() {
        Some(d) => format!("{}:/bin:/usr/bin", d.display()),
        None => "/bin:/usr/bin".to_string(),
    }
}

/// Pipe `payload_json` into the trajectory hook with `HOME` set to `home`
/// and `NONO_CAP_FILE` set (so the gate passes). Fails the test on non-zero exit.
fn feed(home: &PathBuf, payload_json: &str) {
    // Execute via the script's shebang rather than an explicit `bash` to
    // avoid picking up any shim binary a parent nono session may have on PATH.
    let mut child = Command::new(script_path())
        .env_clear()
        .env("HOME", home)
        .env("PATH", sandbox_path())
        .env("NONO_CAP_FILE", "/tmp/fake-nono-cap")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn trajectory hook");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(payload_json.as_bytes())
        .expect("write payload");
    let out = child.wait_with_output().expect("wait on hook");
    assert!(
        out.status.success(),
        "hook exited with status {:?}; stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr),
    );
}

fn read_lines(path: &PathBuf) -> Vec<serde_json::Value> {
    let text = std::fs::read_to_string(path).expect("read trajectory file");
    text.lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("parse jsonl line"))
        .collect()
}

#[test]
fn trajectory_hook_emits_conformant_stream() {
    if !jq_available() {
        eprintln!("skipping: jq not available");
        return;
    }

    let tmp = tempfile::tempdir().expect("tmpdir");
    let home: PathBuf = tmp.path().to_path_buf();
    let session_id = "int-test-1";
    let out = home
        .join(".cache")
        .join("nono-trajectory")
        .join(format!("session-{session_id}.jsonl"));

    let events = [
        r#"{"hook_event_name":"SessionStart","session_id":"int-test-1","model":"claude-sonnet-4-6","cwd":"/tmp","source":"startup"}"#,
        r#"{"hook_event_name":"UserPromptSubmit","session_id":"int-test-1","prompt":"list the repo"}"#,
        r#"{"hook_event_name":"PreToolUse","session_id":"int-test-1","tool_name":"Bash","tool_input":{"command":"ls"},"tool_use_id":"tu_1"}"#,
        r#"{"hook_event_name":"PostToolUse","session_id":"int-test-1","tool_name":"Bash","tool_use_id":"tu_1","tool_response":{"exit_code":0}}"#,
        r#"{"hook_event_name":"UserPromptSubmit","session_id":"int-test-1","prompt":"now rm it"}"#,
        r#"{"hook_event_name":"PreToolUse","session_id":"int-test-1","tool_name":"Bash","tool_input":{"command":"rm -rf /"},"tool_use_id":"tu_2"}"#,
        r#"{"hook_event_name":"PostToolUse","session_id":"int-test-1","tool_name":"Bash","tool_use_id":"tu_2","tool_response":{"exit_code":1,"is_error":true}}"#,
        r#"{"hook_event_name":"SessionEnd","session_id":"int-test-1","reason":"user_exit"}"#,
    ];
    for ev in events {
        feed(&home, ev);
    }

    let lines = read_lines(&out);
    assert_eq!(lines.len(), 8, "expected 8 events, got {}", lines.len());

    // S1 / I1: first event is session_start, has required fields, starts at seq 0.
    let first = &lines[0];
    assert_eq!(first["event_type"], "session_start");
    assert_eq!(first["sequence_number"], 0);
    assert_eq!(first["format_version"], 1);
    assert_eq!(first["session_id"], session_id);
    assert_eq!(first["capture_level"], "standard");
    assert!(
        first["model"]
            .as_str()
            .unwrap_or("")
            .starts_with("nono-sandbox/"),
        "model should be namespaced under nono-sandbox/: {:?}",
        first["model"]
    );

    // I9: sequence_number strictly increasing with no gaps.
    for (i, line) in lines.iter().enumerate() {
        assert_eq!(
            line["sequence_number"].as_u64().expect("sequence_number"),
            i as u64,
            "sequence gap at index {}",
            i
        );
    }

    // session_id present on every event (not just session_start), so
    // downstream log search can filter a single Claude Code session out of
    // the combined stream.
    for line in &lines {
        assert_eq!(
            line["session_id"].as_str().expect("session_id"),
            session_id,
            "every event must carry session_id: {line}",
        );
    }

    // I6: timestamps non-decreasing, RFC 3339 UTC with millisecond precision.
    let mut prev_ts = String::new();
    for line in &lines {
        let ts = line["timestamp"].as_str().expect("timestamp str");
        assert!(ts.ends_with('Z'), "timestamp must be UTC (end Z): {ts}");
        assert!(
            ts.contains('.') && ts.len() >= 23,
            "timestamp must carry ms precision: {ts}",
        );
        assert!(ts.as_bytes() >= prev_ts.as_bytes(), "timestamps regressed");
        prev_ts = ts.to_string();
    }

    // Turn pairing: input_prompt and the following tool_use pair share turn_id.
    let prompts: Vec<&serde_json::Value> = lines
        .iter()
        .filter(|l| l["event_type"] == "input_prompt")
        .collect();
    assert_eq!(prompts.len(), 2, "expected 2 prompts");
    assert_eq!(prompts[0]["turn_id"], 1);
    assert_eq!(prompts[1]["turn_id"], 2);

    let tool_uses: Vec<&serde_json::Value> = lines
        .iter()
        .filter(|l| l["event_type"] == "tool_use")
        .collect();
    assert_eq!(tool_uses.len(), 4, "expected 2 pre+post tool_use pairs");
    assert_eq!(tool_uses[0]["phase"], "pre");
    assert_eq!(tool_uses[1]["phase"], "post");
    assert_eq!(tool_uses[0]["turn_id"], 1);
    assert_eq!(tool_uses[1]["turn_id"], 1);
    assert_eq!(tool_uses[2]["turn_id"], 2);
    assert_eq!(tool_uses[3]["turn_id"], 2);
    // tool_use_id matches across pre/post of the same invocation.
    assert_eq!(tool_uses[0]["tool_use_id"], tool_uses[1]["tool_use_id"]);
    assert_eq!(tool_uses[2]["tool_use_id"], tool_uses[3]["tool_use_id"]);
    // success flag derived correctly.
    assert_eq!(tool_uses[1]["success"], true);
    assert_eq!(tool_uses[3]["success"], false);

    // I11: no `output` key on any tool_use at standard capture level.
    for tu in &tool_uses {
        assert!(
            tu.get("output").is_none(),
            "standard capture must not emit `output`: {tu}",
        );
    }

    // Privacy: input_prompt events must not carry the user's prompt text.
    for p in &prompts {
        assert!(
            p.get("content").is_none(),
            "input_prompt must not carry `content`: {p}",
        );
        assert!(
            p.get("prompt").is_none(),
            "input_prompt must not carry `prompt`: {p}",
        );
    }

    // Privacy: tool_use(post) events must not carry an output_summary field.
    for tu in &tool_uses {
        if tu["phase"] == "post" {
            assert!(
                tu.get("output_summary").is_none(),
                "tool_use(post) must not carry `output_summary`: {tu}",
            );
        }
    }

    // Privacy (end-to-end): the prompt strings fed in must not appear anywhere
    // in the JSONL on disk. Catches accidental leakage via any field.
    let raw = std::fs::read_to_string(&out).expect("read trajectory file");
    for needle in ["list the repo", "now rm it"] {
        assert!(
            !raw.contains(needle),
            "user prompt text {:?} leaked into trajectory file:\n{}",
            needle,
            raw,
        );
    }

    // Last event is session_end and has exit_reason.
    let last = lines.last().expect("non-empty");
    assert_eq!(last["event_type"], "session_end");
    assert_eq!(last["exit_reason"], "user_exit");

    // Regression guard for PR #18 bug: every event had sequence_number=0
    // because the .seq-/.turn-/.pending-tool-<sid> sidecar dotfiles were
    // silently being lost between hook invocations under real Claude Code
    // + nono. The fix derives counters from the JSONL itself, which means
    // the trajectory dir should contain *only* the JSONL — no dotfiles at
    // all. A re-introduction of any sidecar would be visible here.
    let traj_dir = home.join(".cache").join("nono-trajectory");
    let leftovers: Vec<_> = std::fs::read_dir(&traj_dir)
        .expect("read trajectory dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name())
        .filter(|n| {
            let s = n.to_string_lossy();
            !s.starts_with("session-") || !s.ends_with(".jsonl")
        })
        .collect();
    assert!(
        leftovers.is_empty(),
        "trajectory dir must contain only session-*.jsonl after a clean run; \
         dotfile sidecars are a regression to the lost-counter approach: {:?}",
        leftovers,
    );
}

#[test]
fn trajectory_hook_noop_without_nono_env() {
    if !jq_available() {
        eprintln!("skipping: jq not available");
        return;
    }
    let tmp = tempfile::tempdir().expect("tmpdir");
    let home: PathBuf = tmp.path().to_path_buf();

    // Intentionally do NOT set NONO_CAP_FILE. The hook must exit 0 and
    // write nothing, so it is safe to leave registered in Claude Code
    // when the agent is not running under nono.
    let mut child = Command::new(script_path())
        .env_clear()
        .env("HOME", &home)
        .env("PATH", sandbox_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(
            br#"{"hook_event_name":"SessionStart","session_id":"noenv","model":"x","cwd":"/"}"#,
        )
        .expect("write");
    let out = child.wait_with_output().expect("wait");
    assert!(
        out.status.success(),
        "hook should exit 0 when nono inactive"
    );

    let traj_root = home.join(".cache").join("nono-trajectory");
    assert!(
        !traj_root.exists(),
        "hook must not create files when nono inactive"
    );
}

#[test]
fn trajectory_hook_rejects_path_traversal_in_session_id() {
    if !jq_available() {
        eprintln!("skipping: jq not available");
        return;
    }
    let tmp = tempfile::tempdir().expect("tmpdir");
    let home: PathBuf = tmp.path().to_path_buf();

    let mut child = Command::new(script_path())
        .env_clear()
        .env("HOME", &home)
        .env("PATH", sandbox_path())
        .env("NONO_CAP_FILE", "/tmp/fake")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(
            br#"{"hook_event_name":"SessionStart","session_id":"../../etc/passwd","model":"x","cwd":"/"}"#,
        )
        .expect("write");
    let out = child.wait_with_output().expect("wait");
    assert!(out.status.success());

    // Nothing should have been written.
    let traj_root = home.join(".cache").join("nono-trajectory");
    if traj_root.exists() {
        let entries: Vec<_> = std::fs::read_dir(&traj_root)
            .expect("read traj root")
            .collect();
        assert!(
            entries.is_empty(),
            "traversal payload must not produce any file: {:?}",
            entries,
        );
    }
}

/// Drives many concurrent hook invocations against the same session_id and
/// asserts every emitted line has a unique sequence_number with no gaps.
///
/// This exercises the lock-and-counter critical section on a real
/// filesystem under contention. Without the serialization (flock on Linux,
/// mkdir-lock fallback elsewhere) two invocations would race on the
/// read-modify-write of `.seq-<sid>` and either repeat a sequence_number
/// or skip one — both of which violate trajectory-spec I9.
///
/// Without this test, the I9 claim is aspirational: the three sequential
/// tests above only exercise one process at a time.
#[test]
fn trajectory_hook_serializes_sequence_under_concurrency() {
    if !jq_available() {
        eprintln!("skipping: jq not available");
        return;
    }

    let tmp = tempfile::tempdir().expect("tmpdir");
    let home: PathBuf = tmp.path().to_path_buf();
    let session_id = "concur-test-1";
    let out = home
        .join(".cache")
        .join("nono-trajectory")
        .join(format!("session-{session_id}.jsonl"));

    // SessionStart first to establish the file and counter sidecars before
    // the contended phase; this matches how the dispatcher is exercised in
    // practice (one SessionStart, then many tool events).
    feed(
        &home,
        r#"{"hook_event_name":"SessionStart","session_id":"concur-test-1","cwd":"/tmp","source":"startup"}"#,
    );

    // Fan out N concurrent PreToolUse invocations. Each one bumps the
    // sequence_number under lock. With the lock working, every event lands
    // a distinct value; without it, two invocations read the same `seq` and
    // both write `seq + 1`, producing a duplicate.
    const N: usize = 16;
    let mut handles = Vec::with_capacity(N);
    for i in 0..N {
        let home = home.clone();
        handles.push(std::thread::spawn(move || {
            let payload = format!(
                r#"{{"hook_event_name":"PreToolUse","session_id":"concur-test-1","tool_name":"Bash","tool_input":{{"i":{i}}},"tool_use_id":"tu_{i}"}}"#
            );
            feed(&home, &payload);
        }));
    }
    for h in handles {
        h.join().expect("thread join");
    }

    let lines = read_lines(&out);
    assert_eq!(
        lines.len(),
        N + 1,
        "expected {} events on disk (1 SessionStart + {} PreToolUse), got {}",
        N + 1,
        N,
        lines.len()
    );

    // sequence_number must be a permutation of 0..=N with no duplicates and
    // no gaps. Order on disk depends on which thread won the lock each
    // round, so we sort before checking.
    let mut seqs: Vec<u64> = lines
        .iter()
        .map(|l| {
            l["sequence_number"]
                .as_u64()
                .expect("sequence_number is a number")
        })
        .collect();
    seqs.sort_unstable();
    let expected: Vec<u64> = (0..=N as u64).collect();
    assert_eq!(
        seqs, expected,
        "sequence_number must be a contiguous 0..={} permutation under concurrency",
        N
    );
}
