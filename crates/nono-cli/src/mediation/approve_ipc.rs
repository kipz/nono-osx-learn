//! `/approve` IPC: cross-process approval gate for shell-side wrappers.
//!
//! The mediation server's primary socket (`mediation.sock`) is reserved for
//! shim-driven `ShimRequest`/`ShimResponse` traffic, including SCM_RIGHTS
//! transfer of stdio fds. That protocol is too tangled for ad-hoc external
//! callers (e.g. plan 4.3's shell wrappers) that just want to consult the
//! approval gate.
//!
//! This module exposes a sibling Unix socket — `approve.sock`, alongside
//! `mediation.sock` and `control.sock` — that accepts a single
//! length-prefixed JSON request and writes a single length-prefixed JSON
//! response. Plan 4.2 itself does NOT consume this IPC; the in-process
//! `apply` path uses `AllowlistStore` and `ApprovalGate` directly. The
//! endpoint is published as a cross-plan deliverable for plans 4.1 and 4.3.
//!
//! ## Wire format
//!
//! Same framing as `mediation.sock` and `control.sock`:
//!
//! ```text
//!   Request:  u32 big-endian length || JSON payload
//!   Response: u32 big-endian length || JSON payload
//! ```
//!
//! Length-prefixed JSON (rather than line-delimited) is used so the existing
//! `tokio::io::AsyncReadExt::read_u32` / `read_exact` primitives can be
//! reused. All other nono mediation IPC uses the same framing.
//!
//! Request shape:
//!
//! ```json
//! {
//!   "op": "approve",
//!   "session_token": "<NONO_SESSION_TOKEN>",
//!   "key": {
//!     "kind": "argv_shape",
//!     "payload": { "cmd": "security", "argv": ["find-generic-password", "-a", "u"] }
//!   }
//! }
//! ```
//!
//! `key` is a serde-serialized [`AllowlistKey`]. Any of the
//! [`AllowlistKind`](super::allowlist::AllowlistKind) variants is accepted —
//! the dispatcher consults the in-process `AllowlistStore` and
//! `ApprovalGate` exactly as the apply path does.
//!
//! Response shape (one of):
//!
//! ```json
//! { "verdict": "allow_once" }
//! { "verdict": "allow_always" }
//! { "verdict": "deny" }
//! { "error": "unauthenticated" }
//! { "error": "invalid_request" }
//! ```
//!
//! ## Authentication
//!
//! The same `NONO_SESSION_TOKEN` injected into the sandboxed child as the
//! mediation socket gates this endpoint. Validation uses constant-time
//! comparison via `subtle::ConstantTimeEq`, matching `control.rs`. On
//! failure, the dispatcher writes `{"error":"unauthenticated"}` and closes —
//! it does NOT invoke the approval gate or mutate the allowlist.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use nix::libc;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn};

use super::allowlist::{AllowlistKey, AllowlistKind, AllowlistStore};
use super::approval::{ApprovalGate, ApprovalVerdict};

/// Maximum request size accepted on the approve socket. 64 KiB is plenty for
/// any conceivable [`AllowlistKey`] payload and bounds memory allocation
/// before the session token check runs.
const MAX_REQUEST_SIZE: u32 = 64 * 1024;

/// One inbound request to `/approve`.
#[derive(Debug, Deserialize)]
pub struct ApproveRequest {
    /// Operation tag. Currently only `"approve"` is recognised; future
    /// operations (e.g. `"is_approved"` for non-blocking lookup) can be added
    /// without breaking existing callers.
    #[serde(default)]
    pub op: String,
    /// Session authentication token. Must match `NONO_SESSION_TOKEN`.
    pub session_token: String,
    /// The key to consult / approve. Serde-deserialized from the same
    /// tagged-union form used by the on-disk allowlist.
    pub key: AllowlistKey,
}

/// One outbound response from `/approve`.
///
/// Exactly one of `verdict` or `error` is populated; the other is omitted
/// from the wire form via `skip_serializing_if`.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApproveResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<VerdictRepr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Wire representation of [`ApprovalVerdict`].
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum VerdictRepr {
    AllowOnce,
    AllowAlways,
    Deny,
}

impl From<ApprovalVerdict> for VerdictRepr {
    fn from(v: ApprovalVerdict) -> Self {
        match v {
            ApprovalVerdict::AllowOnce => VerdictRepr::AllowOnce,
            ApprovalVerdict::AllowAlways => VerdictRepr::AllowAlways,
            ApprovalVerdict::Deny => VerdictRepr::Deny,
        }
    }
}

impl ApproveResponse {
    fn verdict(v: VerdictRepr) -> Self {
        Self {
            verdict: Some(v),
            error: None,
        }
    }
    fn error(msg: &str) -> Self {
        Self {
            verdict: None,
            error: Some(msg.to_string()),
        }
    }
}

/// Run the `/approve` socket server.
///
/// Binds to `socket_path` and accepts connections indefinitely. Each
/// connection is dispatched to its own `tokio::spawn` task. This function
/// only returns if the listener fails to bind or accept.
pub async fn run(
    socket_path: PathBuf,
    session_token: Arc<str>,
    allowlist: Arc<AllowlistStore>,
    approval: Arc<dyn ApprovalGate + Send + Sync>,
) -> std::io::Result<()> {
    let _ = std::fs::remove_file(&socket_path);

    let listener = bind_socket_owner_only(&socket_path)?;
    debug!("Approve IPC listening on {}", socket_path.display());

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let token = Arc::clone(&session_token);
                let al = Arc::clone(&allowlist);
                let gate = Arc::clone(&approval);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, token, al, gate).await {
                        warn!("approve: connection error: {}", e);
                    }
                });
            }
            Err(e) => return Err(e),
        }
    }
}

/// Handle a single approve connection: read request, dispatch, write response.
pub(crate) async fn handle_connection(
    mut stream: tokio::net::UnixStream,
    session_token: Arc<str>,
    allowlist: Arc<AllowlistStore>,
    approval: Arc<dyn ApprovalGate + Send + Sync>,
) -> std::io::Result<()> {
    let len = stream.read_u32().await?;
    if len > MAX_REQUEST_SIZE {
        warn!(
            "approve: rejected oversized request ({} bytes > {} limit)",
            len, MAX_REQUEST_SIZE
        );
        let resp = ApproveResponse::error("request_too_large");
        write_response(&mut stream, &resp).await?;
        return Ok(());
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;

    let req: ApproveRequest = match serde_json::from_slice(&buf) {
        Ok(r) => r,
        Err(e) => {
            warn!("approve: failed to parse request: {}", e);
            let resp = ApproveResponse::error("invalid_request");
            write_response(&mut stream, &resp).await?;
            return Ok(());
        }
    };

    // Constant-time session-token check. Failure path writes the error and
    // returns BEFORE the gate or allowlist is touched.
    {
        use subtle::ConstantTimeEq;
        let eq: bool = req
            .session_token
            .as_bytes()
            .ct_eq(session_token.as_bytes())
            .into();
        if !eq {
            warn!("approve: rejected connection with invalid session token");
            let resp = ApproveResponse::error("unauthenticated");
            write_response(&mut stream, &resp).await?;
            return Ok(());
        }
    }

    if req.op != "approve" {
        warn!("approve: rejected unknown op '{}'", req.op);
        let resp = ApproveResponse::error("unknown_op");
        write_response(&mut stream, &resp).await?;
        return Ok(());
    }

    let resp = dispatch_approve(req.key, allowlist, approval).await;
    write_response(&mut stream, &resp).await
}

/// Core dispatch: allowlist lookup, then (on miss) approval gate, then
/// (on AllowAlways) record. Mirrors the inline flow in `policy::apply`.
async fn dispatch_approve(
    key: AllowlistKey,
    allowlist: Arc<AllowlistStore>,
    approval: Arc<dyn ApprovalGate + Send + Sync>,
) -> ApproveResponse {
    if allowlist.is_approved(&key) {
        debug!("approve: allowlist hit; returning allow_once");
        return ApproveResponse::verdict(VerdictRepr::AllowOnce);
    }

    let (command, args, reason) = derive_prompt_fields(&key);
    let approval_clone = Arc::clone(&approval);
    let cmd_for_thread = command.clone();
    let args_for_thread = args.clone();
    let reason_for_thread = reason.clone();
    let verdict = tokio::task::spawn_blocking(move || {
        approval_clone.approve_with_save_option(
            &cmd_for_thread,
            &args_for_thread,
            &reason_for_thread,
        )
    })
    .await
    .unwrap_or(ApprovalVerdict::Deny);

    if verdict == ApprovalVerdict::AllowAlways {
        if let Err(e) = allowlist.record(&key) {
            // Mirror the warn-and-continue pattern in `policy::apply`: a
            // persistence failure must not turn a user-visible "yes" into a
            // surprise deny. The caller will simply re-prompt next time.
            warn!("approve: allowlist record failed for '{}': {}", command, e);
        }
    }

    ApproveResponse::verdict(verdict.into())
}

/// Pull `(command, args, reason)` out of an [`AllowlistKey`] for the
/// approval prompt.
///
/// The shapes recognised here follow the payload conventions documented on
/// [`AllowlistKind`](super::allowlist::AllowlistKind). Unknown or malformed
/// payloads degrade to safe placeholders rather than failing — the user
/// still sees the command/key being asked about, just with less polish.
fn derive_prompt_fields(key: &AllowlistKey) -> (String, Vec<String>, String) {
    let cmd = key
        .payload
        .get("cmd")
        .and_then(|v| v.as_str())
        .unwrap_or("(unknown)")
        .to_string();
    let args = key
        .payload
        .get("argv")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let reason = match key.kind {
        AllowlistKind::ArgvShape => "argv shape mismatch".to_string(),
        AllowlistKind::CallerPolicy => "caller policy violation".to_string(),
        AllowlistKind::ScanConfig => "config scan flagged value".to_string(),
        AllowlistKind::ScanEnv => "env scan flagged value".to_string(),
        AllowlistKind::ScanSshOpt => "ssh option scan flagged value".to_string(),
        AllowlistKind::ScanSshIdentity => "ssh identity scan flagged value".to_string(),
    };
    (cmd, args, reason)
}

/// Write a length-prefixed JSON response.
async fn write_response(
    stream: &mut tokio::net::UnixStream,
    resp: &ApproveResponse,
) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(resp).map_err(std::io::Error::other)?;
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

/// Bind a Unix socket with restrictive permissions from creation time
/// (0o600). Same pattern as `server::bind_socket_owner_only` and
/// `control::bind_socket_owner_only` — kept local so the module is
/// self-contained.
fn bind_socket_owner_only(path: &Path) -> std::io::Result<tokio::net::UnixListener> {
    let lock = umask_guard();
    let _guard = lock
        .lock()
        .map_err(|_| std::io::Error::other("approve: failed to acquire umask lock"))?;

    let old_umask = unsafe { libc::umask(0o077) };
    let std_listener = std::os::unix::net::UnixListener::bind(path).map_err(|e| {
        unsafe { libc::umask(old_umask) };
        e
    });
    unsafe { libc::umask(old_umask) };

    let std_listener = std_listener?;
    std_listener.set_nonblocking(true)?;
    tokio::net::UnixListener::from_std(std_listener)
}

fn umask_guard() -> &'static Mutex<()> {
    static UMASK_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    UMASK_LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tempfile::tempdir;

    /// Test gate that panics if invoked. Lets us assert the dispatcher
    /// never reaches the gate (e.g. on auth failure or allowlist hit).
    struct NeverApprovalGate;

    impl ApprovalGate for NeverApprovalGate {
        fn approve(&self, _command: &str, _args: &[String]) -> bool {
            panic!("NeverApprovalGate::approve was invoked but should not have been");
        }
        fn approve_with_save_option(
            &self,
            _command: &str,
            _args: &[String],
            _reason: &str,
        ) -> ApprovalVerdict {
            panic!("NeverApprovalGate::approve_with_save_option was invoked but should not have been");
        }
    }

    /// Test gate that always returns AllowAlways and counts invocations.
    struct AlwaysAllowAlwaysCounting {
        count: AtomicU32,
    }

    impl ApprovalGate for AlwaysAllowAlwaysCounting {
        fn approve(&self, _command: &str, _args: &[String]) -> bool {
            self.count.fetch_add(1, Ordering::SeqCst);
            true
        }
        fn approve_with_save_option(
            &self,
            _command: &str,
            _args: &[String],
            _reason: &str,
        ) -> ApprovalVerdict {
            self.count.fetch_add(1, Ordering::SeqCst);
            ApprovalVerdict::AllowAlways
        }
    }

    fn argv_key(cmd: &str, argv: &[&str]) -> AllowlistKey {
        AllowlistKey {
            kind: AllowlistKind::ArgvShape,
            payload: json!({
                "cmd": cmd,
                "argv": argv,
            }),
        }
    }

    /// Connect a (client, server) UnixStream pair and run `handle_connection`
    /// against the server end. Returns the server task handle so the test
    /// can join it and detect panics from the never-gate.
    async fn spawn_server_end(
        server: tokio::net::UnixStream,
        token: Arc<str>,
        allowlist: Arc<AllowlistStore>,
        approval: Arc<dyn ApprovalGate + Send + Sync>,
    ) -> tokio::task::JoinHandle<std::io::Result<()>> {
        tokio::spawn(async move {
            handle_connection(server, token, allowlist, approval).await
        })
    }

    /// Send a JSON value as a length-prefixed payload and read back the
    /// length-prefixed JSON response.
    async fn round_trip(
        client: &mut tokio::net::UnixStream,
        req: &serde_json::Value,
    ) -> ApproveResponse {
        let bytes = serde_json::to_vec(req).unwrap();
        client.write_u32(bytes.len() as u32).await.unwrap();
        client.write_all(&bytes).await.unwrap();
        client.flush().await.unwrap();

        let len = client.read_u32().await.unwrap();
        let mut buf = vec![0u8; len as usize];
        client.read_exact(&mut buf).await.unwrap();
        serde_json::from_slice(&buf).unwrap()
    }

    #[tokio::test]
    async fn unauthenticated_request_returns_auth_error_no_gate_invocation() {
        let dir = tempdir().unwrap();
        let store = Arc::new(AllowlistStore::open_at(dir.path().join("al.json")).unwrap());
        let token: Arc<str> = Arc::from("the-real-token");
        let gate: Arc<dyn ApprovalGate + Send + Sync> = Arc::new(NeverApprovalGate);

        let (mut client, server) = tokio::net::UnixStream::pair().unwrap();
        let server_task = spawn_server_end(
            server,
            Arc::clone(&token),
            Arc::clone(&store),
            Arc::clone(&gate),
        )
        .await;

        let req = json!({
            "op": "approve",
            "session_token": "WRONG-TOKEN",
            "key": {
                "kind": "argv_shape",
                "payload": { "cmd": "security", "argv": ["find-generic-password"] }
            }
        });
        let resp = round_trip(&mut client, &req).await;

        assert_eq!(
            resp,
            ApproveResponse::error("unauthenticated"),
            "wrong session token must yield unauthenticated, not allow/deny"
        );
        // If NeverApprovalGate had been hit, the spawn_blocking task would
        // have panicked — but more importantly, the server task itself
        // wouldn't reach the gate. Joining it must succeed cleanly.
        server_task.await.unwrap().unwrap();

        // The allowlist must remain untouched on failed auth.
        assert!(!store.is_approved(&argv_key("security", &["find-generic-password"])));
    }

    #[tokio::test]
    async fn allowlisted_key_returns_allow_once_without_invoking_gate() {
        let dir = tempdir().unwrap();
        let store = Arc::new(AllowlistStore::open_at(dir.path().join("al.json")).unwrap());
        let key = argv_key("security", &["find-generic-password", "-a", "u"]);
        store.record(&key).unwrap();

        let token: Arc<str> = Arc::from("tok");
        let gate: Arc<dyn ApprovalGate + Send + Sync> = Arc::new(NeverApprovalGate);

        let (mut client, server) = tokio::net::UnixStream::pair().unwrap();
        let server_task = spawn_server_end(
            server,
            Arc::clone(&token),
            Arc::clone(&store),
            Arc::clone(&gate),
        )
        .await;

        let req = json!({
            "op": "approve",
            "session_token": "tok",
            "key": {
                "kind": "argv_shape",
                "payload": { "cmd": "security", "argv": ["find-generic-password", "-a", "u"] }
            }
        });
        let resp = round_trip(&mut client, &req).await;

        assert_eq!(
            resp,
            ApproveResponse::verdict(VerdictRepr::AllowOnce),
            "allowlist hit must short-circuit to allow_once without prompting"
        );
        // NeverApprovalGate must not have been touched: server task ends cleanly.
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn always_allow_always_persists_then_subsequent_request_hits_allowlist() {
        let dir = tempdir().unwrap();
        let store = Arc::new(AllowlistStore::open_at(dir.path().join("al.json")).unwrap());
        let token: Arc<str> = Arc::from("tok");
        let counting = Arc::new(AlwaysAllowAlwaysCounting {
            count: AtomicU32::new(0),
        });
        let gate: Arc<dyn ApprovalGate + Send + Sync> = counting.clone();

        // First call: miss -> gate fires -> AllowAlways -> recorded.
        let (mut client1, server1) = tokio::net::UnixStream::pair().unwrap();
        let task1 = spawn_server_end(
            server1,
            Arc::clone(&token),
            Arc::clone(&store),
            Arc::clone(&gate),
        )
        .await;
        let key_json = json!({
            "kind": "argv_shape",
            "payload": { "cmd": "security", "argv": ["find-generic-password", "-a", "u"] }
        });
        let req1 = json!({
            "op": "approve",
            "session_token": "tok",
            "key": key_json,
        });
        let resp1 = round_trip(&mut client1, &req1).await;
        assert_eq!(
            resp1,
            ApproveResponse::verdict(VerdictRepr::AllowAlways),
            "first call must surface AllowAlways from the gate"
        );
        task1.await.unwrap().unwrap();
        assert_eq!(
            counting.count.load(Ordering::SeqCst),
            1,
            "gate must have fired exactly once on first call"
        );
        // The store must now contain the key.
        let key = AllowlistKey {
            kind: AllowlistKind::ArgvShape,
            payload: key_json.get("payload").unwrap().clone(),
        };
        assert!(
            store.is_approved(&key),
            "allowlist must have recorded the AllowAlways verdict"
        );

        // Second call: same key, switch to NeverApprovalGate. The
        // dispatcher must serve this from the allowlist without invoking
        // the gate.
        let never: Arc<dyn ApprovalGate + Send + Sync> = Arc::new(NeverApprovalGate);
        let (mut client2, server2) = tokio::net::UnixStream::pair().unwrap();
        let task2 = spawn_server_end(
            server2,
            Arc::clone(&token),
            Arc::clone(&store),
            Arc::clone(&never),
        )
        .await;
        let req2 = json!({
            "op": "approve",
            "session_token": "tok",
            "key": key_json,
        });
        let resp2 = round_trip(&mut client2, &req2).await;
        assert_eq!(
            resp2,
            ApproveResponse::verdict(VerdictRepr::AllowOnce),
            "second call must hit the allowlist and return allow_once"
        );
        task2.await.unwrap().unwrap();
    }
}
