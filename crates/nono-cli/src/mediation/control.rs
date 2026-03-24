//! Control socket server for privilege mode.
//!
//! A second Unix socket (`control.sock`) in the session directory, alongside
//! `mediation.sock`. The control socket allows privileged processes (the native
//! menu bar app or `nono admin` CLI) to enable/disable privilege modes.
//!
//! Authentication uses a separate `control_token` (256-bit random, hex-encoded)
//! that is written only to `session.json` (mode 600) and never passed to the
//! sandboxed child. This is distinct from the mediation `session_token` which
//! lives in the child's environment.
//!
//! Protocol (same framing as mediation socket):
//!   Request:  u32 big-endian length || JSON payload
//!   Response: u32 big-endian length || JSON payload

use super::admin::{write_admin_audit, AdminState, PrivilegeMode};
use super::MediationGroup;
use nix::libc;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn};

/// Generate a 256-bit random token, hex-encoded.
pub fn generate_token() -> String {
    use rand::RngExt;
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

/// A request to the control socket.
#[derive(Debug, Deserialize)]
pub struct ControlRequest {
    pub token: String,
    pub action: ControlAction,
    /// Seconds for privilege mode to be active (used by `enable` only).
    #[serde(default = "default_duration_secs")]
    pub duration_secs: u64,
    /// Audit label for who granted/revoked access (e.g. "TouchID", "CLI").
    #[serde(default)]
    pub granted_by: String,
    /// Optional group name. When set with `enable`, activates a specific group
    /// instead of YOLO mode. When absent, `enable` activates YOLO mode.
    #[serde(default)]
    pub group: Option<String>,
}

fn default_duration_secs() -> u64 {
    600
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlAction {
    Enable,
    Disable,
    Status,
}

/// Summary of a named permission group for the status response.
#[derive(Debug, Serialize)]
pub struct GroupSummary {
    pub name: String,
    pub description: String,
    pub requires_auth: bool,
    pub duration_secs: u64,
    pub default: bool,
}

/// A response from the control socket.
#[derive(Debug, Serialize)]
pub struct ControlResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub granted_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<GroupSummary>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ControlResponse {
    fn ok_status(status: &str) -> Self {
        Self {
            ok: true,
            status: Some(status.to_string()),
            expires_at_unix: None,
            granted_by: None,
            active_group: None,
            groups: None,
            error: None,
        }
    }

    fn err(msg: &str) -> Self {
        Self {
            ok: false,
            status: None,
            expires_at_unix: None,
            granted_by: None,
            active_group: None,
            groups: None,
            error: Some(msg.to_string()),
        }
    }
}

const MAX_REQUEST_SIZE: u32 = 64 * 1024;

/// Run the control socket server.
///
/// Binds to `control_socket_path` and handles enable/disable/status requests.
/// Validates `control_token` with constant-time comparison before dispatching.
pub async fn run_control_server(
    control_socket_path: PathBuf,
    control_token: String,
    admin_state: AdminState,
    session_dir: PathBuf,
    groups: Arc<indexmap::IndexMap<String, MediationGroup>>,
) -> std::io::Result<()> {
    let _ = std::fs::remove_file(&control_socket_path);

    let listener = bind_socket_owner_only(&control_socket_path)?;
    debug!(
        "Control server listening on {}",
        control_socket_path.display()
    );

    let token = Arc::new(control_token);
    let state = Arc::new(admin_state);
    let sdir = Arc::new(session_dir);

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let t = Arc::clone(&token);
                let s = Arc::clone(&state);
                let sd = Arc::clone(&sdir);
                let g = Arc::clone(&groups);
                tokio::spawn(async move {
                    if let Err(e) = handle_control_connection(stream, &t, &s, &sd, &g).await {
                        warn!("control: connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
}

async fn handle_control_connection(
    mut stream: tokio::net::UnixStream,
    control_token: &str,
    admin_state: &AdminState,
    session_dir: &Path,
    groups: &indexmap::IndexMap<String, MediationGroup>,
) -> std::io::Result<()> {
    let len = stream.read_u32().await?;
    if len > MAX_REQUEST_SIZE {
        warn!(
            "control: rejected oversized request ({} bytes > {} limit)",
            len, MAX_REQUEST_SIZE
        );
        return Ok(());
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;

    let req: ControlRequest = match serde_json::from_slice(&buf) {
        Ok(r) => r,
        Err(e) => {
            warn!("control: failed to parse request: {}", e);
            let resp = ControlResponse::err("invalid request");
            write_control_response(&mut stream, &resp).await?;
            return Ok(());
        }
    };

    // Validate token with constant-time comparison
    {
        use subtle::ConstantTimeEq;
        let token_eq: bool = req.token.as_bytes().ct_eq(control_token.as_bytes()).into();
        if !token_eq {
            warn!("control: rejected connection with invalid control token");
            let resp = ControlResponse::err("unauthorized");
            write_control_response(&mut stream, &resp).await?;
            return Ok(());
        }
    }

    let resp = dispatch(req, admin_state, session_dir, groups).await;
    write_control_response(&mut stream, &resp).await
}

fn build_group_summaries(groups: &indexmap::IndexMap<String, MediationGroup>) -> Vec<GroupSummary> {
    groups
        .iter()
        .map(|(name, g)| GroupSummary {
            name: name.clone(),
            description: g.description.clone(),
            requires_auth: g.requires_auth,
            duration_secs: g.duration_secs,
            default: g.default,
        })
        .collect()
}

async fn dispatch(
    req: ControlRequest,
    admin_state: &AdminState,
    session_dir: &Path,
    groups: &indexmap::IndexMap<String, MediationGroup>,
) -> ControlResponse {
    match req.action {
        ControlAction::Status => {
            let current = admin_state.current();
            let group_summaries = build_group_summaries(groups);
            match &current {
                PrivilegeMode::None => {
                    let mut resp = ControlResponse::ok_status("disabled");
                    resp.groups = Some(group_summaries);
                    resp
                }
                PrivilegeMode::Group {
                    name,
                    expires_at,
                    granted_by,
                } => {
                    let active = match expires_at {
                        Some(exp) => Instant::now() < *exp,
                        None => true,
                    };
                    if active {
                        let expires_unix = expires_at.map(|exp| {
                            let secs_remaining = exp
                                .checked_duration_since(Instant::now())
                                .unwrap_or(Duration::ZERO)
                                .as_secs();
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs() + secs_remaining)
                                .unwrap_or(0)
                        });
                        ControlResponse {
                            ok: true,
                            status: Some("group".to_string()),
                            expires_at_unix: expires_unix,
                            granted_by: Some(granted_by.clone()),
                            active_group: Some(name.clone()),
                            groups: Some(group_summaries),
                            error: None,
                        }
                    } else {
                        let mut resp = ControlResponse::ok_status("disabled");
                        resp.groups = Some(group_summaries);
                        resp
                    }
                }
                PrivilegeMode::Yolo {
                    expires_at,
                    granted_by,
                } => {
                    if Instant::now() < *expires_at {
                        let secs_remaining = expires_at
                            .checked_duration_since(Instant::now())
                            .unwrap_or(Duration::ZERO)
                            .as_secs();
                        let expires_unix = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs() + secs_remaining)
                            .unwrap_or(0);
                        ControlResponse {
                            ok: true,
                            status: Some("yolo".to_string()),
                            expires_at_unix: Some(expires_unix),
                            granted_by: Some(granted_by.clone()),
                            active_group: None,
                            groups: Some(group_summaries),
                            error: None,
                        }
                    } else {
                        let mut resp = ControlResponse::ok_status("disabled");
                        resp.groups = Some(group_summaries);
                        resp
                    }
                }
            }
        }
        ControlAction::Enable => {
            if let Some(ref group_name) = req.group {
                // Enable a specific permission group
                let Some(group_def) = groups.get(group_name) else {
                    return ControlResponse::err(&format!("unknown group: {}", group_name));
                };

                let duration_secs = if group_def.duration_secs > 0 {
                    group_def.duration_secs
                } else if req.duration_secs > 0 {
                    req.duration_secs
                } else {
                    0
                };

                let expires_at = if duration_secs > 0 {
                    Some(Instant::now() + Duration::from_secs(duration_secs))
                } else {
                    None
                };

                let expires_unix = if duration_secs > 0 {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() + duration_secs)
                        .ok()
                } else {
                    None
                };

                let granted_by = req.granted_by.clone();
                let pid = std::process::id();
                warn!(
                    "group '{}' ENABLED granted_by=\"{}\" duration_secs={} session_pid={}",
                    group_name, granted_by, duration_secs, pid
                );

                write_admin_audit(
                    session_dir,
                    &serde_json::json!({
                        "event": "group_enabled",
                        "group": group_name,
                        "granted_by": &granted_by,
                        "expires_at_unix": expires_unix,
                        "at": chrono::Utc::now().to_rfc3339(),
                    }),
                );

                admin_state.set(PrivilegeMode::Group {
                    name: group_name.clone(),
                    expires_at,
                    granted_by: granted_by.clone(),
                });

                // Spawn expiry task if duration is set
                if let Some(exp) = expires_at {
                    let dur = Duration::from_secs(duration_secs);
                    let state_clone = admin_state.clone();
                    let sdir = session_dir.to_path_buf();
                    let gn = group_name.clone();
                    let gb = granted_by.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(dur).await;
                        let current = state_clone.current();
                        if current.active_group() == Some(gn.as_str()) {
                            warn!("group '{}' EXPIRED session_pid={}", gn, pid);
                            write_admin_audit(
                                &sdir,
                                &serde_json::json!({
                                    "event": "group_expired",
                                    "group": &gn,
                                    "granted_by": &gb,
                                    "at": chrono::Utc::now().to_rfc3339(),
                                }),
                            );
                            state_clone.set(PrivilegeMode::None);
                        }
                    });
                    let _ = exp; // suppress unused warning
                }

                ControlResponse {
                    ok: true,
                    status: Some("group".to_string()),
                    expires_at_unix: expires_unix,
                    granted_by: Some(granted_by),
                    active_group: Some(group_name.clone()),
                    groups: None,
                    error: None,
                }
            } else {
                // Enable YOLO mode (full admin bypass)
                let duration = Duration::from_secs(req.duration_secs);
                let expires_at = Instant::now() + duration;
                let expires_unix = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() + req.duration_secs)
                    .unwrap_or(0);

                let granted_by = req.granted_by.clone();
                let pid = std::process::id();
                warn!(
                    "YOLO mode ENABLED granted_by=\"{}\" duration_secs={} session_pid={}",
                    granted_by, req.duration_secs, pid
                );

                write_admin_audit(
                    session_dir,
                    &serde_json::json!({
                        "event": "yolo_enabled",
                        "granted_by": &granted_by,
                        "expires_at_unix": expires_unix,
                        "at": chrono::Utc::now().to_rfc3339(),
                    }),
                );

                admin_state.set(PrivilegeMode::Yolo {
                    expires_at,
                    granted_by: granted_by.clone(),
                });

                // Spawn expiry task
                let state_clone = admin_state.clone();
                let sdir = session_dir.to_path_buf();
                let gb = granted_by.clone();
                let expiry_groups = groups.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(duration).await;
                    let current = state_clone.current();
                    if current.is_yolo() {
                        warn!("YOLO mode EXPIRED session_pid={}", pid);
                        write_admin_audit(
                            &sdir,
                            &serde_json::json!({
                                "event": "yolo_expired",
                                "granted_by": &gb,
                                "at": chrono::Utc::now().to_rfc3339(),
                            }),
                        );
                        // Fall back to default group if one exists
                        if let Some((name, group)) = expiry_groups.iter().find(|(_, g)| g.default) {
                            let exp = if group.duration_secs > 0 {
                                Some(Instant::now() + Duration::from_secs(group.duration_secs))
                            } else {
                                None
                            };
                            state_clone.set(PrivilegeMode::Group {
                                name: name.clone(),
                                expires_at: exp,
                                granted_by: "default".to_string(),
                            });
                        } else {
                            state_clone.set(PrivilegeMode::None);
                        }
                    }
                });

                ControlResponse {
                    ok: true,
                    status: Some("yolo".to_string()),
                    expires_at_unix: Some(expires_unix),
                    granted_by: Some(granted_by),
                    active_group: None,
                    groups: None,
                    error: None,
                }
            }
        }
        ControlAction::Disable => {
            let current = admin_state.current();
            if !current.is_active() {
                return ControlResponse::err("already disabled");
            }

            let granted_by = if req.granted_by.is_empty() {
                "unknown".to_string()
            } else {
                req.granted_by.clone()
            };
            let pid = std::process::id();

            let event_name = if current.is_yolo() {
                "yolo_disabled"
            } else {
                "group_disabled"
            };

            let mut audit = serde_json::json!({
                "event": event_name,
                "granted_by": &granted_by,
                "at": chrono::Utc::now().to_rfc3339(),
            });
            if let Some(group) = current.active_group() {
                audit["group"] = serde_json::json!(group);
            }

            warn!(
                "privilege mode DISABLED granted_by=\"{}\" session_pid={}",
                granted_by, pid
            );

            write_admin_audit(session_dir, &audit);

            // If there's a default group, fall back to it instead of None.
            if let Some((name, group)) = groups.iter().find(|(_, g)| g.default) {
                let expires_at = if group.duration_secs > 0 {
                    Some(Instant::now() + Duration::from_secs(group.duration_secs))
                } else {
                    None
                };
                admin_state.set(PrivilegeMode::Group {
                    name: name.clone(),
                    expires_at,
                    granted_by: "default".to_string(),
                });
                debug!("fell back to default group '{}'", name);
                ControlResponse {
                    ok: true,
                    status: Some("group".to_string()),
                    expires_at_unix: None,
                    granted_by: Some("default".to_string()),
                    active_group: Some(name.clone()),
                    groups: None,
                    error: None,
                }
            } else {
                admin_state.set(PrivilegeMode::None);
                ControlResponse::ok_status("disabled")
            }
        }
    }
}

async fn write_control_response(
    stream: &mut tokio::net::UnixStream,
    resp: &ControlResponse,
) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(resp).map_err(std::io::Error::other)?;
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

fn bind_socket_owner_only(path: &Path) -> std::io::Result<tokio::net::UnixListener> {
    let lock = umask_guard();
    let _guard = lock.lock().map_err(|_| {
        std::io::Error::other("control: failed to acquire umask synchronization lock")
    })?;

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

    #[test]
    fn test_control_request_with_group_deserializes() {
        let json = r#"{
            "token": "abc123",
            "action": "enable",
            "group": "git_read",
            "granted_by": "TouchID"
        }"#;
        let req: ControlRequest = serde_json::from_str(json).expect("deserialize");
        assert_eq!(req.group, Some("git_read".to_string()));
        assert_eq!(req.duration_secs, 600); // default
    }

    #[test]
    fn test_control_request_without_group_deserializes() {
        let json = r#"{
            "token": "abc123",
            "action": "enable",
            "duration_secs": 300,
            "granted_by": "CLI"
        }"#;
        let req: ControlRequest = serde_json::from_str(json).expect("deserialize");
        assert!(req.group.is_none());
        assert_eq!(req.duration_secs, 300);
    }

    #[test]
    fn test_control_response_serializes_with_groups() {
        let resp = ControlResponse {
            ok: true,
            status: Some("group".to_string()),
            expires_at_unix: Some(1000),
            granted_by: Some("test".to_string()),
            active_group: Some("deploy".to_string()),
            groups: Some(vec![GroupSummary {
                name: "deploy".to_string(),
                description: "Deploy ops".to_string(),
                requires_auth: true,
                duration_secs: 600,
                default: false,
            }]),
            error: None,
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        assert!(json.contains("active_group"));
        assert!(json.contains("deploy"));
    }

    #[test]
    fn test_group_summaries_from_config() {
        let mut groups = indexmap::IndexMap::new();
        groups.insert(
            "git_read".to_string(),
            MediationGroup {
                description: "Git read ops".to_string(),
                requires_auth: false,
                duration_secs: 0,
                default: false,
                allow: vec![],
            },
        );
        groups.insert(
            "deploy".to_string(),
            MediationGroup {
                description: "Deploy".to_string(),
                requires_auth: true,
                duration_secs: 600,
                default: false,
                allow: vec![],
            },
        );
        let summaries = build_group_summaries(&groups);
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].name, "git_read");
        assert!(summaries[1].requires_auth);
    }
}
