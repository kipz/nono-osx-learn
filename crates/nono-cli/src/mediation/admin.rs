//! Privilege mode state for the mediation server.
//!
//! Privilege mode is a per-session, time-limited override that modifies
//! mediation policy. There are three modes:
//!
//! - **None**: Normal policy enforcement (default).
//! - **Group**: A named permission group is active, allowing specific
//!   commands/subcommands defined by the group's rules.
//! - **Yolo**: Full bypass of all mediation policy (admin mode).
//!
//! State is shared via a `tokio::sync::watch` channel. The control socket
//! server is the sole writer; all `handle_connection` tasks subscribe.

use std::sync::Arc;
use std::time::Instant;
use tokio::sync::watch;
use tracing::warn;

/// The current privilege escalation mode for this session.
#[derive(Clone, Debug)]
pub enum PrivilegeMode {
    /// Normal mediation policy applies.
    None,
    /// A named permission group is active. Commands matching the group's
    /// allow rules bypass intercept; all others follow normal policy.
    Group {
        name: String,
        expires_at: Option<Instant>,
        granted_by: String,
    },
    /// Full admin bypass. All commands pass through without any mediation.
    Yolo {
        expires_at: Instant,
        granted_by: String,
    },
}

impl PrivilegeMode {
    /// Returns true if any privilege escalation is active and not expired.
    pub fn is_active(&self) -> bool {
        match self {
            Self::None => false,
            Self::Group { expires_at, .. } => expires_at.map_or(true, |exp| Instant::now() < exp),
            Self::Yolo { expires_at, .. } => Instant::now() < *expires_at,
        }
    }

    /// Returns true if YOLO (full admin bypass) mode is active.
    pub fn is_yolo(&self) -> bool {
        matches!(self, Self::Yolo { expires_at, .. } if Instant::now() < *expires_at)
    }

    /// Returns the active group name, if a group is currently active.
    pub fn active_group(&self) -> Option<&str> {
        match self {
            Self::Group {
                name, expires_at, ..
            } => {
                let active = expires_at.map_or(true, |exp| Instant::now() < exp);
                if active {
                    Some(name.as_str())
                } else {
                    Option::None
                }
            }
            _ => Option::None,
        }
    }
}

/// Shared privilege mode state for a session.
#[derive(Clone)]
pub struct AdminState {
    tx: Arc<watch::Sender<PrivilegeMode>>,
}

impl AdminState {
    /// Create a new `AdminState` with privilege mode set to None.
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(PrivilegeMode::None);
        Self { tx: Arc::new(tx) }
    }

    /// Subscribe to privilege mode changes (for mediation server watch tasks).
    pub fn subscribe(&self) -> watch::Receiver<PrivilegeMode> {
        self.tx.subscribe()
    }

    /// Read the current privilege mode without creating a receiver.
    pub fn current(&self) -> PrivilegeMode {
        self.tx.borrow().clone()
    }

    /// Update privilege mode.
    pub fn set(&self, mode: PrivilegeMode) {
        self.tx.send_replace(mode);
    }
}

/// Append an event to the session's admin audit log.
///
/// The file is append-only JSONL. Errors are logged at warn level (audit
/// failure must not block the operation).
pub fn write_admin_audit(session_dir: &std::path::Path, event: &serde_json::Value) {
    use std::io::Write;

    let path = session_dir.join("admin_audit.jsonl");
    let line = match serde_json::to_string(event) {
        Ok(s) => s,
        Err(e) => {
            warn!("admin audit: failed to serialize event: {}", e);
            return;
        }
    };

    let mut file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(f) => f,
        Err(e) => {
            warn!("admin audit: failed to open {}: {}", path.display(), e);
            return;
        }
    };

    if let Err(e) = writeln!(file, "{}", line) {
        warn!("admin audit: failed to write to {}: {}", path.display(), e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privilege_mode_none_is_not_active() {
        let mode = PrivilegeMode::None;
        assert!(!mode.is_active());
        assert!(!mode.is_yolo());
        assert!(mode.active_group().is_none());
    }

    #[test]
    fn test_privilege_mode_yolo_active() {
        let mode = PrivilegeMode::Yolo {
            expires_at: Instant::now() + std::time::Duration::from_secs(60),
            granted_by: "test".to_string(),
        };
        assert!(mode.is_active());
        assert!(mode.is_yolo());
        assert!(mode.active_group().is_none());
    }

    #[test]
    fn test_privilege_mode_yolo_expired() {
        let mode = PrivilegeMode::Yolo {
            expires_at: Instant::now() - std::time::Duration::from_secs(1),
            granted_by: "test".to_string(),
        };
        assert!(!mode.is_active());
        assert!(!mode.is_yolo());
    }

    #[test]
    fn test_privilege_mode_group_with_expiry() {
        let mode = PrivilegeMode::Group {
            name: "git_read".to_string(),
            expires_at: Some(Instant::now() + std::time::Duration::from_secs(60)),
            granted_by: "test".to_string(),
        };
        assert!(mode.is_active());
        assert!(!mode.is_yolo());
        assert_eq!(mode.active_group(), Some("git_read"));
    }

    #[test]
    fn test_privilege_mode_group_no_expiry() {
        let mode = PrivilegeMode::Group {
            name: "deploy".to_string(),
            expires_at: None,
            granted_by: "test".to_string(),
        };
        assert!(mode.is_active());
        assert_eq!(mode.active_group(), Some("deploy"));
    }

    #[test]
    fn test_privilege_mode_group_expired() {
        let mode = PrivilegeMode::Group {
            name: "deploy".to_string(),
            expires_at: Some(Instant::now() - std::time::Duration::from_secs(1)),
            granted_by: "test".to_string(),
        };
        assert!(!mode.is_active());
        assert!(mode.active_group().is_none());
    }

    #[test]
    fn test_admin_state_transitions() {
        let state = AdminState::new();
        assert!(!state.current().is_active());

        state.set(PrivilegeMode::Group {
            name: "test".to_string(),
            expires_at: Some(Instant::now() + std::time::Duration::from_secs(60)),
            granted_by: "unit_test".to_string(),
        });
        assert!(state.current().is_active());
        assert_eq!(state.current().active_group(), Some("test"));

        state.set(PrivilegeMode::None);
        assert!(!state.current().is_active());
    }
}
