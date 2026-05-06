//! Audit logging for proxy requests.
//!
//! Logs all proxy requests with structured fields via `tracing`.
//! Sensitive data (authorization headers, tokens, request bodies)
//! is never included in audit logs.

use nono::undo::{NetworkAuditDecision, NetworkAuditEvent, NetworkAuditMode};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// Maximum number of in-memory network audit events kept per proxy session.
const MAX_AUDIT_EVENTS: usize = 4096;

/// Shared in-memory sink for network audit events.
pub type SharedAuditLog = Arc<Mutex<Vec<NetworkAuditEvent>>>;

/// Proxy mode for audit logging.
#[derive(Debug, Clone, Copy)]
pub enum ProxyMode {
    /// CONNECT tunnel (host filtering only)
    Connect,
    /// Reverse proxy (credential injection)
    Reverse,
    /// External proxy passthrough (enterprise)
    External,
}

impl std::fmt::Display for ProxyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyMode::Connect => write!(f, "connect"),
            ProxyMode::Reverse => write!(f, "reverse"),
            ProxyMode::External => write!(f, "external"),
        }
    }
}

/// Create a shared in-memory audit log.
#[must_use]
pub fn new_audit_log() -> SharedAuditLog {
    Arc::new(Mutex::new(Vec::new()))
}

/// Drain all network audit events collected so far.
#[must_use]
pub fn drain_audit_events(audit_log: &SharedAuditLog) -> Vec<NetworkAuditEvent> {
    match audit_log.lock() {
        Ok(mut events) => events.drain(..).collect(),
        Err(e) => {
            warn!(
                "Network audit log mutex poisoned while draining events: {}",
                e
            );
            Vec::new()
        }
    }
}

fn now_unix_millis() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            let millis = duration.as_millis();
            if millis > u128::from(u64::MAX) {
                warn!("System clock millis exceeded u64::MAX; clamping audit timestamp");
                u64::MAX
            } else {
                millis as u64
            }
        }
        Err(e) => {
            warn!(
                "System clock before UNIX_EPOCH while generating audit timestamp: {}",
                e
            );
            0
        }
    }
}

fn map_mode(mode: ProxyMode) -> NetworkAuditMode {
    match mode {
        ProxyMode::Connect => NetworkAuditMode::Connect,
        ProxyMode::Reverse => NetworkAuditMode::Reverse,
        ProxyMode::External => NetworkAuditMode::External,
    }
}

fn push_event(audit_log: Option<&SharedAuditLog>, event: NetworkAuditEvent) {
    let Some(audit_log) = audit_log else {
        return;
    };

    match audit_log.lock() {
        Ok(mut events) => {
            if events.len() < MAX_AUDIT_EVENTS {
                events.push(event);
            } else {
                warn!(
                    "Network audit buffer full ({} events); dropping event",
                    MAX_AUDIT_EVENTS
                );
            }
        }
        Err(e) => {
            warn!(
                "Network audit log mutex poisoned while recording event: {}",
                e
            );
        }
    }
}

/// Log an allowed proxy request.
pub fn log_allowed(
    audit_log: Option<&SharedAuditLog>,
    mode: ProxyMode,
    host: &str,
    port: u16,
    method: &str,
) {
    info!(
        target: "nono_proxy::audit",
        mode = %mode,
        host = host,
        port = port,
        method = method,
        decision = "allow",
        "proxy request allowed"
    );

    push_event(
        audit_log,
        NetworkAuditEvent {
            timestamp_unix_ms: now_unix_millis(),
            mode: map_mode(mode),
            decision: NetworkAuditDecision::Allow,
            target: host.to_string(),
            port: Some(port),
            method: Some(method.to_string()),
            path: None,
            status: None,
            reason: None,
        },
    );
}

/// Log a denied proxy request.
pub fn log_denied(
    audit_log: Option<&SharedAuditLog>,
    mode: ProxyMode,
    host: &str,
    port: u16,
    reason: &str,
) {
    info!(
        target: "nono_proxy::audit",
        mode = %mode,
        host = host,
        port = port,
        decision = "deny",
        reason = reason,
        "proxy request denied"
    );

    push_event(
        audit_log,
        NetworkAuditEvent {
            timestamp_unix_ms: now_unix_millis(),
            mode: map_mode(mode),
            decision: NetworkAuditDecision::Deny,
            target: host.to_string(),
            port: Some(port),
            method: None,
            path: None,
            status: None,
            reason: Some(reason.to_string()),
        },
    );
}

/// Log a successful OAuth credential-capture event.
///
/// Emitted by the OAuth body rewriters (TLS-intercept and reverse-proxy
/// paths) every time real upstream OAuth tokens are swapped for
/// broker-issued nonces. Capture is privileged — the in-process broker
/// now controls real Anthropic credentials — so each event is recorded
/// at `info!` level *and* persisted to the audit ring buffer with a
/// stable `OAUTH_CAPTURE` reason prefix.
///
/// `fields_substituted` is the number of token fields rewritten in this
/// response (1 for access-only or refresh-only, 2 for the full pair).
/// Token and nonce values are deliberately NOT logged — neither full
/// nor partial — so the audit trail captures the *act* of capture
/// without expanding the secret's exposure surface.
pub fn log_oauth_capture(
    audit_log: Option<&SharedAuditLog>,
    mode: ProxyMode,
    host: &str,
    port: u16,
    fields_substituted: u32,
) {
    let reason = format!("OAUTH_CAPTURE substituted={}", fields_substituted);
    info!(
        target: "nono_proxy::audit",
        mode = %mode,
        host = host,
        port = port,
        fields_substituted = fields_substituted,
        decision = "allow",
        "oauth credential captured"
    );

    push_event(
        audit_log,
        NetworkAuditEvent {
            timestamp_unix_ms: now_unix_millis(),
            mode: map_mode(mode),
            decision: NetworkAuditDecision::Allow,
            target: host.to_string(),
            port: Some(port),
            method: None,
            path: None,
            status: None,
            reason: Some(reason),
        },
    );
}

/// Log a reverse proxy request with service info.
pub fn log_reverse_proxy(
    audit_log: Option<&SharedAuditLog>,
    service: &str,
    method: &str,
    path: &str,
    status: u16,
) {
    info!(
        target: "nono_proxy::audit",
        mode = "reverse",
        service = service,
        method = method,
        path = path,
        status = status,
        "reverse proxy response"
    );

    push_event(
        audit_log,
        NetworkAuditEvent {
            timestamp_unix_ms: now_unix_millis(),
            mode: NetworkAuditMode::Reverse,
            decision: NetworkAuditDecision::Allow,
            target: service.to_string(),
            port: None,
            method: Some(method.to_string()),
            path: Some(path.to_string()),
            status: Some(status),
            reason: None,
        },
    );
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn log_allowed_records_event() {
        let log = new_audit_log();

        log_allowed(
            Some(&log),
            ProxyMode::Connect,
            "api.openai.com",
            443,
            "CONNECT",
        );

        let events = drain_audit_events(&log);
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.mode, NetworkAuditMode::Connect);
        assert_eq!(event.decision, NetworkAuditDecision::Allow);
        assert_eq!(event.target, "api.openai.com");
        assert_eq!(event.port, Some(443));
        assert_eq!(event.method.as_deref(), Some("CONNECT"));
        assert!(event.timestamp_unix_ms > 0);
    }

    #[test]
    fn log_oauth_capture_records_event_with_reason() {
        let log = new_audit_log();

        log_oauth_capture(Some(&log), ProxyMode::Connect, "claude.ai", 443, 2);

        let events = drain_audit_events(&log);
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.mode, NetworkAuditMode::Connect);
        assert_eq!(event.decision, NetworkAuditDecision::Allow);
        assert_eq!(event.target, "claude.ai");
        assert_eq!(event.port, Some(443));
        assert_eq!(
            event.reason.as_deref(),
            Some("OAUTH_CAPTURE substituted=2")
        );
        assert!(event.method.is_none());
    }

    #[test]
    fn log_oauth_capture_with_no_audit_log_is_noop() {
        // No panic when audit_log is None — mirrors log_allowed/log_denied.
        log_oauth_capture(None, ProxyMode::Reverse, "anthropic", 443, 1);
    }

    #[test]
    fn log_denied_records_reason() {
        let log = new_audit_log();

        log_denied(
            Some(&log),
            ProxyMode::External,
            "169.254.169.254",
            80,
            "blocked by metadata deny list",
        );

        let events = drain_audit_events(&log);
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.mode, NetworkAuditMode::External);
        assert_eq!(event.decision, NetworkAuditDecision::Deny);
        assert_eq!(
            event.reason.as_deref(),
            Some("blocked by metadata deny list")
        );
    }
}
