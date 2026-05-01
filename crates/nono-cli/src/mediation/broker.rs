//! Token broker for the phantom token pattern.
//!
//! Short-lived credentials (ddtool service tokens, STS, kubelogin OIDC) are
//! captured by the mediation server and stored here under a `nono_<hex>` nonce.
//! The nonce is returned to the sandbox; the real credential never crosses the
//! sandbox boundary.
//!
//! On passthrough, the server promotes nonce-bearing env vars by replacing the
//! nonce with the real value before exec-ing the real binary.
//!
//! Each entry optionally carries a *scope*: the list of consumer command names
//! that may redeem this nonce. A nonce without a scope (issued via the legacy
//! `issue` API or via `issue_with_scope(value, None)`) resolves for any consumer.

use std::collections::HashMap;
use std::sync::Mutex;
use zeroize::Zeroizing;

/// One entry in the broker — the credential plus its optional consumer scope.
struct Entry {
    value: Zeroizing<String>,
    /// Allowed consumers. `None` = unscoped (any consumer may resolve).
    /// `Some(list)` = only commands whose name is in `list` may resolve via
    /// `resolve_for`. The unconditional `resolve` API ignores scope (used
    /// internally for sandbox-context lookups, not for credential promotion).
    consumers: Option<Vec<String>>,
}

/// In-memory store mapping nonces to real credential values.
///
/// Session-scoped: created in `setup()`, dropped when the session ends.
/// All stored values are wrapped in `Zeroizing` so memory is wiped on drop.
pub struct TokenBroker {
    tokens: Mutex<HashMap<String, Entry>>,
}

impl TokenBroker {
    pub fn new() -> Self {
        Self {
            tokens: Mutex::new(HashMap::new()),
        }
    }

    /// Store a real credential value with no consumer scope and return a nonce.
    ///
    /// Equivalent to `issue_with_scope(value, None)`. Retained for callers
    /// that do not produce credentials (e.g. sandbox-context nonces).
    pub fn issue(&self, real_value: Zeroizing<String>) -> String {
        self.issue_with_scope(real_value, None)
    }

    /// Store a real credential value, optionally scoped to a list of allowed
    /// consumer command names, and return a `nono_<hex>` nonce.
    ///
    /// The nonce format is `nono_` followed by 64 lowercase hex characters
    /// (32 random bytes).
    pub fn issue_with_scope(
        &self,
        real_value: Zeroizing<String>,
        consumers: Option<Vec<String>>,
    ) -> String {
        use rand::RngExt;
        let mut rng = rand::rng();
        let bytes: [u8; 32] = rng.random();
        let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let nonce = format!("nono_{}", hex);

        let mut tokens = self.tokens.lock().expect("TokenBroker mutex poisoned");
        tokens.insert(
            nonce.clone(),
            Entry {
                value: real_value,
                consumers,
            },
        );
        nonce
    }

    /// Look up the real credential for a nonce, ignoring scope.
    ///
    /// Used for server-internal lookups where scope does not apply (e.g.
    /// resolving the parent name from a `NONO_SANDBOX_CONTEXT` nonce).
    /// **Do not use this for promoting agent-supplied env-var nonces** —
    /// use `resolve_for` so scope is enforced.
    pub fn resolve(&self, nonce: &str) -> Option<Zeroizing<String>> {
        let tokens = self.tokens.lock().expect("TokenBroker mutex poisoned");
        tokens.get(nonce).map(|e| e.value.clone())
    }

    /// Look up the real credential for a nonce, checking that `consumer`
    /// is allowed to redeem it.
    ///
    /// Returns `None` for:
    /// - Unknown nonces.
    /// - Scoped nonces where `consumer` is not in the consumers list.
    ///
    /// Returns `Some(value)` for:
    /// - Unscoped nonces (any consumer).
    /// - Scoped nonces where `consumer` is in the list.
    pub fn resolve_for(&self, nonce: &str, consumer: &str) -> Option<Zeroizing<String>> {
        let tokens = self.tokens.lock().expect("TokenBroker mutex poisoned");
        let entry = tokens.get(nonce)?;
        match &entry.consumers {
            None => Some(entry.value.clone()),
            Some(list) => {
                if list.iter().any(|c| c == consumer) {
                    Some(entry.value.clone())
                } else {
                    None
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_returns_nono_prefix() {
        let broker = TokenBroker::new();
        let nonce = broker.issue(Zeroizing::new("ghp_secret".to_string()));
        assert!(nonce.starts_with("nono_"), "nonce was: {}", nonce);
        assert_eq!(
            nonce.len(),
            5 + 64,
            "expected 'nono_' + 64 hex chars, got: {}",
            nonce
        );
    }

    #[test]
    fn resolve_finds_issued_nonce() {
        let broker = TokenBroker::new();
        let nonce = broker.issue(Zeroizing::new("real_token_value".to_string()));
        let resolved = broker.resolve(&nonce).expect("nonce should resolve");
        assert_eq!(resolved.as_str(), "real_token_value");
    }

    #[test]
    fn resolve_unknown_nonce_returns_none() {
        let broker = TokenBroker::new();
        assert!(broker.resolve("nono_unknown").is_none());
        assert!(broker.resolve("ghp_notanonce").is_none());
        assert!(broker.resolve("").is_none());
    }

    #[test]
    fn each_issue_produces_unique_nonce() {
        let broker = TokenBroker::new();
        let n1 = broker.issue(Zeroizing::new("val1".to_string()));
        let n2 = broker.issue(Zeroizing::new("val2".to_string()));
        assert_ne!(n1, n2);
    }

    #[test]
    fn issue_with_scope_records_consumers() {
        let broker = TokenBroker::new();
        let nonce = broker.issue_with_scope(
            Zeroizing::new("ghp_secret".to_string()),
            Some(vec!["gh".to_string(), "git".to_string()]),
        );
        assert!(nonce.starts_with("nono_"));

        // Allowed consumers resolve normally.
        let v1 = broker.resolve_for(&nonce, "gh").expect("gh allowed");
        assert_eq!(v1.as_str(), "ghp_secret");
        let v2 = broker.resolve_for(&nonce, "git").expect("git allowed");
        assert_eq!(v2.as_str(), "ghp_secret");

        // Disallowed consumer must not resolve.
        assert!(
            broker.resolve_for(&nonce, "kubectl").is_none(),
            "scoped nonce must not resolve for unlisted consumer"
        );
    }

    #[test]
    fn issue_without_scope_resolves_for_any_consumer() {
        let broker = TokenBroker::new();
        let nonce = broker.issue_with_scope(
            Zeroizing::new("anywhere".to_string()),
            None, // unscoped
        );
        assert_eq!(
            broker.resolve_for(&nonce, "gh").map(|z| z.as_str().to_string()),
            Some("anywhere".to_string())
        );
        assert_eq!(
            broker.resolve_for(&nonce, "kubectl").map(|z| z.as_str().to_string()),
            Some("anywhere".to_string())
        );
    }

    #[test]
    fn legacy_issue_is_unscoped() {
        // The existing `issue` API must continue to produce nonces that
        // resolve for any consumer. This preserves backward compatibility
        // for sandbox-context nonces issued by exec_passthrough.
        let broker = TokenBroker::new();
        let nonce = broker.issue(Zeroizing::new("internal".to_string()));
        assert_eq!(
            broker.resolve_for(&nonce, "anything").map(|z| z.as_str().to_string()),
            Some("internal".to_string())
        );
    }

    #[test]
    fn legacy_resolve_returns_value_regardless_of_scope() {
        // The existing `resolve` API must work for both scoped and unscoped
        // nonces — it is used internally for sandbox-context lookups where
        // there is no consumer command name to check against.
        let broker = TokenBroker::new();
        let scoped = broker.issue_with_scope(
            Zeroizing::new("scoped_value".to_string()),
            Some(vec!["gh".to_string()]),
        );
        let resolved = broker.resolve(&scoped).expect("resolve");
        assert_eq!(resolved.as_str(), "scoped_value");
    }
}
