//! Token broker for the phantom token pattern.
//!
//! Short-lived credentials (ddtool service tokens, STS, kubelogin OIDC) are
//! captured by the mediation server and stored here under a `nono_<hex>` nonce.
//! The nonce is returned to the sandbox; the real credential never crosses the
//! sandbox boundary.
//!
//! On passthrough, the server promotes nonce-bearing env vars by replacing the
//! nonce with the real value before exec-ing the real binary.

use crate::mediation::broker_store::{BrokerStore, PersistedRecord};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::warn;
use zeroize::Zeroizing;

/// In-memory store mapping nonces to real credential values, optionally
/// backed by durable storage so OAuth pairs survive across nono sessions.
///
/// Session-scoped: created in `setup()`, dropped when the session ends.
/// All stored values are wrapped in `Zeroizing` so memory is wiped on drop.
///
/// When constructed via [`TokenBroker::with_store`], the broker hydrates
/// itself from the store on construction (re-registering the nonces and
/// real tokens of any previously persisted OAuth pair) and persists new
/// captures via [`TokenBroker::capture_oauth_pair`]. The simpler
/// [`TokenBroker::new`] constructor is store-free and behaves identically
/// to the pre-persistence broker for command-mediation phantom tokens.
pub struct TokenBroker {
    tokens: Mutex<HashMap<String, Zeroizing<String>>>,
    store: Option<Arc<dyn BrokerStore>>,
}

impl TokenBroker {
    pub fn new() -> Self {
        Self {
            tokens: Mutex::new(HashMap::new()),
            store: None,
        }
    }

    /// Construct a broker backed by `store`. On success, any OAuth pair
    /// already persisted in `store` is loaded into the in-memory map so
    /// nonces sitting in the user's keychain from a previous session
    /// resolve immediately.
    ///
    /// Returns an error only if the store's `load` itself fails. A store
    /// containing no record (the first-ever-launch case) is not an
    /// error — the broker is simply empty until the first capture.
    pub fn with_store(store: Arc<dyn BrokerStore>) -> std::result::Result<Self, nono::NonoError> {
        let broker = Self {
            tokens: Mutex::new(HashMap::new()),
            store: Some(store.clone()),
        };
        if let Some(record) = store.load()? {
            let mut tokens = broker.tokens.lock().expect("TokenBroker mutex poisoned");
            tokens.insert(record.access_nonce, record.access_token);
            tokens.insert(record.refresh_nonce, record.refresh_token);
        }
        Ok(broker)
    }

    /// Store a real credential value and return a `nono_<hex>` nonce.
    ///
    /// The nonce format is `nono_` followed by 64 lowercase hex characters
    /// (32 random bytes). This is clearly distinct from real token formats
    /// (`ghp_`, `AKIA`, `sk-`, `xoxb-`) and longer than any real token.
    pub fn issue(&self, real_value: Zeroizing<String>) -> String {
        use rand::RngExt;
        let mut rng = rand::rng();
        let bytes: [u8; 32] = rng.random();
        let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let nonce = format!("nono_{}", hex);

        let mut tokens = self.tokens.lock().expect("TokenBroker mutex poisoned");
        tokens.insert(nonce.clone(), real_value);
        nonce
    }

    /// Look up the real credential for a nonce.
    ///
    /// Returns `None` for unknown nonces (silently — callers must not distinguish
    /// "invalid nonce" from "nonce not found" to avoid probing attacks).
    pub fn resolve(&self, nonce: &str) -> Option<Zeroizing<String>> {
        let tokens = self.tokens.lock().expect("TokenBroker mutex poisoned");
        tokens.get(nonce).cloned()
    }

    /// Capture an OAuth `(access_token, refresh_token)` pair: mint nonces
    /// for both, register them in memory, and persist the pair to the
    /// configured store (if any) so the mapping survives this session.
    ///
    /// Returns `(access_nonce, refresh_nonce)` so the caller can splice
    /// the nonces into the response body bound for the sandboxed client.
    ///
    /// Persistence is best-effort: a store error is logged at `warn!`
    /// level and swallowed. The in-memory side always succeeds, so
    /// capture-and-rewrite continues to work in the current session even
    /// when durable storage is unavailable.
    pub fn capture_oauth_pair(
        &self,
        access: Zeroizing<String>,
        refresh: Zeroizing<String>,
    ) -> (String, String) {
        let access_nonce = self.issue(access.clone());
        let refresh_nonce = self.issue(refresh.clone());
        if let Some(store) = self.store.as_ref() {
            let record = PersistedRecord {
                access_nonce: access_nonce.clone(),
                refresh_nonce: refresh_nonce.clone(),
                access_token: access,
                refresh_token: refresh,
            };
            if let Err(e) = store.save(&record) {
                warn!("OAuth broker persistence failed (continuing in-memory only): {e}");
            }
        }
        (access_nonce, refresh_nonce)
    }
}

/// Implements the `nono-proxy` `TokenResolver` seam so the proxy can
/// hold an `Arc<dyn TokenResolver>` backed by the same broker the
/// mediation server uses for command-mediation phantom tokens.
///
/// Layer 1.2 of the OAuth-capture design (see
/// `2026-04-27-capture-anthropic-auth.md`): the proxy's TLS-intercept
/// path calls `issue` on captured OAuth tokens and `resolve` to swap
/// nonces back to real values at egress.
impl nono_proxy::TokenResolver for TokenBroker {
    fn issue(&self, secret: Zeroizing<String>) -> String {
        TokenBroker::issue(self, secret)
    }

    fn resolve(&self, nonce: &str) -> Option<Zeroizing<String>> {
        TokenBroker::resolve(self, nonce)
    }

    fn capture_oauth_pair(
        &self,
        access: Zeroizing<String>,
        refresh: Zeroizing<String>,
    ) -> (String, String) {
        TokenBroker::capture_oauth_pair(self, access, refresh)
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
    fn capture_oauth_pair_without_store_just_issues_two_nonces() {
        let broker = TokenBroker::new();
        let (access_nonce, refresh_nonce) = broker.capture_oauth_pair(
            Zeroizing::new("real_access".to_string()),
            Zeroizing::new("real_refresh".to_string()),
        );
        assert!(access_nonce.starts_with("nono_"));
        assert!(refresh_nonce.starts_with("nono_"));
        assert_ne!(access_nonce, refresh_nonce);
        assert_eq!(broker.resolve(&access_nonce).unwrap().as_str(), "real_access");
        assert_eq!(broker.resolve(&refresh_nonce).unwrap().as_str(), "real_refresh");
    }

    #[test]
    fn capture_oauth_pair_with_store_persists_record() {
        use crate::mediation::broker_store::test_support::MemoryBrokerStore;

        let store = std::sync::Arc::new(MemoryBrokerStore::new());
        let broker = TokenBroker::with_store(store.clone()).expect("empty store hydrates fine");
        let (access_nonce, refresh_nonce) = broker.capture_oauth_pair(
            Zeroizing::new("real_access".to_string()),
            Zeroizing::new("real_refresh".to_string()),
        );

        let saved = store.current().expect("record was persisted");
        assert_eq!(saved.access_nonce, access_nonce);
        assert_eq!(saved.refresh_nonce, refresh_nonce);
        assert_eq!(saved.access_token.as_str(), "real_access");
        assert_eq!(saved.refresh_token.as_str(), "real_refresh");
    }

    #[test]
    fn with_store_hydrates_existing_record_into_memory() {
        use crate::mediation::broker_store::test_support::MemoryBrokerStore;
        use crate::mediation::broker_store::PersistedRecord;

        let preloaded = PersistedRecord {
            access_nonce: "nono_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            refresh_nonce: "nono_rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr".to_string(),
            access_token: Zeroizing::new("real_access".to_string()),
            refresh_token: Zeroizing::new("real_refresh".to_string()),
        };
        let store = std::sync::Arc::new(MemoryBrokerStore::preload(preloaded.clone()));
        let broker =
            TokenBroker::with_store(store).expect("store load succeeds for valid record");

        // The persisted nonce IDs must resolve immediately — that is the
        // whole point of cross-session persistence: the keychain still
        // has these nonces, and the new broker resolves them without a
        // re-login.
        assert_eq!(
            broker
                .resolve(&preloaded.access_nonce)
                .expect("hydrated access nonce resolves")
                .as_str(),
            "real_access"
        );
        assert_eq!(
            broker
                .resolve(&preloaded.refresh_nonce)
                .expect("hydrated refresh nonce resolves")
                .as_str(),
            "real_refresh"
        );
    }

    #[test]
    fn with_store_propagates_load_errors() {
        struct FailingStore;
        impl crate::mediation::broker_store::BrokerStore for FailingStore {
            fn load(&self) -> nono::Result<Option<crate::mediation::broker_store::PersistedRecord>> {
                Err(nono::NonoError::KeystoreAccess("simulated failure".to_string()))
            }
            fn save(&self, _: &crate::mediation::broker_store::PersistedRecord) -> nono::Result<()> {
                Ok(())
            }
            fn clear(&self) -> nono::Result<()> {
                Ok(())
            }
        }
        let result = TokenBroker::with_store(std::sync::Arc::new(FailingStore));
        assert!(result.is_err(), "load failure must propagate");
    }

    #[test]
    fn capture_oauth_pair_swallows_save_errors() {
        // Persistence is best-effort: a save failure must not break the
        // capture path. The broker should still return valid nonces and
        // resolve them in-memory.
        struct WriteFailingStore;
        impl crate::mediation::broker_store::BrokerStore for WriteFailingStore {
            fn load(&self) -> nono::Result<Option<crate::mediation::broker_store::PersistedRecord>> {
                Ok(None)
            }
            fn save(&self, _: &crate::mediation::broker_store::PersistedRecord) -> nono::Result<()> {
                Err(nono::NonoError::KeystoreAccess("simulated save failure".to_string()))
            }
            fn clear(&self) -> nono::Result<()> {
                Ok(())
            }
        }
        let broker = TokenBroker::with_store(std::sync::Arc::new(WriteFailingStore))
            .expect("load returned Ok(None), construction must succeed");
        let (access_nonce, refresh_nonce) = broker.capture_oauth_pair(
            Zeroizing::new("real_access".to_string()),
            Zeroizing::new("real_refresh".to_string()),
        );
        assert!(access_nonce.starts_with("nono_"));
        assert_eq!(broker.resolve(&access_nonce).unwrap().as_str(), "real_access");
        assert_eq!(broker.resolve(&refresh_nonce).unwrap().as_str(), "real_refresh");
    }

    #[test]
    fn token_resolver_trait_object_round_trips() {
        // The proxy holds the broker as `Arc<dyn nono_proxy::TokenResolver>`.
        // Issue + resolve through the trait object must return the same
        // value the concrete broker does, proving the seam is wired and
        // the trait is object-safe in our usage.
        use nono_proxy::TokenResolver;
        use std::sync::Arc;

        let resolver: Arc<dyn TokenResolver> = Arc::new(TokenBroker::new());
        let nonce = resolver.issue(Zeroizing::new("real_value".to_string()));
        assert!(nonce.starts_with("nono_"));

        let resolved = resolver
            .resolve(&nonce)
            .expect("nonce issued via trait should resolve via trait");
        assert_eq!(resolved.as_str(), "real_value");

        assert!(
            resolver.resolve("nono_unknown_nonce").is_none(),
            "unknown nonces must resolve to None silently"
        );
    }
}
