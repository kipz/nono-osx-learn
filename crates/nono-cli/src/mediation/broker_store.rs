//! Persistent storage for the OAuth token broker.
//!
//! After Layer 1 OAuth capture lands, the in-memory `TokenBroker` holds the
//! mapping `nonce -> real_token`. That map is destroyed when nono exits, so
//! the nonces written to the user's keychain (`Claude Code-credentials`) by
//! the rewritten OAuth response have nothing to resolve to in the next nono
//! session — the user would have to `/login` again every time.
//!
//! This module persists captured `(access_token, refresh_token)` pairs to
//! the same OS keystore the existing nono credential-injection feature
//! uses (service name [`SERVICE_NAME`], i.e. the value of
//! [`nono::keystore::DEFAULT_SERVICE`]). On startup, the broker hydrates
//! itself from this persisted record and re-registers the same nonces it
//! issued in the previous session so that the keychain entry the
//! sandboxed Claude reads continues to resolve.
//!
//! ## Threat model
//!
//! Identical to nono's existing credential-injection feature
//! (https://nono.sh/docs/cli/features/credential-injection): real
//! credentials live in the OS keychain under service name `nono`, the
//! sandboxed child sees only proxy-issued nonces. Whatever subprocess
//! mediation rules a profile uses to gate `security` CLI access already
//! cover the broker's entry because both share the same service.
//!
//! ## Why save goes through the `keyring` crate (not `security` CLI)
//!
//! Our broker payload is a JSON blob containing two nonces plus two
//! real OAuth tokens (~270+ bytes for Anthropic-issued tokens). The
//! macOS `security add-generic-password` CLI has no way to accept a
//! password of that size without leaking the bytes through argv:
//!
//! - `-w <payload>` puts the secret in the child's argv, where it is
//!   briefly visible to any local process scanning `ps` / sysctl
//!   `kern.proc.argmax`. Documented as insecure by the tool itself.
//! - `-w` with no argument is the documented secure path: `security`
//!   calls `readpassphrase(3)`, which uses a hard-coded 128-byte
//!   buffer (`_PASSWORD_LEN`). Our payload silently truncates to
//!   ~127 bytes — the access_nonce survives but the refresh_nonce
//!   and both real tokens are lost. Verified empirically on 2026-05-14.
//!
//! The `keyring` crate's `set_password` calls `SecItemAdd` directly via
//! the Security framework, which accepts arbitrary-length values. We
//! use that for save and keep the legacy `security find-generic-password
//! -w` path for load (it honours keyring-created ACLs silently when the
//! reading binary is in the entry's trusted-apps list, which is the
//! common case for normal usage; rebuilds via `cargo install` may produce
//! a new binary signature and require the user to allow the entry once).
//!
//! Earlier revisions of this module shelled out to `security
//! add-generic-password -A` to avoid that re-prompt entirely (the `-A`
//! flag creates an empty trusted-apps list — "any app may access
//! without warning"). That worked for the original token-injection
//! credentials, which fit in 128 bytes. The OAuth-capture broker's
//! payload doesn't.

use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

/// Keychain service name shared with nono's credential-injection feature.
/// New account names introduced here must not collide with documented
/// account names from that feature (e.g. `openai_api_key`,
/// `anthropic_api_key`, `github_token`).
pub const SERVICE_NAME: &str = nono::keystore::DEFAULT_SERVICE;

/// Account name for the OAuth-capture broker's persisted record.
///
/// Holds a JSON object with both broker-issued nonces and the real
/// upstream tokens. Distinct from any user-managed account names so
/// `security add-generic-password` for unrelated services never
/// overwrites it and vice versa.
pub const CLAUDE_OAUTH_ACCOUNT: &str = "claude_oauth_broker";

/// One captured OAuth credential pair.
///
/// `access_nonce` and `refresh_nonce` are the broker-issued
/// `nono_<hex>` strings that the sandboxed client reads from its
/// own credential file (e.g. macOS keychain `Claude Code-credentials`).
/// `access_token` and `refresh_token` are the real upstream secrets
/// the broker forwards to Anthropic on behalf of the client.
#[derive(Debug, Clone)]
pub struct PersistedRecord {
    pub access_nonce: String,
    pub refresh_nonce: String,
    pub access_token: Zeroizing<String>,
    pub refresh_token: Zeroizing<String>,
}

/// Persistence backend for the broker.
///
/// Implementations are responsible for storing exactly one record per
/// service+account pair. `save` overwrites any existing record; `clear`
/// removes it. `load` returns `None` if no record is stored.
pub trait BrokerStore: Send + Sync {
    fn load(&self) -> Result<Option<PersistedRecord>>;
    fn save(&self, record: &PersistedRecord) -> Result<()>;
    fn clear(&self) -> Result<()>;
}

/// On-disk JSON shape. Kept private so callers go through `BrokerStore`
/// and hold the secret as `Zeroizing<String>` once decoded.
#[derive(Serialize, Deserialize)]
struct PersistedJson {
    access_nonce: String,
    refresh_nonce: String,
    access_token: String,
    refresh_token: String,
}

impl PersistedJson {
    fn from_record(record: &PersistedRecord) -> Self {
        Self {
            access_nonce: record.access_nonce.clone(),
            refresh_nonce: record.refresh_nonce.clone(),
            access_token: record.access_token.as_str().to_string(),
            refresh_token: record.refresh_token.as_str().to_string(),
        }
    }

    fn into_record(self) -> PersistedRecord {
        PersistedRecord {
            access_nonce: self.access_nonce,
            refresh_nonce: self.refresh_nonce,
            access_token: Zeroizing::new(self.access_token),
            refresh_token: Zeroizing::new(self.refresh_token),
        }
    }
}

/// macOS / Linux keystore-backed store. Reads via the `keyring` crate
/// (in-process Security framework / secret-service call). Writes on
/// macOS shell out to `security add-generic-password -A` so the entry
/// is created with the "any app, no warning" ACL that matches the
/// existing credential-injection feature; on Linux the `keyring` crate
/// is used for both save and load.
#[cfg(feature = "system-keyring")]
pub struct KeystoreBrokerStore {
    service: String,
    account: String,
}

#[cfg(feature = "system-keyring")]
impl KeystoreBrokerStore {
    /// Construct a store keyed by `service` and `account`.
    pub fn new(service: impl Into<String>, account: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            account: account.into(),
        }
    }

    /// Default store: nono's credential-injection service, OAuth account.
    pub fn default_for_claude_oauth() -> Self {
        Self::new(SERVICE_NAME, CLAUDE_OAUTH_ACCOUNT)
    }

    fn entry(&self) -> Result<keyring::Entry> {
        keyring::Entry::new(&self.service, &self.account).map_err(|e| {
            NonoError::KeystoreAccess(format!(
                "broker keyring entry init for {}/{}: {e}",
                self.service, self.account
            ))
        })
    }

    /// Save path: write the JSON payload via the `keyring` crate.
    ///
    /// On macOS this invokes `SecItemAdd` directly (no argv leak, no
    /// `readpassphrase` 128-byte cap). On Linux it goes to the
    /// secret-service collection. See the module docs on why we don't
    /// shell out to `security add-generic-password` for this payload.
    fn save_via_keyring(&self, payload: &str) -> Result<()> {
        let entry = self.entry()?;
        entry.set_password(payload).map_err(|e| {
            NonoError::KeystoreAccess(format!(
                "broker record save to {}/{}: {e}",
                self.service, self.account
            ))
        })
    }

    /// macOS-specific load path: shell out to `security find-generic-password
    /// -w` instead of going through the `keyring` crate.
    ///
    /// The `keyring` crate's `get_password()` on macOS uses a Security
    /// framework code path that triggers a system password prompt when
    /// the calling binary is not in the entry's trusted-apps ACL — even
    /// when the entry was created with `-A` (empty trusted-apps list,
    /// "any application may access without warning"). The `security` CLI
    /// uses the older Keychain Services API which honours the empty ACL
    /// silently, matching the no-prompt behaviour the existing nono
    /// credential-injection feature relies on.
    ///
    /// Verified empirically: `security ... -w` reads our `-A`-created
    /// entry without prompting; the keyring crate prompts on the same
    /// entry. We therefore use `security` for both ends (save and load)
    /// on macOS so the broker's experience matches what users get for
    /// every other credential under service "nono".
    #[cfg(target_os = "macos")]
    fn load_via_security_cli(&self) -> Result<Option<String>> {
        let output = Command::new("/usr/bin/security")
            .args([
                "find-generic-password",
                "-s",
                &self.service,
                "-a",
                &self.account,
                "-w",
            ])
            .stdin(Stdio::null())
            .output()
            .map_err(|e| NonoError::KeystoreAccess(format!("invoke /usr/bin/security: {e}")))?;
        if output.status.success() {
            // -w prints the password followed by a single newline; trim it.
            let mut stdout = String::from_utf8(output.stdout).map_err(|e| {
                NonoError::KeystoreAccess(format!(
                    "non-UTF8 password from {}/{}: {e}",
                    self.service, self.account
                ))
            })?;
            if stdout.ends_with('\n') {
                stdout.pop();
            }
            Ok(Some(stdout))
        } else {
            // Distinguish "no such item" from real errors. macOS exits 44
            // ("The specified item could not be found in the keychain.")
            // when the entry doesn't exist.
            let stderr = String::from_utf8_lossy(&output.stderr);
            if output.status.code() == Some(44)
                || stderr.contains("could not be found in the keychain")
            {
                Ok(None)
            } else {
                Err(NonoError::KeystoreAccess(format!(
                    "security find-generic-password ({}) for {}/{}: {}",
                    output.status,
                    self.service,
                    self.account,
                    stderr.trim()
                )))
            }
        }
    }
}

#[cfg(feature = "system-keyring")]
impl BrokerStore for KeystoreBrokerStore {
    fn load(&self) -> Result<Option<PersistedRecord>> {
        // Read via `security` CLI on macOS (silent for `-A`-created
        // entries), keyring crate elsewhere. See the docs on
        // [`Self::load_via_security_cli`] for why.
        let maybe_json: Option<String> = {
            #[cfg(target_os = "macos")]
            {
                self.load_via_security_cli()?
            }
            #[cfg(not(target_os = "macos"))]
            {
                let entry = self.entry()?;
                match entry.get_password() {
                    Ok(s) => Some(s),
                    Err(keyring::Error::NoEntry) => None,
                    Err(other) => {
                        return Err(NonoError::KeystoreAccess(format!(
                            "broker record load from {}/{}: {other}",
                            self.service, self.account
                        )));
                    }
                }
            }
        };
        match maybe_json {
            Some(json) => match serde_json::from_str::<PersistedJson>(&json) {
                Ok(parsed) => Ok(Some(parsed.into_record())),
                Err(e) => Err(NonoError::KeystoreAccess(format!(
                    "broker record at {}/{} is not valid JSON: {e}",
                    self.service, self.account
                ))),
            },
            None => Ok(None),
        }
    }

    fn save(&self, record: &PersistedRecord) -> Result<()> {
        // Wrap the serialised JSON in `Zeroizing` so the buffer is
        // wiped when this function returns, regardless of branch.
        let json: Zeroizing<String> = Zeroizing::new(
            serde_json::to_string(&PersistedJson::from_record(record))
                .map_err(|e| NonoError::KeystoreAccess(format!("broker record serialise: {e}")))?,
        );
        self.save_via_keyring(&json)
    }

    fn clear(&self) -> Result<()> {
        let entry = self.entry()?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(other) => Err(NonoError::KeystoreAccess(format!(
                "broker record clear from {}/{}: {other}",
                self.service, self.account
            ))),
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! In-memory `BrokerStore` for unit tests.

    use super::*;
    use std::sync::Mutex;

    pub struct MemoryBrokerStore {
        record: Mutex<Option<PersistedRecord>>,
    }

    impl MemoryBrokerStore {
        pub fn new() -> Self {
            Self {
                record: Mutex::new(None),
            }
        }

        pub fn preload(record: PersistedRecord) -> Self {
            Self {
                record: Mutex::new(Some(record)),
            }
        }

        pub fn current(&self) -> Option<PersistedRecord> {
            self.record
                .lock()
                .expect("MemoryBrokerStore poisoned")
                .clone()
        }
    }

    impl BrokerStore for MemoryBrokerStore {
        fn load(&self) -> Result<Option<PersistedRecord>> {
            Ok(self
                .record
                .lock()
                .expect("MemoryBrokerStore poisoned")
                .clone())
        }

        fn save(&self, record: &PersistedRecord) -> Result<()> {
            *self.record.lock().expect("MemoryBrokerStore poisoned") = Some(record.clone());
            Ok(())
        }

        fn clear(&self) -> Result<()> {
            *self.record.lock().expect("MemoryBrokerStore poisoned") = None;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_json_payload_exceeds_readpassphrase_buffer() {
        // Regression guard for the 2026-05-14 truncation bug. A real
        // Anthropic OAuth token pair serialised through `PersistedJson`
        // is well over the 128-byte `readpassphrase(3)` cap that broke
        // the earlier `security add-generic-password -w` save path.
        // The current implementation uses `keyring`'s `set_password`
        // (SecItemAdd) which has no such cap; this test only documents
        // why the size matters so a future refactor can't silently
        // reintroduce a 128-byte-bounded backend.
        let record = PersistedRecord {
            access_nonce: format!("nono_{}", "a".repeat(64)),
            refresh_nonce: format!("nono_{}", "b".repeat(64)),
            // Anthropic OAuth tokens are JWT-shaped, typically 150-300
            // bytes. Use a representative 200-byte string here.
            access_token: Zeroizing::new("sk-ant-oat01-".to_string() + &"x".repeat(187)),
            refresh_token: Zeroizing::new("sk-ant-ort01-".to_string() + &"y".repeat(187)),
        };
        let json = serde_json::to_string(&PersistedJson::from_record(&record))
            .expect("serialise persisted json");
        assert!(
            json.len() > 128,
            "payload must exceed readpassphrase _PASSWORD_LEN (got {} bytes); \
             update the test or restore an in-process keystore backend",
            json.len()
        );
    }
}
