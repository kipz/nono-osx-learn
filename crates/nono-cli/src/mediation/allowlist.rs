//! Per-user persistent allowlist for "Allow-always" approvals.
//!
//! The store is a tagged-union design so it can be reused across multiple
//! mediation plans (4.1 caller-policy, 4.2 argv-shape, 4.3 config/env scan).
//! Each entry carries an `AllowlistKey { kind, payload }`; this plan (4.2)
//! introduces the `ArgvShape` variant only.
//!
//! Persistence: a single JSON document at `~/.nono/argv-allowlist.json` (or
//! a caller-supplied path). Writes are exclusive-flock'd against a sidecar
//! `*.lock` file and committed via write-to-temp + atomic rename. The
//! schema carries an integer `version` and the loader rejects any value
//! greater than [`KNOWN_VERSION`] so an older nono cannot silently
//! mis-interpret a newer file.

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use nono::{NonoError, Result};

/// The latest schema version this code knows how to read.
///
/// On load, any document with `version > KNOWN_VERSION` is rejected — an
/// older nono must not silently mis-interpret entries it does not
/// understand.
const KNOWN_VERSION: u32 = 1;

/// The kind of approval an entry represents.
///
/// New variants are reserved for upcoming mediation plans (4.1, 4.3) so the
/// same store can be reused without a schema-migration round.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AllowlistKind {
    /// Plan 4.2: payload `{ "cmd": String, "argv": [String] }`.
    ArgvShape,
    /// Plan 4.1: payload `{ "cmd": String, "parent": String, "argv": [String] }`.
    CallerPolicy,
    /// Plan 4.3: payload `{ "cmd": String, "key": String, "value": String }`.
    ScanConfig,
    /// Plan 4.3: payload `{ "cmd": String, "key": String, "value": String }`.
    ScanEnv,
    /// Plan 4.3: payload `{ "key": String, "value": String }`.
    ScanSshOpt,
    /// Plan 4.3: payload `{ "path": String }`.
    ScanSshIdentity,
}

/// A tagged-union key identifying an allowlist entry.
///
/// Equality is structural over `(kind, payload)`. The payload is an opaque
/// JSON value whose shape is determined by `kind`; matching is exact byte-
/// for-byte (after canonical JSON serialization).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AllowlistKey {
    pub kind: AllowlistKind,
    pub payload: serde_json::Value,
}

/// A single persisted allowlist entry: a key plus the approval timestamp.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct AllowlistEntry {
    #[serde(flatten)]
    pub key: AllowlistKey,
    /// RFC 3339 UTC timestamp at which the user approved this entry.
    pub approved_at: String,
}

/// On-disk document layout. Top-level fields:
/// - `version`: schema version (currently `1`).
/// - `entries`: ordered list of approvals.
#[derive(Debug, Clone, Deserialize, Serialize)]
struct AllowlistDoc {
    #[serde(default = "default_version")]
    version: u32,
    #[serde(default)]
    entries: Vec<AllowlistEntry>,
}

impl Default for AllowlistDoc {
    fn default() -> Self {
        Self {
            version: KNOWN_VERSION,
            entries: Vec::new(),
        }
    }
}

fn default_version() -> u32 {
    KNOWN_VERSION
}

/// Per-user persistent allowlist.
///
/// Constructed via [`AllowlistStore::open_default`] (resolves
/// `~/.nono/argv-allowlist.json`) or [`AllowlistStore::open_at`]
/// (caller-supplied path; primarily used in tests).
///
/// Both `is_approved` and `record` take an exclusive flock against a sidecar
/// `*.lock` file for the duration of the call, so concurrent processes /
/// threads cannot lose each other's writes. `is_approved` additionally
/// degrades gracefully on flock or load errors (returns `false`); `record`
/// surfaces them.
pub struct AllowlistStore {
    /// Path to the JSON document (the lock file is `<path>.lock`).
    path: PathBuf,
    /// In-process serialization. The flock guards cross-process; this Mutex
    /// keeps in-process callers from racing on the temp-file rename.
    inner: Mutex<()>,
}

impl AllowlistStore {
    /// Open (or prepare for) the default per-user allowlist at
    /// `~/.nono/argv-allowlist.json`. Creates `~/.nono/` if missing.
    pub fn open_default() -> Result<Self> {
        let home = dirs::home_dir().ok_or(NonoError::HomeNotFound)?;
        let dir = home.join(".nono");
        if !dir.exists() {
            std::fs::create_dir_all(&dir).map_err(|e| {
                NonoError::SandboxInit(format!(
                    "allowlist: failed to create {}: {}",
                    dir.display(),
                    e
                ))
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o700);
                let _ = std::fs::set_permissions(&dir, perms);
            }
        }
        Self::open_at(dir.join("argv-allowlist.json"))
    }

    /// Open (or prepare for) an allowlist at the given path.
    ///
    /// The path need not exist yet — it will be created on first `record`.
    /// The parent directory must exist.
    pub fn open_at<P: AsRef<Path>>(path: P) -> Result<Self> {
        Ok(Self {
            path: path.as_ref().to_path_buf(),
            inner: Mutex::new(()),
        })
    }

    /// Path to the sidecar lock file.
    fn lock_path(&self) -> PathBuf {
        let mut p = self.path.clone().into_os_string();
        p.push(".lock");
        PathBuf::from(p)
    }

    /// Acquire an exclusive flock on the sidecar lock file. The returned
    /// `File` releases the lock on drop.
    fn flock(&self) -> Result<File> {
        let lock_path = self.lock_path();
        let f = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| {
                NonoError::SandboxInit(format!(
                    "allowlist: failed to open lock file {}: {}",
                    lock_path.display(),
                    e
                ))
            })?;
        FileExt::lock_exclusive(&f).map_err(|e| {
            NonoError::SandboxInit(format!(
                "allowlist: failed to flock {}: {}",
                lock_path.display(),
                e
            ))
        })?;
        Ok(f)
    }

    /// Read the document from disk. A missing file returns the default
    /// (empty) document. Any `version > KNOWN_VERSION` is rejected.
    fn load(&self) -> Result<AllowlistDoc> {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(AllowlistDoc::default());
            }
            Err(e) => {
                return Err(NonoError::SandboxInit(format!(
                    "allowlist: failed to read {}: {}",
                    self.path.display(),
                    e
                )));
            }
        };
        let doc: AllowlistDoc = serde_json::from_slice(&bytes).map_err(|e| {
            NonoError::SandboxInit(format!(
                "allowlist: failed to parse {}: {}",
                self.path.display(),
                e
            ))
        })?;
        if doc.version > KNOWN_VERSION {
            return Err(NonoError::SandboxInit(format!(
                "allowlist: unknown future schema version {} in {} (this nono knows up to {})",
                doc.version,
                self.path.display(),
                KNOWN_VERSION
            )));
        }
        Ok(doc)
    }

    /// Atomically replace the document on disk: write to a temp file in
    /// the same directory, then `rename` over the target.
    fn save(&self, doc: &AllowlistDoc) -> Result<()> {
        let dir = self.path.parent().ok_or_else(|| {
            NonoError::SandboxInit(format!(
                "allowlist: path has no parent directory: {}",
                self.path.display()
            ))
        })?;
        if !dir.exists() {
            std::fs::create_dir_all(dir).map_err(|e| {
                NonoError::SandboxInit(format!(
                    "allowlist: failed to create {}: {}",
                    dir.display(),
                    e
                ))
            })?;
        }
        let tmp = self
            .path
            .with_extension(format!("json.tmp.{}", std::process::id()));
        let bytes = serde_json::to_vec_pretty(doc).map_err(|e| {
            NonoError::SandboxInit(format!("allowlist: failed to serialize: {}", e))
        })?;
        {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)
                .map_err(|e| {
                    NonoError::SandboxInit(format!(
                        "allowlist: failed to open temp file {}: {}",
                        tmp.display(),
                        e
                    ))
                })?;
            f.write_all(&bytes).map_err(|e| {
                NonoError::SandboxInit(format!(
                    "allowlist: failed to write temp file {}: {}",
                    tmp.display(),
                    e
                ))
            })?;
            f.sync_all().map_err(|e| {
                NonoError::SandboxInit(format!(
                    "allowlist: failed to sync temp file {}: {}",
                    tmp.display(),
                    e
                ))
            })?;
        }
        std::fs::rename(&tmp, &self.path).map_err(|e| {
            NonoError::SandboxInit(format!(
                "allowlist: failed to rename {} -> {}: {}",
                tmp.display(),
                self.path.display(),
                e
            ))
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(&self.path, perms);
        }
        Ok(())
    }

    /// Returns `true` if `key` exactly matches an entry in the store.
    ///
    /// On any I/O / parse / lock error this returns `false` — a graceful
    /// degradation: the user will simply see the prompt again, never a
    /// silent allow.
    pub fn is_approved(&self, key: &AllowlistKey) -> bool {
        let _guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        let _flock = match self.flock() {
            Ok(f) => f,
            Err(_) => return false,
        };
        let doc = match self.load() {
            Ok(d) => d,
            Err(_) => return false,
        };
        doc.entries.iter().any(|e| &e.key == key)
    }

    /// Append `key` (with the current UTC timestamp) if it is not already
    /// present. Errors propagate — callers can surface them in the prompt
    /// flow.
    pub fn record(&self, key: &AllowlistKey) -> Result<()> {
        let _guard = self
            .inner
            .lock()
            .map_err(|e| NonoError::SandboxInit(format!("allowlist: mutex poisoned: {}", e)))?;
        let _flock = self.flock()?;
        let mut doc = self.load()?;
        if doc.entries.iter().any(|e| &e.key == key) {
            return Ok(());
        }
        doc.entries.push(AllowlistEntry {
            key: key.clone(),
            approved_at: chrono::Utc::now().to_rfc3339(),
        });
        self.save(&doc)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    fn argv_key(cmd: &str, argv: &[&str]) -> AllowlistKey {
        AllowlistKey {
            kind: AllowlistKind::ArgvShape,
            payload: json!({
                "cmd": cmd,
                "argv": argv,
            }),
        }
    }

    #[test]
    fn empty_allowlist_returns_false_for_any_query() {
        let dir = tempdir().unwrap();
        let store = AllowlistStore::open_at(dir.path().join("argv-allowlist.json")).unwrap();
        assert!(!store.is_approved(&argv_key("security", &["find-generic-password"])));
    }

    #[test]
    fn record_then_query_returns_true_for_exact_match() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("argv-allowlist.json");
        let store = AllowlistStore::open_at(&path).unwrap();
        let k = argv_key("security", &["find-generic-password", "-a", "u"]);
        store.record(&k).unwrap();
        assert!(store.is_approved(&k));
    }

    #[test]
    fn query_returns_false_for_argv_with_extra_token() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("argv-allowlist.json");
        let store = AllowlistStore::open_at(&path).unwrap();
        store.record(&argv_key("security", &["a", "b"])).unwrap();
        assert!(
            !store.is_approved(&argv_key("security", &["a", "b", "c"])),
            "extra token must not match"
        );
        assert!(
            !store.is_approved(&argv_key("security", &["a"])),
            "missing token must not match"
        );
        assert!(
            !store.is_approved(&argv_key("security", &["a", "different"])),
            "different token must not match"
        );
    }

    #[test]
    fn record_persists_across_open_calls() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("argv-allowlist.json");
        {
            let store = AllowlistStore::open_at(&path).unwrap();
            store.record(&argv_key("foo", &["bar"])).unwrap();
        }
        let store2 = AllowlistStore::open_at(&path).unwrap();
        assert!(store2.is_approved(&argv_key("foo", &["bar"])));
    }

    #[test]
    fn record_is_per_command() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("argv-allowlist.json");
        let store = AllowlistStore::open_at(&path).unwrap();
        store
            .record(&argv_key("security", &["find-generic-password"]))
            .unwrap();
        assert!(
            !store.is_approved(&argv_key("ddtool", &["find-generic-password"])),
            "same argv under a different command must not match"
        );
    }

    #[test]
    fn open_at_nonexistent_path_returns_empty_store() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        let store = AllowlistStore::open_at(&path).unwrap();
        assert!(!store.is_approved(&argv_key("any", &["thing"])));
    }

    #[test]
    fn load_rejects_unknown_future_version() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("argv-allowlist.json");
        std::fs::write(&path, r#"{"version": 99, "entries": []}"#).unwrap();
        let store = AllowlistStore::open_at(&path).unwrap();
        // is_approved swallows load errors and returns false (graceful), but
        // record() surfaces the error.
        let err = store
            .record(&argv_key("foo", &["bar"]))
            .expect_err("future version must error");
        let msg = format!("{}", err);
        assert!(
            msg.contains("version") && msg.contains("99"),
            "error must mention the unknown version; got: {}",
            msg
        );
    }

    #[test]
    fn concurrent_record_calls_both_persist() {
        // Two threads each record a distinct entry. With per-call flock, both
        // entries must end up on disk (no last-writer-wins).
        let dir = tempdir().unwrap();
        let path = dir.path().join("argv-allowlist.json");
        let store = std::sync::Arc::new(AllowlistStore::open_at(&path).unwrap());
        let s1 = std::sync::Arc::clone(&store);
        let s2 = std::sync::Arc::clone(&store);
        let t1 = std::thread::spawn(move || {
            s1.record(&argv_key("a", &["1"])).unwrap();
        });
        let t2 = std::thread::spawn(move || {
            s2.record(&argv_key("b", &["2"])).unwrap();
        });
        t1.join().unwrap();
        t2.join().unwrap();
        assert!(store.is_approved(&argv_key("a", &["1"])));
        assert!(store.is_approved(&argv_key("b", &["2"])));
    }
}
