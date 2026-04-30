//! Exec-based credential source with TTL refresh.
//!
//! Provides [`ExecTokenCache`] — a thread-safe cache that holds the trimmed
//! stdout of a credential-issuance command (e.g. `ddtool auth token …`,
//! `gcloud auth print-access-token`) and refreshes it on demand before its
//! configured TTL elapses. Designed for the reverse-proxy credential
//! injection flow where the agent never sees the real bearer.
//!
//! The cache lifecycle (TTL gating, write-lock dance, graceful degradation,
//! force-refresh cooldown) lives in [`crate::cache::TtlCache`]; this module
//! just supplies the fetcher closure that runs the configured command and
//! validates its stdout.
//!
//! ## Design
//!
//! - **Absolute-path argv.** `command[0]` must be an absolute path. PATH
//!   lookup is refused so a sibling on PATH cannot shadow the configured
//!   binary.
//! - **Trimmed stdout.** A single trailing newline (Unix or Windows) is
//!   stripped, matching how `nono::keystore::load_secret_file` treats
//!   file-backed secrets.
//! - **No CR/LF/NUL in the credential.** A trailing newline is stripped,
//!   but any embedded control character is rejected — without this, a
//!   helper that emits `"tok\r\nX-Admin: yes"` would let a malicious
//!   helper splice arbitrary headers via `credential_format`.

use crate::cache::{FetcherFn, FetcherFuture, TtlCache};
use crate::config::ExecConfig;
use crate::error::{ProxyError, Result};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use zeroize::Zeroizing;

/// Default timeout for a single fetch invocation when the route does not
/// specify `timeout_secs`. Generous enough for commands that prompt for
/// biometric or hardware-key approval (matches the secret-manager budget in
/// `nono::keystore`).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Hard upper bound on accepted stdout size (1 MiB). Prevents a misbehaving
/// helper from exhausting memory before we trim and zeroize.
const MAX_STDOUT_BYTES: usize = 1024 * 1024;

/// Cooldown between successive `force_refresh` attempts. Stops a
/// 401-flapping upstream from causing the helper to be re-run on every
/// request — at most one re-issuance per cooldown window.
const FORCE_REFRESH_COOLDOWN: Duration = Duration::from_secs(30);

/// Resolved configuration for an exec-based credential, ready to invoke.
#[derive(Clone)]
pub struct ExecResolvedConfig {
    /// Argv. `command[0]` is an absolute path.
    pub command: Vec<String>,
    /// Configured TTL for the cached value.
    pub ttl: Duration,
    /// Per-invocation timeout.
    pub timeout: Duration,
}

impl std::fmt::Debug for ExecResolvedConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Only the binary path is logged; subsequent argv entries can carry
        // sensitive flags (e.g. account selectors) so they are redacted.
        let bin = self.command.first().map(String::as_str).unwrap_or("");
        f.debug_struct("ExecResolvedConfig")
            .field("command[0]", &bin)
            .field("argv_len", &self.command.len())
            .field("ttl", &self.ttl)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl ExecResolvedConfig {
    /// Resolve a serialized [`ExecConfig`] into a runnable form, validating
    /// the argv and TTL.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::Config`] if `command` is empty, `command[0]` is
    /// not absolute, or `ttl_secs` is zero.
    pub fn from_config(cfg: &ExecConfig) -> Result<Self> {
        if cfg.command.is_empty() {
            return Err(ProxyError::Config(
                "exec credential 'command' must contain at least the binary path".to_string(),
            ));
        }

        let bin = &cfg.command[0];
        if bin.is_empty() {
            return Err(ProxyError::Config(
                "exec credential 'command[0]' is empty".to_string(),
            ));
        }
        if !Path::new(bin).is_absolute() {
            return Err(ProxyError::Config(format!(
                "exec credential 'command[0]' must be an absolute path, got: {}",
                bin
            )));
        }

        if cfg.ttl_secs == 0 {
            return Err(ProxyError::Config(
                "exec credential 'ttl_secs' must be greater than zero".to_string(),
            ));
        }

        let timeout = cfg
            .timeout_secs
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_TIMEOUT);

        Ok(Self {
            command: cfg.command.clone(),
            ttl: Duration::from_secs(cfg.ttl_secs),
            timeout,
        })
    }
}

/// TTL-bounded cache for a credential produced by an external command.
///
/// A thin wrapper over [`TtlCache`] that knows how to build the fetcher
/// closure from an [`ExecResolvedConfig`].
#[derive(Debug)]
pub struct ExecTokenCache {
    inner: TtlCache,
}

/// Build the fetcher closure that runs the configured command and returns
/// `(stdout, ttl)`. Cloning `config` once per call keeps the closure
/// `Send + Sync` without any locking.
fn build_fetcher(config: ExecResolvedConfig) -> FetcherFn {
    Box::new(move || -> FetcherFuture {
        let cfg = config.clone();
        Box::pin(async move {
            let value = run_command(&cfg).await?;
            Ok((value, cfg.ttl))
        })
    })
}

fn label_for(config: &ExecResolvedConfig) -> String {
    format!(
        "exec:{}",
        config
            .command
            .first()
            .map(String::as_str)
            .unwrap_or("<unknown>")
    )
}

impl ExecTokenCache {
    /// Build a new cache by running the command and caching the result.
    /// Bridges into async via `tokio::task::block_in_place` so this can be
    /// called from within the synchronous `CredentialStore::load`.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::ExecFetch`] if the initial fetch fails (timeout,
    /// non-zero exit, empty stdout, control characters, oversized stdout).
    /// The caller is expected to skip the route on failure so the proxy can
    /// still start for other routes.
    pub fn new(config: ExecResolvedConfig) -> Result<Self> {
        let label = label_for(&config);
        let fetcher = build_fetcher(config);
        let inner = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(TtlCache::new(
                label,
                FORCE_REFRESH_COOLDOWN,
                fetcher,
            ))
        })?;
        Ok(Self { inner })
    }

    /// Construct a cache with a pre-populated value. Used by tests that do
    /// not want to run an external command.
    #[cfg(test)]
    pub(crate) fn new_from_parts(config: ExecResolvedConfig, value: &str, ttl: Duration) -> Self {
        let label = label_for(&config);
        let fetcher = build_fetcher(config);
        let inner = TtlCache::new_from_parts(label, FORCE_REFRESH_COOLDOWN, fetcher, value, ttl);
        Self { inner }
    }

    /// Return the cached value, refreshing if within the expiry buffer. See
    /// [`TtlCache::get_or_refresh`].
    pub async fn get_or_refresh(&self) -> Zeroizing<String> {
        self.inner.get_or_refresh().await
    }

    /// Force a refresh, ignoring TTL. Subject to the configured cooldown —
    /// see [`TtlCache::force_refresh`].
    pub async fn force_refresh(&self) -> Zeroizing<String> {
        self.inner.force_refresh().await
    }
}

/// Run the configured command, capture stdout, validate, and return the
/// trimmed value wrapped in `Zeroizing`.
async fn run_command(config: &ExecResolvedConfig) -> Result<Zeroizing<String>> {
    let bin = config.command[0].clone();
    let args: Vec<String> = config.command.iter().skip(1).cloned().collect();
    let timeout = config.timeout;

    let output = tokio::time::timeout(
        timeout,
        tokio::process::Command::new(&bin)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await
    .map_err(|_| {
        ProxyError::ExecFetch(format!(
            "command timed out after {}s: {}",
            timeout.as_secs(),
            bin
        ))
    })?
    .map_err(|e| ProxyError::ExecFetch(format!("failed to spawn {}: {}", bin, e)))?;

    if !output.status.success() {
        let code = output
            .status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signal".to_string());
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        let suffix = if stderr.is_empty() {
            String::new()
        } else {
            format!(": {}", stderr)
        };
        return Err(ProxyError::ExecFetch(format!(
            "command exited {}: {}{}",
            code, bin, suffix
        )));
    }

    if output.stdout.len() > MAX_STDOUT_BYTES {
        return Err(ProxyError::ExecFetch(format!(
            "command stdout exceeds maximum size of {} bytes: {}",
            MAX_STDOUT_BYTES, bin
        )));
    }

    // Take ownership of the stdout buffer and zeroize-wrap as soon as we can.
    let raw = String::from_utf8(output.stdout).map_err(|e| {
        ProxyError::ExecFetch(format!(
            "command stdout is not valid UTF-8 ({}): {}",
            e, bin
        ))
    })?;
    let mut value = Zeroizing::new(raw);

    // Strip a single trailing line ending — match `load_secret_file` so the
    // semantics line up with file-backed credentials.
    if value.ends_with("\r\n") {
        let new_len = value.len().saturating_sub(2);
        value.truncate(new_len);
    } else if value.ends_with('\n') {
        let new_len = value.len().saturating_sub(1);
        value.truncate(new_len);
    }

    if value.is_empty() {
        return Err(ProxyError::ExecFetch(format!(
            "command produced empty stdout: {}",
            bin
        )));
    }

    // Reject any embedded CR/LF/NUL — these would let a helper splice
    // arbitrary headers into the upstream request when the value is spliced
    // into `credential_format` and written to the wire by build_exec_request.
    if value.contains('\r') || value.contains('\n') || value.contains('\0') {
        return Err(ProxyError::ExecFetch(format!(
            "command stdout contains a control character (CR/LF/NUL): {}",
            bin
        )));
    }

    Ok(value)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn cfg(command: Vec<&str>, ttl_secs: u64, timeout_secs: Option<u64>) -> ExecConfig {
        ExecConfig {
            command: command.into_iter().map(String::from).collect(),
            ttl_secs,
            timeout_secs,
        }
    }

    #[test]
    fn from_config_rejects_empty_argv() {
        let err = ExecResolvedConfig::from_config(&cfg(vec![], 60, None)).unwrap_err();
        assert!(matches!(err, ProxyError::Config(_)));
    }

    #[test]
    fn from_config_rejects_relative_path() {
        let err = ExecResolvedConfig::from_config(&cfg(vec!["ddtool"], 60, None)).unwrap_err();
        match err {
            ProxyError::Config(msg) => assert!(msg.contains("absolute path"), "got: {}", msg),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn from_config_rejects_zero_ttl() {
        let err =
            ExecResolvedConfig::from_config(&cfg(vec!["/bin/echo", "x"], 0, None)).unwrap_err();
        match err {
            ProxyError::Config(msg) => assert!(msg.contains("ttl_secs"), "got: {}", msg),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn from_config_uses_default_timeout_when_unset() {
        let resolved =
            ExecResolvedConfig::from_config(&cfg(vec!["/bin/echo", "x"], 60, None)).unwrap();
        assert_eq!(resolved.timeout, DEFAULT_TIMEOUT);
        assert_eq!(resolved.ttl, Duration::from_secs(60));
    }

    #[test]
    fn from_config_honours_explicit_timeout() {
        let resolved =
            ExecResolvedConfig::from_config(&cfg(vec!["/bin/echo", "x"], 60, Some(5))).unwrap();
        assert_eq!(resolved.timeout, Duration::from_secs(5));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_command_captures_stdout() {
        let resolved =
            ExecResolvedConfig::from_config(&cfg(vec!["/bin/echo", "fresh-token"], 60, Some(5)))
                .unwrap();
        let value = run_command(&resolved).await.unwrap();
        assert_eq!(value.as_str(), "fresh-token");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_command_strips_single_trailing_newline() {
        // /bin/echo always appends a newline; if we did not strip we'd get
        // "fresh\n".
        let resolved =
            ExecResolvedConfig::from_config(&cfg(vec!["/bin/echo", "-n", "fresh\n"], 60, Some(5)))
                .unwrap();
        let value = run_command(&resolved).await.unwrap();
        assert_eq!(value.as_str(), "fresh");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_command_accepts_valid_token() {
        let resolved = ExecResolvedConfig::from_config(&cfg(
            vec!["/bin/echo", "-n", "valid-token"],
            60,
            Some(5),
        ))
        .unwrap();
        let value = run_command(&resolved).await.unwrap();
        assert_eq!(value.as_str(), "valid-token");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_command_rejects_embedded_crlf() {
        // printf so we can splice raw \r\n bytes into stdout. The trailing
        // newline strip removes only the final \n, leaving the embedded CR/LF
        // pair to be caught by the control-character check.
        let resolved = ExecResolvedConfig::from_config(&cfg(
            vec!["/usr/bin/printf", "tok\r\nX-Injected: bad\n"],
            60,
            Some(5),
        ))
        .unwrap();
        let err = run_command(&resolved).await.unwrap_err();
        match err {
            ProxyError::ExecFetch(msg) => {
                assert!(msg.contains("control character"), "got: {}", msg)
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_command_rejects_embedded_nul() {
        let resolved = ExecResolvedConfig::from_config(&cfg(
            vec!["/usr/bin/printf", "tok\\0bad"],
            60,
            Some(5),
        ))
        .unwrap();
        let err = run_command(&resolved).await.unwrap_err();
        match err {
            ProxyError::ExecFetch(msg) => {
                assert!(msg.contains("control character"), "got: {}", msg)
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_command_rejects_empty_stdout() {
        let resolved =
            ExecResolvedConfig::from_config(&cfg(vec!["/usr/bin/true"], 60, Some(5))).unwrap();
        let err = run_command(&resolved).await.unwrap_err();
        match err {
            ProxyError::ExecFetch(msg) => assert!(msg.contains("empty"), "got: {}", msg),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_command_propagates_non_zero_exit() {
        let resolved =
            ExecResolvedConfig::from_config(&cfg(vec!["/usr/bin/false"], 60, Some(5))).unwrap();
        let err = run_command(&resolved).await.unwrap_err();
        match err {
            ProxyError::ExecFetch(msg) => assert!(msg.contains("exited"), "got: {}", msg),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_command_times_out() {
        let resolved =
            ExecResolvedConfig::from_config(&cfg(vec!["/bin/sleep", "5"], 60, Some(1))).unwrap();
        let err = run_command(&resolved).await.unwrap_err();
        match err {
            ProxyError::ExecFetch(msg) => assert!(msg.contains("timed out"), "got: {}", msg),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cache_returns_cached_value_within_ttl() {
        let resolved =
            ExecResolvedConfig::from_config(&cfg(vec!["/bin/echo", "v1"], 60, Some(5))).unwrap();
        let cache = ExecTokenCache::new_from_parts(resolved, "cached-v1", Duration::from_secs(60));
        let v = cache.get_or_refresh().await;
        assert_eq!(v.as_str(), "cached-v1");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cache_refreshes_when_expired() {
        // Pre-populate with a stale value that has already expired, then call
        // get_or_refresh — it should run the command and replace the value.
        let resolved =
            ExecResolvedConfig::from_config(&cfg(vec!["/bin/echo", "fresh-v2"], 60, Some(5)))
                .unwrap();
        let cache = ExecTokenCache::new_from_parts(resolved, "stale-v1", Duration::from_secs(0));

        // Sleep briefly so the pre-populated TTL is unambiguously past.
        tokio::time::sleep(Duration::from_millis(10)).await;

        let v = cache.get_or_refresh().await;
        assert_eq!(v.as_str(), "fresh-v2");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn force_refresh_bypasses_ttl_and_replaces_value() {
        // Pre-populate with a still-fresh value, then call force_refresh —
        // the configured command must run regardless of remaining TTL.
        let resolved =
            ExecResolvedConfig::from_config(&cfg(vec!["/bin/echo", "post-rotation"], 60, Some(5)))
                .unwrap();
        let cache =
            ExecTokenCache::new_from_parts(resolved, "pre-rotation", Duration::from_secs(3600));
        // Sanity: TTL is far in the future.
        let v = cache.get_or_refresh().await;
        assert_eq!(v.as_str(), "pre-rotation");

        // Force-refresh should re-run the command and replace the value
        // even though the cache wasn't expired.
        let v = cache.force_refresh().await;
        assert_eq!(v.as_str(), "post-rotation");

        // Subsequent get_or_refresh sees the new value.
        let v = cache.get_or_refresh().await;
        assert_eq!(v.as_str(), "post-rotation");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn force_refresh_returns_stale_when_command_fails() {
        // /usr/bin/false fails; force_refresh must hand back the stale value
        // rather than propagate the error.
        let resolved =
            ExecResolvedConfig::from_config(&cfg(vec!["/usr/bin/false"], 60, Some(5))).unwrap();
        let cache =
            ExecTokenCache::new_from_parts(resolved, "stale-but-usable", Duration::from_secs(3600));
        let v = cache.force_refresh().await;
        assert_eq!(v.as_str(), "stale-but-usable");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cache_returns_stale_value_when_refresh_fails() {
        // /usr/bin/false will fail at refresh time. The cache must hand back
        // the stale value rather than propagate the error.
        let resolved =
            ExecResolvedConfig::from_config(&cfg(vec!["/usr/bin/false"], 60, Some(5))).unwrap();
        let cache =
            ExecTokenCache::new_from_parts(resolved, "stale-but-usable", Duration::from_secs(0));

        tokio::time::sleep(Duration::from_millis(10)).await;

        let v = cache.get_or_refresh().await;
        assert_eq!(v.as_str(), "stale-but-usable");
    }
}
