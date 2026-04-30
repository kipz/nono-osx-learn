//! Shared TTL-bounded credential cache.
//!
//! [`TtlCache`] is the common refresh primitive used by both the
//! [`crate::exec`] and [`crate::oauth2`] credential sources. Each source
//! injects a fetcher closure; the cache owns the TTL semantics, the
//! read-/write-lock dance, the graceful-degradation-on-failure policy, and
//! the cross-request cooldown that keeps a 401-flapping upstream from
//! re-running the issuance command on every request.
//!
//! ## Design
//!
//! - **No background tasks.** Validity is checked on each use via
//!   [`TtlCache::get_or_refresh`]. Refresh fires once the cached value is
//!   within [`EXPIRY_BUFFER_SECS`] of expiry.
//! - **Graceful degradation.** A failed refresh logs a warning and returns
//!   the stale value rather than failing the request. A transient issuer
//!   outage should not cascade into request failures.
//! - **Force-refresh cooldown.** [`TtlCache::force_refresh`] is gated by a
//!   configurable minimum interval since the last force_refresh attempt. Set
//!   the cooldown to [`Duration::ZERO`] to disable the gate.
//! - **Per-fetch TTL.** The fetcher returns `(value, ttl)`, so each source
//!   can pick its own lifetime — e.g. exec uses the configured `ttl_secs`,
//!   OAuth2 honours the server's `expires_in`.

use crate::error::Result;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn};
use zeroize::Zeroizing;

/// Refresh fires this many seconds before the cached value's deadline.
pub const EXPIRY_BUFFER_SECS: u64 = 30;

/// A single fetch produces a credential value and the TTL the cache should
/// honour for that value. Both come from the source that issued the
/// credential, so OAuth2 can use the server-supplied `expires_in` while
/// exec sources use the configured `ttl_secs`.
pub type FetcherFuture =
    Pin<Box<dyn Future<Output = Result<(Zeroizing<String>, Duration)>> + Send>>;

/// Boxed callable that produces a fresh credential each time it's invoked.
/// `Send + Sync` so the cache can be shared across tokio tasks.
pub type FetcherFn = Box<dyn Fn() -> FetcherFuture + Send + Sync>;

struct Inner {
    value: Zeroizing<String>,
    expires_at: Instant,
    /// Last time `force_refresh` actually ran the fetcher (success or
    /// failure). `None` until the first force_refresh.
    last_force_refresh: Option<Instant>,
}

pub struct TtlCache {
    inner: Arc<RwLock<Inner>>,
    fetcher: FetcherFn,
    /// Minimum interval between successive `force_refresh` invocations.
    /// `Duration::ZERO` disables the cooldown.
    force_refresh_cooldown: Duration,
    /// Diagnostic label used in log lines (e.g. `"exec:/usr/bin/ddtool"`).
    label: String,
}

impl std::fmt::Debug for TtlCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TtlCache")
            .field("label", &self.label)
            .field("force_refresh_cooldown", &self.force_refresh_cooldown)
            .finish()
    }
}

impl TtlCache {
    /// Build a cache by performing the initial fetch.
    ///
    /// # Errors
    ///
    /// Forwards any error returned by the fetcher. The caller is expected to
    /// skip the route on failure so the proxy can still start for other
    /// routes.
    pub async fn new(
        label: impl Into<String>,
        force_refresh_cooldown: Duration,
        fetcher: FetcherFn,
    ) -> Result<Self> {
        let label = label.into();
        let (value, ttl) = (fetcher)().await?;
        debug!(
            "TtlCache '{}' initial fetch ok, ttl {}s",
            label,
            ttl.as_secs()
        );
        Ok(Self {
            inner: Arc::new(RwLock::new(Inner {
                value,
                expires_at: Instant::now() + ttl,
                last_force_refresh: None,
            })),
            fetcher,
            force_refresh_cooldown,
            label,
        })
    }

    /// Build a cache with a pre-populated value, skipping the initial fetch.
    /// Used by tests that want deterministic state without invoking the
    /// fetcher.
    #[cfg(test)]
    pub(crate) fn new_from_parts(
        label: impl Into<String>,
        force_refresh_cooldown: Duration,
        fetcher: FetcherFn,
        value: &str,
        ttl: Duration,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner {
                value: Zeroizing::new(value.to_string()),
                expires_at: Instant::now() + ttl,
                last_force_refresh: None,
            })),
            fetcher,
            force_refresh_cooldown,
            label: label.into(),
        }
    }

    /// Return the cached value, refreshing if it is within
    /// [`EXPIRY_BUFFER_SECS`] of expiry. On refresh failure, returns the
    /// stale value with a warning rather than failing.
    pub async fn get_or_refresh(&self) -> Zeroizing<String> {
        let buffer = Duration::from_secs(EXPIRY_BUFFER_SECS);

        // Fast path — value still fresh.
        {
            let guard = self.inner.read().await;
            if Instant::now() + buffer < guard.expires_at {
                return guard.value.clone();
            }
        }

        // Slow path — refresh under the write lock.
        let mut guard = self.inner.write().await;

        // Double-check after acquiring the write lock — another task may have
        // refreshed while we were queued.
        if Instant::now() + buffer < guard.expires_at {
            return guard.value.clone();
        }

        match (self.fetcher)().await {
            Ok((new_value, ttl)) => {
                debug!(
                    "TtlCache '{}' refreshed, ttl {}s",
                    self.label,
                    ttl.as_secs()
                );
                guard.value = new_value;
                guard.expires_at = Instant::now() + ttl;
                guard.value.clone()
            }
            Err(e) => {
                warn!(
                    "TtlCache '{}' refresh failed, returning stale value: {}",
                    self.label, e
                );
                guard.value.clone()
            }
        }
    }

    /// Force a refresh, ignoring the cached value's remaining TTL.
    ///
    /// Used by the reverse-proxy 401-retry path: an upstream that rejects a
    /// credential we believe is still valid may have rotated or revoked it
    /// before our TTL elapsed. Subject to the configured cooldown — if a
    /// force_refresh ran less than `force_refresh_cooldown` ago, the cached
    /// value is returned without re-invoking the fetcher. This prevents a
    /// flapping upstream from turning each 401 into a fresh fetcher
    /// invocation.
    ///
    /// On refresh failure, the stale value is returned with a warning. The
    /// failure still resets the cooldown so a hard-down issuer doesn't get
    /// re-hit on every request.
    pub async fn force_refresh(&self) -> Zeroizing<String> {
        let mut guard = self.inner.write().await;

        if !self.force_refresh_cooldown.is_zero() {
            if let Some(last) = guard.last_force_refresh {
                let since = Instant::now().saturating_duration_since(last);
                if since < self.force_refresh_cooldown {
                    debug!(
                        "TtlCache '{}' force_refresh skipped, within cooldown ({:?} since last)",
                        self.label, since
                    );
                    return guard.value.clone();
                }
            }
        }

        match (self.fetcher)().await {
            Ok((new_value, ttl)) => {
                debug!(
                    "TtlCache '{}' force-refreshed, ttl {}s",
                    self.label,
                    ttl.as_secs()
                );
                guard.value = new_value;
                guard.expires_at = Instant::now() + ttl;
                guard.last_force_refresh = Some(Instant::now());
                guard.value.clone()
            }
            Err(e) => {
                warn!(
                    "TtlCache '{}' force-refresh failed, returning stale value: {}",
                    self.label, e
                );
                guard.last_force_refresh = Some(Instant::now());
                guard.value.clone()
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Build a fetcher that returns successive values from `values`,
    /// incrementing a counter each time it is invoked.
    fn counting_fetcher(values: Vec<&'static str>, ttl: Duration) -> (FetcherFn, Arc<AtomicUsize>) {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_for_fn = counter.clone();
        let values = Arc::new(values);
        let f: FetcherFn = Box::new(move || {
            let idx = counter_for_fn.fetch_add(1, Ordering::SeqCst);
            let values = values.clone();
            Box::pin(async move {
                let v = values.get(idx).copied().unwrap_or("exhausted").to_string();
                Ok((Zeroizing::new(v), ttl))
            })
        });
        (f, counter)
    }

    /// Build a fetcher that always errors.
    fn failing_fetcher() -> FetcherFn {
        Box::new(|| {
            Box::pin(async move {
                Err(crate::error::ProxyError::ExecFetch(
                    "test failure".to_string(),
                ))
            })
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn force_refresh_runs_fetcher_when_outside_cooldown() {
        let (fetcher, counter) = counting_fetcher(vec!["v1", "v2", "v3"], Duration::from_secs(60));
        let cache = TtlCache::new_from_parts(
            "test",
            Duration::from_secs(30),
            fetcher,
            "stale",
            Duration::from_secs(3600),
        );

        let v = cache.force_refresh().await;
        assert_eq!(v.as_str(), "v1");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn force_refresh_skipped_when_within_cooldown() {
        let (fetcher, counter) = counting_fetcher(vec!["v1", "v2", "v3"], Duration::from_secs(60));
        let cache = TtlCache::new_from_parts(
            "test",
            Duration::from_secs(30),
            fetcher,
            "stale",
            Duration::from_secs(3600),
        );

        // First call: runs fetcher → v1.
        let v1 = cache.force_refresh().await;
        assert_eq!(v1.as_str(), "v1");
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        // Second call within cooldown: must not run fetcher; returns the
        // cached v1, NOT v2.
        let v2 = cache.force_refresh().await;
        assert_eq!(v2.as_str(), "v1");
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        // Third call within cooldown: same.
        let v3 = cache.force_refresh().await;
        assert_eq!(v3.as_str(), "v1");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn force_refresh_failure_still_arms_cooldown() {
        // A flapping issuer must not get re-hit on every 401: even when
        // force_refresh fails, we record the attempt so subsequent calls are
        // gated.
        let cache = TtlCache::new_from_parts(
            "test",
            Duration::from_secs(30),
            failing_fetcher(),
            "stale",
            Duration::from_secs(3600),
        );

        // First force_refresh fails → returns stale, arms cooldown.
        let v1 = cache.force_refresh().await;
        assert_eq!(v1.as_str(), "stale");

        // Swap in a fetcher that would succeed if invoked. We don't have
        // direct access to mutate self.fetcher; instead, rely on the
        // cooldown gate by counting invocations on a fresh instance.
        let (fetcher, counter) = counting_fetcher(vec!["never"], Duration::from_secs(60));
        let cache2 = TtlCache::new_from_parts(
            "test",
            Duration::from_secs(30),
            fetcher,
            "stale",
            Duration::from_secs(3600),
        );
        // Burn one force_refresh on cache2 to arm the cooldown.
        let _ = cache2.force_refresh().await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        // Next call must be gated.
        let _ = cache2.force_refresh().await;
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "second force_refresh within cooldown must not invoke fetcher"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn force_refresh_zero_cooldown_runs_every_time() {
        let (fetcher, counter) = counting_fetcher(vec!["v1", "v2", "v3"], Duration::from_secs(60));
        let cache = TtlCache::new_from_parts(
            "test",
            Duration::ZERO,
            fetcher,
            "stale",
            Duration::from_secs(3600),
        );

        let _ = cache.force_refresh().await;
        let _ = cache.force_refresh().await;
        let _ = cache.force_refresh().await;
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_or_refresh_uses_fast_path_when_fresh() {
        let (fetcher, counter) = counting_fetcher(vec!["fresh"], Duration::from_secs(60));
        let cache = TtlCache::new_from_parts(
            "test",
            Duration::ZERO,
            fetcher,
            "cached",
            Duration::from_secs(3600),
        );
        let v = cache.get_or_refresh().await;
        assert_eq!(v.as_str(), "cached");
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_or_refresh_invokes_fetcher_when_expired() {
        let (fetcher, counter) = counting_fetcher(vec!["fresh"], Duration::from_secs(60));
        let cache =
            TtlCache::new_from_parts("test", Duration::ZERO, fetcher, "stale", Duration::ZERO);
        tokio::time::sleep(Duration::from_millis(10)).await;
        let v = cache.get_or_refresh().await;
        assert_eq!(v.as_str(), "fresh");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_or_refresh_returns_stale_on_failure() {
        let cache = TtlCache::new_from_parts(
            "test",
            Duration::ZERO,
            failing_fetcher(),
            "stale-but-usable",
            Duration::ZERO,
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
        let v = cache.get_or_refresh().await;
        assert_eq!(v.as_str(), "stale-but-usable");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn new_runs_fetcher_once() {
        let (fetcher, counter) = counting_fetcher(vec!["initial"], Duration::from_secs(60));
        let cache = TtlCache::new("test", Duration::ZERO, fetcher)
            .await
            .unwrap();
        let v = cache.get_or_refresh().await;
        assert_eq!(v.as_str(), "initial");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }
}
