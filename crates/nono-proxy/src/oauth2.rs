//! OAuth2 `client_credentials` token exchange and caching.
//!
//! Provides [`TokenCache`] — a thread-safe cache that holds an OAuth2 access
//! token and refreshes it on demand before expiry. Designed for the reverse
//! proxy credential injection flow where the agent never sees the real
//! client_id/client_secret.
//!
//! Cache lifecycle (TTL gating, write-lock dance, graceful degradation) is
//! delegated to [`crate::cache::TtlCache`]; this module just supplies the
//! fetcher closure that performs the OAuth2 token exchange.
//!
//! ## Design
//!
//! - **No background tasks**: Token validity is checked on each use via
//!   [`TokenCache::get_or_refresh()`]. If the cached token is about to expire
//!   (within 30 seconds), a synchronous refresh is attempted.
//! - **Graceful degradation**: If a refresh attempt fails but a stale token
//!   exists, the stale token is returned with a warning log. This avoids
//!   transient auth-server outages from cascading into request failures.
//! - **TLS via rustls**: Uses the same `webpki-roots` + `tokio-rustls` stack
//!   as the rest of the proxy. No additional HTTP client dependencies.

use crate::cache::{FetcherFn, FetcherFuture, TtlCache};
use crate::error::{ProxyError, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

/// Default TTL when the token endpoint omits `expires_in`.
const DEFAULT_EXPIRES_IN_SECS: u64 = 3600;

/// Timeout for the TCP connect + TLS handshake + HTTP exchange.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum response body size from the token endpoint (64 KiB).
const MAX_TOKEN_RESPONSE: usize = 64 * 1024;

// ────────────────────────────────────────────────────────────────────────────
// Public types
// ────────────────────────────────────────────────────────────────────────────

/// Resolved OAuth2 credentials ready for token exchange.
///
/// All secret fields use [`Zeroizing`] so they are zeroed on drop.
pub struct OAuth2ExchangeConfig {
    pub token_url: String,
    pub client_id: Zeroizing<String>,
    pub client_secret: Zeroizing<String>,
    pub scope: String,
}

/// Custom Debug that redacts secrets.
impl std::fmt::Debug for OAuth2ExchangeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuth2ExchangeConfig")
            .field("token_url", &self.token_url)
            .field("client_id", &"[REDACTED]")
            .field("client_secret", &"[REDACTED]")
            .field("scope", &self.scope)
            .finish()
    }
}

/// OAuth2 access-token cache with on-demand refresh.
///
/// A thin wrapper over [`TtlCache`] that knows how to build the fetcher
/// closure from an [`OAuth2ExchangeConfig`] + [`TlsConnector`].
#[derive(Debug)]
pub struct TokenCache {
    inner: TtlCache,
}

/// Build the fetcher closure that performs an OAuth2 token exchange and
/// returns `(access_token, expires_in)`.
fn build_fetcher(config: Arc<OAuth2ExchangeConfig>, tls_connector: TlsConnector) -> FetcherFn {
    Box::new(move || -> FetcherFuture {
        let config = config.clone();
        let tls = tls_connector.clone();
        Box::pin(async move { exchange_token(&config, &tls).await })
    })
}

impl TokenCache {
    /// Create a new cache and perform the **initial** token exchange.
    ///
    /// Called during [`CredentialStore::load()`](crate::credential::CredentialStore::load)
    /// which is synchronous. We bridge into async via
    /// [`tokio::runtime::Handle::current().block_on()`].
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::OAuth2Exchange`] if the initial exchange fails
    /// (DNS, TCP, TLS, non-200, malformed JSON). The calling code skips the
    /// route so the proxy can still start for other routes.
    pub fn new(config: OAuth2ExchangeConfig, tls_connector: TlsConnector) -> Result<Self> {
        let label = format!("oauth2:{}", config.token_url);
        let fetcher = build_fetcher(Arc::new(config), tls_connector);
        // OAuth2 has no force_refresh callers today, so the cooldown is moot;
        // ZERO keeps semantics unchanged if one is added later.
        let inner = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(TtlCache::new(
                label,
                Duration::ZERO,
                fetcher,
            ))
        })?;
        Ok(Self { inner })
    }

    /// Create a `TokenCache` with a pre-populated token (for testing).
    ///
    /// Skips the initial token exchange. Used by tests that need a cache
    /// without a real OAuth2 server.
    #[cfg(test)]
    pub(crate) fn new_from_parts(
        config: OAuth2ExchangeConfig,
        tls_connector: TlsConnector,
        token: &str,
        ttl: Duration,
    ) -> Self {
        let label = format!("oauth2:{}", config.token_url);
        let fetcher = build_fetcher(Arc::new(config), tls_connector);
        let inner = TtlCache::new_from_parts(label, Duration::ZERO, fetcher, token, ttl);
        Self { inner }
    }

    /// Return a valid access token, refreshing if needed.
    ///
    /// If the cached token is still valid (expires > 30 s from now), returns
    /// the cached value without any network call.
    ///
    /// If expired, attempts one exchange. On failure, returns the **stale**
    /// token with a warning — better to try a possibly-expired token than to
    /// fail the request outright.
    pub async fn get_or_refresh(&self) -> Zeroizing<String> {
        self.inner.get_or_refresh().await
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Token exchange (HTTP POST)
// ────────────────────────────────────────────────────────────────────────────

/// Perform a single `client_credentials` token exchange against the token
/// endpoint described in `config`.
///
/// Returns `(access_token, expires_in_duration)`.
async fn exchange_token(
    config: &OAuth2ExchangeConfig,
    tls_connector: &TlsConnector,
) -> Result<(Zeroizing<String>, Duration)> {
    let parsed = url::Url::parse(&config.token_url).map_err(|e| {
        ProxyError::OAuth2Exchange(format!("invalid token_url '{}': {}", config.token_url, e))
    })?;

    let scheme = parsed.scheme();
    let is_https = match scheme {
        "https" => true,
        "http" => false,
        other => {
            return Err(ProxyError::OAuth2Exchange(format!(
                "unsupported scheme '{}' in token_url",
                other
            )));
        }
    };

    let host = parsed
        .host_str()
        .ok_or_else(|| {
            ProxyError::OAuth2Exchange(format!("missing host in token_url '{}'", config.token_url))
        })?
        .to_string();

    let default_port: u16 = if is_https { 443 } else { 80 };
    let port = parsed.port().unwrap_or(default_port);
    let path = if parsed.path().is_empty() {
        "/"
    } else {
        parsed.path()
    };
    let path_with_query = match parsed.query() {
        Some(q) => format!("{}?{}", path, q),
        None => path.to_string(),
    };

    // ── Build form body ──────────────────────────────────────────────────
    let body = build_token_request_body(&config.client_id, &config.client_secret, &config.scope);

    // ── Build HTTP/1.1 request ───────────────────────────────────────────
    let request = Zeroizing::new(format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\n\
         Accept: application/json\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        path_with_query,
        host,
        body.len(),
        body.as_str()
    ));

    // ── TCP + optional TLS ───────────────────────────────────────────────
    let addr = format!("{}:{}", host, port);

    let response_bytes = tokio::time::timeout(EXCHANGE_TIMEOUT, async {
        let tcp = TcpStream::connect(&addr)
            .await
            .map_err(|e| ProxyError::OAuth2Exchange(format!("TCP connect to {}: {}", addr, e)))?;

        async fn send_and_read<S: tokio::io::AsyncWrite + tokio::io::AsyncRead + Unpin>(
            stream: &mut S,
            request: &[u8],
            host: &str,
        ) -> Result<Vec<u8>> {
            stream
                .write_all(request)
                .await
                .map_err(|e| ProxyError::OAuth2Exchange(format!("write to {}: {}", host, e)))?;
            stream
                .flush()
                .await
                .map_err(|e| ProxyError::OAuth2Exchange(format!("flush to {}: {}", host, e)))?;
            read_http_response(stream).await
        }

        if is_https {
            let server_name =
                rustls::pki_types::ServerName::try_from(host.clone()).map_err(|_| {
                    ProxyError::OAuth2Exchange(format!("invalid TLS server name: {}", host))
                })?;

            let mut tls = tls_connector.connect(server_name, tcp).await.map_err(|e| {
                ProxyError::OAuth2Exchange(format!("TLS handshake with {}: {}", host, e))
            })?;

            send_and_read(&mut tls, request.as_bytes(), &host).await
        } else {
            let mut tcp = tcp;
            send_and_read(&mut tcp, request.as_bytes(), &host).await
        }
    })
    .await
    .map_err(|_| ProxyError::OAuth2Exchange(format!("token exchange with {} timed out", addr)))??;

    // ── Parse HTTP response ──────────────────────────────────────────────
    let response_str = String::from_utf8(response_bytes).map_err(|_| {
        ProxyError::OAuth2Exchange("token endpoint returned non-UTF-8 response".to_string())
    })?;

    // Split headers from body
    let body_start = response_str
        .find("\r\n\r\n")
        .map(|i| i + 4)
        .or_else(|| response_str.find("\n\n").map(|i| i + 2))
        .ok_or_else(|| {
            ProxyError::OAuth2Exchange(
                "malformed HTTP response: no header/body separator".to_string(),
            )
        })?;

    // Check status code
    let status_line = response_str.lines().next().unwrap_or("");
    let status_code = parse_status_code(status_line);
    if !(200..300).contains(&status_code) {
        let body_preview: String = response_str[body_start..].chars().take(200).collect();
        return Err(ProxyError::OAuth2Exchange(format!(
            "token endpoint returned HTTP {}: {}",
            status_code, body_preview
        )));
    }

    let json_body = &response_str[body_start..];
    parse_token_response(json_body)
}

/// Read a full HTTP response from a stream up to [`MAX_TOKEN_RESPONSE`] bytes.
async fn read_http_response<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| ProxyError::OAuth2Exchange(format!("read response: {}", e)))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > MAX_TOKEN_RESPONSE {
            return Err(ProxyError::OAuth2Exchange(format!(
                "token response exceeds {} bytes",
                MAX_TOKEN_RESPONSE
            )));
        }
    }
    Ok(buf)
}

/// Parse the HTTP status code from the status line.
fn parse_status_code(line: &str) -> u16 {
    // "HTTP/1.1 200 OK" -> "200"
    let mut parts = line.split_whitespace();
    parts.nth(1).and_then(|code| code.parse().ok()).unwrap_or(0)
}

// ────────────────────────────────────────────────────────────────────────────
// Request / response helpers (pub(crate) for testing)
// ────────────────────────────────────────────────────────────────────────────

/// Build the `application/x-www-form-urlencoded` body for the token request.
///
/// The `scope` parameter is omitted when empty.
fn build_token_request_body(
    client_id: &str,
    client_secret: &str,
    scope: &str,
) -> Zeroizing<String> {
    let mut body = Zeroizing::new(format!(
        "grant_type=client_credentials&client_id={}&client_secret={}",
        urlencoding::encode(client_id),
        urlencoding::encode(client_secret),
    ));
    if !scope.is_empty() {
        body.push_str(&format!("&scope={}", urlencoding::encode(scope)));
    }
    body
}

/// Parse a standard OAuth2 token response JSON.
///
/// Expects `{"access_token": "...", "expires_in": 3600, ...}`.
/// - `access_token` is required.
/// - `expires_in` defaults to [`DEFAULT_EXPIRES_IN_SECS`] if missing.
fn parse_token_response(json: &str) -> Result<(Zeroizing<String>, Duration)> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|e| {
        ProxyError::OAuth2Exchange(format!("invalid JSON from token endpoint: {}", e))
    })?;

    let access_token = value
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ProxyError::OAuth2Exchange("token response missing 'access_token' field".to_string())
        })?;

    let expires_in_secs = value
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_EXPIRES_IN_SECS);

    Ok((
        Zeroizing::new(access_token.to_string()),
        Duration::from_secs(expires_in_secs),
    ))
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // ── parse_token_response ─────────────────────────────────────────────

    #[test]
    fn test_parse_token_response_success() {
        let json =
            r#"{"access_token":"eyJhbGciOiJSUzI1NiJ9","token_type":"Bearer","expires_in":3600}"#;
        let (token, expires) = parse_token_response(json).unwrap();
        assert_eq!(token.as_str(), "eyJhbGciOiJSUzI1NiJ9");
        assert_eq!(expires, Duration::from_secs(3600));
    }

    #[test]
    fn test_parse_token_response_missing_expires_defaults() {
        let json = r#"{"access_token":"tok_abc","token_type":"Bearer"}"#;
        let (token, expires) = parse_token_response(json).unwrap();
        assert_eq!(token.as_str(), "tok_abc");
        assert_eq!(expires, Duration::from_secs(DEFAULT_EXPIRES_IN_SECS));
    }

    #[test]
    fn test_parse_token_response_missing_access_token_errors() {
        let json = r#"{"token_type":"Bearer","expires_in":3600}"#;
        let err = parse_token_response(json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("access_token"),
            "error should mention access_token: {}",
            msg
        );
    }

    #[test]
    fn test_parse_token_response_non_json_errors() {
        let err = parse_token_response("this is not json").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("invalid JSON"),
            "error should mention invalid JSON: {}",
            msg
        );
    }

    // ── build_token_request_body ─────────────────────────────────────────

    #[test]
    fn test_build_token_request_body() {
        let body = build_token_request_body("my-client", "s3cret!", "read write");
        assert!(body.contains("grant_type=client_credentials"));
        assert!(body.contains("client_id=my-client"));
        assert!(body.contains("client_secret=s3cret%21"));
        assert!(body.contains("scope=read%20write"));
    }

    #[test]
    fn test_build_token_request_body_no_scope() {
        let body = build_token_request_body("cid", "csec", "");
        assert!(body.contains("grant_type=client_credentials"));
        assert!(body.contains("client_id=cid"));
        assert!(body.contains("client_secret=csec"));
        assert!(!body.contains("scope="), "empty scope should be omitted");
    }

    // ── parse_status_code ────────────────────────────────────────────────

    #[test]
    fn test_parse_status_code_200() {
        assert_eq!(parse_status_code("HTTP/1.1 200 OK"), 200);
    }

    #[test]
    fn test_parse_status_code_401() {
        assert_eq!(parse_status_code("HTTP/1.1 401 Unauthorized"), 401);
    }

    #[test]
    fn test_parse_status_code_garbage() {
        assert_eq!(parse_status_code("not http"), 0);
    }

    // ── TokenCache expiry logic ──────────────────────────────────────────

    #[tokio::test]
    async fn test_token_cache_returns_valid_token() {
        // Construct a cache with a token that expires far in the future.
        let cache = make_test_cache("valid_token", Duration::from_secs(3600));
        let token = cache.get_or_refresh().await;
        assert_eq!(token.as_str(), "valid_token");
    }

    #[tokio::test]
    async fn test_token_cache_detects_expiry() {
        // Token whose TTL is already zero. The fetcher (pointing at a
        // non-routable address) will fail, so graceful degradation should
        // hand back the stale token.
        let cache = make_test_cache("stale_token", Duration::ZERO);
        // Sleep briefly so the pre-populated TTL is unambiguously past.
        tokio::time::sleep(Duration::from_millis(10)).await;
        let token = cache.get_or_refresh().await;
        assert_eq!(token.as_str(), "stale_token");
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    /// Build a `TokenCache` with a pre-populated token for unit tests.
    /// The `exchange_token` config points to a non-routable address so any
    /// actual exchange attempt will fail (which is fine — we test cache logic).
    fn make_test_cache(token: &str, ttl: Duration) -> TokenCache {
        let config = OAuth2ExchangeConfig {
            token_url: "https://127.0.0.1:1/oauth/token".to_string(),
            client_id: Zeroizing::new("test-client".to_string()),
            client_secret: Zeroizing::new("test-secret".to_string()),
            scope: String::new(),
        };

        // Build a minimal TLS connector (never actually used in these tests).
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
        let tls_connector = TlsConnector::from(Arc::new(tls_config));

        TokenCache::new_from_parts(config, tls_connector, token, ttl)
    }
}
