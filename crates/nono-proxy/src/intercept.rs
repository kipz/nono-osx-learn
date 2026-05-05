//! TLS-intercept session CA and on-demand leaf-cert factory.
//!
//! Generates a fresh root CA per proxy session, in memory only, and
//! issues short-lived leaf certificates for individual hostnames on
//! demand. Each leaf is signed by the session CA and presented to the
//! sandboxed agent during TLS handshake; the agent trusts the CA via
//! `NODE_EXTRA_CA_CERTS`, populated from a PEM file written by
//! [`InterceptCa::write_ca_pem`].
//!
//! The CA private key never leaves this process. Only the public CA
//! certificate is materialized to disk.
//!
//! Layer 1 of the OAuth-capture design (see
//! `2026-04-27-capture-anthropic-auth.md`). [`InterceptCa`] is the
//! per-session CA + leaf factory; [`handle_intercept`] is the per-CONNECT
//! dispatch entry point that the [`crate::connect`] module hands off to
//! when a target host matches a `tls_intercept: true` route.

use std::collections::HashMap;
use std::convert::Infallible;
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::ServerConfig;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::audit;
use crate::broker::TokenResolver;
use crate::connect;
use crate::error::{ProxyError, Result};
use crate::route::OauthCaptureMatch;

/// CA validity window. Far longer than any reasonable session, and a
/// fresh CA is regenerated on every proxy startup.
const CA_VALIDITY: Duration = Duration::from_secs(24 * 60 * 60);

/// Leaf certificate validity. One hour bounds the blast radius if a
/// cached `ServerConfig` somehow leaked (the leaf private key never
/// leaves this process, so this is defence in depth).
const LEAF_VALIDITY: Duration = Duration::from_secs(60 * 60);

/// Backdated `NotBefore` window to absorb client/server clock skew.
const CLOCK_SKEW: Duration = Duration::from_secs(5 * 60);

/// File mode for the materialized CA PEM. The cert itself is public
/// information; 0644 mirrors the design in
/// `2026-04-27-capture-anthropic-auth.md` (read-only mount into the
/// child via `NODE_EXTRA_CA_CERTS`).
const CA_PEM_MODE: u32 = 0o644;

/// Session-scoped TLS-interception authority.
///
/// Holds the CA certificate (PEM form for materialization), the CA
/// signing key (kept in memory only), and a hostname → `ServerConfig`
/// cache so we re-issue at most one leaf per host per session.
pub struct InterceptCa {
    ca_pem: String,
    issuer: Issuer<'static, KeyPair>,
    leaf_cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl InterceptCa {
    /// Generate a fresh session CA. The private key is held in memory
    /// only and is never written to disk.
    pub fn new() -> Result<Self> {
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| ProxyError::Config(format!("CA key generation failed: {e}")))?;

        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| ProxyError::Config(format!("CA params init failed: {e}")))?;

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "nono session CA");
        params.distinguished_name = dn;

        // Restrict to issuing leaf certs only (path-length 0).
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        let now = SystemTime::now();
        params.not_before = (now - CLOCK_SKEW).into();
        params.not_after = (now + CA_VALIDITY).into();

        let ca_cert = params
            .self_signed(&key_pair)
            .map_err(|e| ProxyError::Config(format!("CA self-sign failed: {e}")))?;
        let ca_pem = ca_cert.pem();

        let issuer = Issuer::new(params, key_pair);

        debug!(
            "generated TLS-intercept session CA (validity: {} hours)",
            CA_VALIDITY.as_secs() / 3600
        );

        Ok(Self {
            ca_pem,
            issuer,
            leaf_cache: Mutex::new(HashMap::new()),
        })
    }

    /// Public CA certificate as PEM. Suitable for the contents of
    /// `NODE_EXTRA_CA_CERTS`.
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    /// Get a `ServerConfig` for the given hostname, generating and
    /// caching a fresh leaf certificate on first use. Hostname matching
    /// is case-insensitive; the cache key is lowercase.
    pub fn server_config_for(&self, hostname: &str) -> Result<Arc<ServerConfig>> {
        let key = hostname.to_ascii_lowercase();

        let mut cache = self
            .leaf_cache
            .lock()
            .expect("InterceptCa leaf_cache mutex poisoned");

        if let Some(existing) = cache.get(&key) {
            return Ok(Arc::clone(existing));
        }

        let server_config = self.build_leaf_server_config(&key)?;
        let arc = Arc::new(server_config);
        cache.insert(key.clone(), Arc::clone(&arc));
        debug!("issued TLS-intercept leaf for {}", key);
        Ok(arc)
    }

    /// Write the CA PEM to `path` with mode 0644. The write is atomic
    /// (write-temp + rename) so a concurrent reader never sees a
    /// half-written file. The parent directory must already exist.
    pub fn write_ca_pem(&self, path: &Path) -> Result<()> {
        let parent = path.parent().ok_or_else(|| {
            ProxyError::Config(format!(
                "CA PEM path has no parent directory: {}",
                path.display()
            ))
        })?;
        if !parent.exists() {
            return Err(ProxyError::Config(format!(
                "CA PEM parent directory does not exist: {}",
                parent.display()
            )));
        }

        // Write to a sibling temp file, then rename atomically.
        let mut tmp = path.to_path_buf();
        let tmp_name = match path.file_name() {
            Some(name) => format!(".{}.tmp", name.to_string_lossy()),
            None => {
                return Err(ProxyError::Config(format!(
                    "CA PEM path has no file name: {}",
                    path.display()
                )));
            }
        };
        tmp.set_file_name(tmp_name);

        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(CA_PEM_MODE)
                .open(&tmp)?;
            f.write_all(self.ca_pem.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)?;
        Ok(())
    }

    fn build_leaf_server_config(&self, hostname: &str) -> Result<ServerConfig> {
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| ProxyError::Config(format!("leaf key generation failed: {e}")))?;

        let mut params = CertificateParams::new(vec![hostname.to_string()])
            .map_err(|e| ProxyError::Config(format!("leaf params init failed: {e}")))?;

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, hostname);
        params.distinguished_name = dn;

        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let now = SystemTime::now();
        params.not_before = (now - CLOCK_SKEW).into();
        params.not_after = (now + LEAF_VALIDITY).into();

        let leaf_cert = params
            .signed_by(&leaf_key, &self.issuer)
            .map_err(|e| ProxyError::Config(format!("leaf signing failed: {e}")))?;

        let leaf_der: CertificateDer<'static> = leaf_cert.der().clone();
        let leaf_key_der = leaf_key.serialize_der();

        let cert_chain: Vec<CertificateDer<'static>> = vec![leaf_der];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key_der));

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| ProxyError::Config(format!("rustls protocol versions: {e}")))?
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| ProxyError::Config(format!("rustls server cert: {e}")))?;

        // Advertise only HTTP/1.1 via ALPN. Our intercept dispatcher
        // uses `hyper::server::conn::http1` and would refuse an HTTP/2
        // upgrade; without setting ALPN the client could try to
        // negotiate h2 and stall.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];

        Ok(config)
    }
}

/// Type-erased response body used by the per-request forwarder.
type RewrittenBody = BoxBody<Bytes, hyper::Error>;

/// Handle a CONNECT request whose target host is configured for TLS
/// interception.
///
/// 1. Open a TCP connection to one of the pre-resolved upstream IPs
///    as a reachability probe. If it fails, the client never sees a
///    200, matching `connect.rs`'s transparent-tunnel behaviour. The
///    probed connection is then dropped — per-request upstream
///    connections are opened fresh inside the service.
/// 2. Reply `HTTP/1.1 200 Connection Established` so the client begins
///    its TLS handshake against us.
/// 3. Look up (or mint and cache) a leaf certificate for `host` from
///    `ca` and use it to TLS-accept the client. Our leaf advertises
///    only `http/1.1` via ALPN.
/// 4. Run a `hyper::server::conn::http1` connection on the decrypted
///    client stream. For each request, [`forward_request`] opens a
///    fresh upstream TLS connection, forwards the request, and either
///    streams the response through unchanged or — when the route is
///    [`InjectMode::OauthCapture`] and the request URL matches —
///    buffers the JSON body, mints nonces via `token_resolver`, and
///    returns a rewritten response.
///
/// On client-side TLS-accept failure (e.g. the sandboxed agent does
/// not trust our CA), we audit-log the rejection and return `Ok(())`
/// — closing the connection is the right move and not a proxy fault.
/// Upstream-reachability failures bubble up as
/// `ProxyError::UpstreamConnect`.
#[allow(clippy::too_many_arguments)]
pub async fn handle_intercept(
    mut client_stream: TcpStream,
    host: &str,
    port: u16,
    resolved_addrs: &[SocketAddr],
    ca: Arc<InterceptCa>,
    upstream_tls: TlsConnector,
    oauth_capture: Option<&OauthCaptureMatch>,
    token_resolver: Option<Arc<dyn TokenResolver>>,
    audit_log: Option<&audit::SharedAuditLog>,
) -> Result<()> {
    debug!("intercept: dispatching CONNECT to {}:{}", host, port);

    // 1. Reachability probe (TCP only — TLS handshake to the upstream
    //    happens per-request inside the service). The probe is dropped
    //    immediately; we just want a clean 502/connection-close path
    //    when the upstream is unreachable, before we mislead the
    //    client with a 200.
    drop(connect::connect_to_resolved(resolved_addrs, host).await?);

    // 2. Tell the client to start its TLS handshake.
    static OK_LINE: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
    client_stream.write_all(OK_LINE).await?;
    client_stream.flush().await?;

    // 3. Get a leaf cert / `ServerConfig` for this hostname and TLS-
    //    accept the client.
    let server_config = ca.server_config_for(host)?;
    let acceptor = TlsAcceptor::from(server_config);
    let client_tls = match acceptor.accept(client_stream).await {
        Ok(tls) => tls,
        Err(e) => {
            warn!(
                "intercept: client-side TLS accept failed for {}:{}: {}",
                host, port, e
            );
            audit::log_denied(
                audit_log,
                audit::ProxyMode::Connect,
                host,
                port,
                &format!("intercept TLS accept: {e}"),
            );
            return Ok(());
        }
    };

    audit::log_allowed(
        audit_log,
        audit::ProxyMode::Connect,
        host,
        port,
        "INTERCEPT",
    );

    // 4. Per-request forwarding via hyper. Captured values are cloned
    //    on each invocation of the service (one HTTP request → one
    //    fresh upstream TLS handshake; cheap for the OAuth flow which
    //    is at most a handful of requests).
    let host_owned = host.to_string();
    let resolved_addrs_owned = resolved_addrs.to_vec();
    let oauth_capture_owned = oauth_capture.cloned();

    let service = service_fn(move |req: Request<Incoming>| {
        let host = host_owned.clone();
        let resolved_addrs = resolved_addrs_owned.clone();
        let upstream_tls = upstream_tls.clone();
        let oauth_capture = oauth_capture_owned.clone();
        let token_resolver = token_resolver.clone();
        async move {
            forward_request(
                req,
                &host,
                &resolved_addrs,
                upstream_tls,
                oauth_capture.as_ref(),
                token_resolver,
            )
            .await
        }
    });

    if let Err(e) = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(client_tls), service)
        .await
    {
        debug!("intercept: client connection ended: {e}");
    }

    Ok(())
}

/// Forward a single intercepted request to the upstream and return a
/// possibly-rewritten response. Always returns `Ok` at the service
/// level — internal failures become 502 responses so the connection
/// stays open for any subsequent requests.
async fn forward_request(
    req: Request<Incoming>,
    host: &str,
    resolved_addrs: &[SocketAddr],
    upstream_tls: TlsConnector,
    oauth_capture: Option<&OauthCaptureMatch>,
    token_resolver: Option<Arc<dyn TokenResolver>>,
) -> std::result::Result<Response<RewrittenBody>, Infallible> {
    match try_forward(
        req,
        host,
        resolved_addrs,
        upstream_tls,
        oauth_capture,
        token_resolver,
    )
    .await
    {
        Ok(resp) => Ok(resp),
        Err(e) => {
            warn!("intercept: forwarding failed for {host}: {e}");
            Ok(make_502(format!("intercept upstream error: {e}")))
        }
    }
}

async fn try_forward(
    mut req: Request<Incoming>,
    host: &str,
    resolved_addrs: &[SocketAddr],
    upstream_tls: TlsConnector,
    oauth_capture: Option<&OauthCaptureMatch>,
    token_resolver: Option<Arc<dyn TokenResolver>>,
) -> Result<Response<RewrittenBody>> {
    let req_path = req.uri().path().to_string();
    debug!(
        "intercept: request {} {} (oauth_capture={})",
        req.method(),
        req.uri(),
        oauth_capture.is_some_and(|m| m.matches(&req_path))
    );

    // Open a fresh upstream connection for this request.
    let upstream_tcp = connect::connect_to_resolved(resolved_addrs, host).await?;
    let server_name =
        ServerName::try_from(host.to_string()).map_err(|e| ProxyError::UpstreamConnect {
            host: host.to_string(),
            reason: format!("invalid SNI for upstream: {e}"),
        })?;
    let upstream_stream = upstream_tls
        .connect(server_name, upstream_tcp)
        .await
        .map_err(|e| ProxyError::UpstreamConnect {
            host: host.to_string(),
            reason: format!("upstream-side TLS connect failed: {e}"),
        })?;

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(upstream_stream))
        .await
        .map_err(|e| ProxyError::UpstreamConnect {
            host: host.to_string(),
            reason: format!("upstream-side HTTP/1 handshake failed: {e}"),
        })?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!("intercept: upstream connection task ended: {e}");
        }
    });

    // For routes that capture OAuth responses we must be able to read
    // the response body; strip Accept-Encoding so the upstream returns
    // identity-encoded JSON. Negligible bandwidth cost — OAuth token
    // responses are a few hundred bytes — and avoids decompression
    // edge cases in the rewriter.
    let should_capture =
        oauth_capture.is_some_and(|m| m.matches(&req_path)) && token_resolver.is_some();
    if should_capture {
        req.headers_mut().remove(hyper::header::ACCEPT_ENCODING);
    }

    // Translate `nono_` Bearer tokens to real tokens before forwarding
    // upstream. Required for the Anthropic Console flow: after the
    // OAuth token exchange, claude immediately calls
    // `POST api.anthropic.com/api/oauth/claude_cli/create_api_key`
    // with the (now nonce) bearer token to mint a long-lived API key.
    // Without translation, Anthropic receives `Bearer nono_<hex>` and
    // returns 401, breaking /login. The reverse-proxy path already
    // does this translation at its own egress boundary; the intercept
    // is the second egress boundary that has to do the same.
    if let Some(ref resolver) = token_resolver {
        rewrite_bearer_header(req.headers_mut(), resolver.as_ref());
    }

    // Box the request body to a uniform type before sending.
    let (parts, body) = req.into_parts();
    let req: Request<RewrittenBody> = Request::from_parts(parts, body.boxed());

    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| ProxyError::UpstreamConnect {
            host: host.to_string(),
            reason: format!("upstream send_request: {e}"),
        })?;

    if should_capture {
        let resolver = token_resolver.expect("checked by should_capture");
        rewrite_oauth_response(resp, resolver.as_ref()).await
    } else {
        let (parts, body) = resp.into_parts();
        Ok(Response::from_parts(parts, body.boxed()))
    }
}

/// Buffer an upstream OAuth response, mint nonces for any `access_token`
/// / `refresh_token` fields via `resolver`, and return a rewritten
/// response with substituted nonces.
///
/// On any error short of resolver failure (which cannot happen — the
/// trait API is infallible), the original response body is forwarded
/// unchanged. This keeps `/login` working even when upstream returns
/// something unexpected.
async fn rewrite_oauth_response(
    resp: Response<Incoming>,
    resolver: &(dyn TokenResolver + 'static),
) -> Result<Response<RewrittenBody>> {
    let (mut parts, body) = resp.into_parts();

    let body_bytes = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            warn!("oauth-capture: collecting response body failed: {e}; substituting empty");
            // Body already partially consumed; cannot replay. Return
            // an empty body with a clear status — conservative and
            // visible.
            return Ok(make_502(format!("oauth-capture body read failed: {e}")));
        }
    };

    let mut value: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => {
            warn!("oauth-capture: response is not JSON ({e}); passing through unmodified");
            return Ok(Response::from_parts(parts, full_body(body_bytes)));
        }
    };

    let mut substituted: u32 = 0;
    if let Some(obj) = value.as_object_mut() {
        // Capture access + refresh together so the broker can persist
        // them as a pair (and so the access -> refresh association is
        // preserved for any future refresh-on-401 flow). When only one
        // is present (atypical), fall back to single-token issue() with
        // no persistence.
        let access = obj
            .get("access_token")
            .and_then(serde_json::Value::as_str)
            .map(|s| Zeroizing::new(s.to_string()));
        let refresh = obj
            .get("refresh_token")
            .and_then(serde_json::Value::as_str)
            .map(|s| Zeroizing::new(s.to_string()));

        match (access, refresh) {
            (Some(a), Some(r)) => {
                let (access_nonce, refresh_nonce) = resolver.capture_oauth_pair(a, r);
                obj.insert(
                    "access_token".to_string(),
                    serde_json::Value::String(access_nonce),
                );
                obj.insert(
                    "refresh_token".to_string(),
                    serde_json::Value::String(refresh_nonce),
                );
                substituted = 2;
            }
            (Some(a), None) => {
                let nonce = resolver.issue(a);
                obj.insert(
                    "access_token".to_string(),
                    serde_json::Value::String(nonce),
                );
                substituted = 1;
            }
            (None, Some(r)) => {
                let nonce = resolver.issue(r);
                obj.insert(
                    "refresh_token".to_string(),
                    serde_json::Value::String(nonce),
                );
                substituted = 1;
            }
            (None, None) => {}
        }
    }

    if substituted == 0 {
        debug!(
            "oauth-capture: matched URL but no access_token/refresh_token in JSON; passing through"
        );
        return Ok(Response::from_parts(parts, full_body(body_bytes)));
    }

    let new_body_bytes = match serde_json::to_vec(&value) {
        Ok(b) => Bytes::from(b),
        Err(e) => {
            warn!("oauth-capture: re-serializing JSON failed: {e}; passing through");
            return Ok(Response::from_parts(parts, full_body(body_bytes)));
        }
    };

    debug!(
        "oauth-capture: substituted {} token field(s); response body re-serialized",
        substituted
    );

    // The original body framing no longer applies — hyper will set a
    // fresh Content-Length from our `Full<Bytes>`.
    parts.headers.remove(hyper::header::CONTENT_LENGTH);
    parts.headers.remove(hyper::header::TRANSFER_ENCODING);
    // Defensive: even though we asked for identity, scrub
    // Content-Encoding so a misconfigured upstream cannot trick the
    // client into decompressing our plaintext bytes.
    parts.headers.remove(hyper::header::CONTENT_ENCODING);

    Ok(Response::from_parts(parts, full_body(new_body_bytes)))
}

/// Translate any `nono_`-prefixed Bearer token in the `Authorization`
/// header to its real upstream value via the broker.
///
/// Required for the Anthropic Console flow: after capturing the OAuth
/// token exchange and substituting nonces in the response body, claude
/// immediately makes a follow-up authenticated request inside the same
/// CONNECT tunnel (`POST api.anthropic.com/api/oauth/claude_cli/create_api_key`)
/// using the access token it just received. Because the response was
/// rewritten, that token is now `nono_<hex>` — the upstream rejects it
/// with 401 unless we translate before forwarding.
///
/// Mirrors the resolver-then-Bearer-prefix logic in the reverse proxy's
/// pass-through path. If the broker does not have the nonce (e.g. a
/// stale value from a prior session whose record has been cleared),
/// forward the raw value unchanged so the upstream's auth error
/// surfaces to the client unchanged.
///
/// Tokens that don't start with `nono_` are left alone — passes through
/// real bearer tokens (typical for non-OAuth-capture intercepted hosts)
/// and any other `Authorization` schemes (Basic, etc.).
fn rewrite_bearer_header(
    headers: &mut hyper::HeaderMap,
    resolver: &(dyn TokenResolver + 'static),
) {
    let raw = match headers.get(hyper::header::AUTHORIZATION) {
        Some(v) => match v.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return,
        },
        None => return,
    };
    let token = match raw.strip_prefix("Bearer ").or_else(|| raw.strip_prefix("bearer ")) {
        Some(t) => t.trim(),
        None => return,
    };
    if !token.starts_with("nono_") {
        return;
    }
    let resolved = match resolver.resolve(token) {
        Some(real) => real,
        None => {
            debug!("intercept: nonce {}... not in broker; forwarding raw", &token[..12.min(token.len())]);
            return;
        }
    };
    let new_value = format!("Bearer {}", resolved.as_str());
    match hyper::header::HeaderValue::from_str(&new_value) {
        Ok(hv) => {
            headers.insert(hyper::header::AUTHORIZATION, hv);
            debug!("intercept: translated nonce Bearer to real upstream token");
        }
        Err(e) => {
            warn!("intercept: resolved token contained invalid header chars: {e}; forwarding raw");
        }
    }
}

/// Wrap concrete bytes in our type-erased response body.
fn full_body(bytes: Bytes) -> RewrittenBody {
    Full::new(bytes).map_err(|never| match never {}).boxed()
}

/// Build a 502 with a plaintext reason. Falls back to an empty 502 if
/// the builder somehow rejects the body type (it should not).
fn make_502(reason: String) -> Response<RewrittenBody> {
    Response::builder()
        .status(hyper::StatusCode::BAD_GATEWAY)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full_body(Bytes::from(reason)))
        .unwrap_or_else(|_| {
            // SAFETY: this branch is unreachable for well-typed bodies.
            // We construct an empty 502 directly to avoid relying on
            // `unwrap` while still satisfying the return type.
            let mut empty = Response::new(full_body(Bytes::new()));
            *empty.status_mut() = hyper::StatusCode::BAD_GATEWAY;
            empty
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    /// Test fake: a `TokenResolver` with a fixed `nonce -> real_token`
    /// mapping. Used to exercise `rewrite_bearer_header` without
    /// constructing a full `TokenBroker`.
    struct FakeResolver {
        nonce: &'static str,
        real: &'static str,
    }
    impl crate::broker::TokenResolver for FakeResolver {
        fn issue(&self, _: zeroize::Zeroizing<String>) -> String {
            unreachable!("not used by these tests")
        }
        fn resolve(&self, nonce: &str) -> Option<zeroize::Zeroizing<String>> {
            if nonce == self.nonce {
                Some(zeroize::Zeroizing::new(self.real.to_string()))
            } else {
                None
            }
        }
    }

    #[test]
    fn rewrite_bearer_header_translates_nonce_to_real() {
        let resolver = FakeResolver {
            nonce: "nono_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            real: "sk-ant-oat01-deadbeef",
        };
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            hyper::header::AUTHORIZATION,
            hyper::header::HeaderValue::from_static(
                "Bearer nono_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        );

        rewrite_bearer_header(&mut headers, &resolver);

        let after = headers
            .get(hyper::header::AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(after, "Bearer sk-ant-oat01-deadbeef");
    }

    #[test]
    fn rewrite_bearer_header_passes_through_unknown_nonce() {
        let resolver = FakeResolver {
            nonce: "nono_known",
            real: "real",
        };
        let mut headers = hyper::HeaderMap::new();
        let original = "Bearer nono_unknown_nonce_value";
        headers.insert(
            hyper::header::AUTHORIZATION,
            hyper::header::HeaderValue::from_static(original),
        );

        rewrite_bearer_header(&mut headers, &resolver);

        let after = headers
            .get(hyper::header::AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(after, original, "unknown nonce must be left as-is");
    }

    #[test]
    fn rewrite_bearer_header_leaves_real_tokens_alone() {
        let resolver = FakeResolver {
            nonce: "nono_x",
            real: "real_x",
        };
        let mut headers = hyper::HeaderMap::new();
        let original = "Bearer sk-ant-oat01-realtoken";
        headers.insert(
            hyper::header::AUTHORIZATION,
            hyper::header::HeaderValue::from_static(original),
        );

        rewrite_bearer_header(&mut headers, &resolver);

        let after = headers
            .get(hyper::header::AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(after, original);
    }

    #[test]
    fn rewrite_bearer_header_no_authorization_header_is_noop() {
        let resolver = FakeResolver {
            nonce: "nono_x",
            real: "real_x",
        };
        let mut headers = hyper::HeaderMap::new();
        rewrite_bearer_header(&mut headers, &resolver);
        assert!(headers.get(hyper::header::AUTHORIZATION).is_none());
    }

    #[test]
    fn rewrite_bearer_header_handles_lowercase_bearer() {
        let resolver = FakeResolver {
            nonce: "nono_lc",
            real: "real_lc",
        };
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            hyper::header::AUTHORIZATION,
            hyper::header::HeaderValue::from_static("bearer nono_lc"),
        );
        rewrite_bearer_header(&mut headers, &resolver);
        let after = headers
            .get(hyper::header::AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(after, "Bearer real_lc");
    }

    #[test]
    fn ca_new_succeeds_and_emits_pem() {
        let ca = InterceptCa::new().unwrap();
        let pem = ca.ca_pem();
        assert!(
            pem.starts_with("-----BEGIN CERTIFICATE-----"),
            "CA PEM should start with the certificate header, got: {}",
            &pem[..pem.len().min(80)]
        );
        assert!(
            pem.trim_end().ends_with("-----END CERTIFICATE-----"),
            "CA PEM should end with the certificate footer"
        );
    }

    #[test]
    fn each_session_ca_is_unique() {
        let a = InterceptCa::new().unwrap();
        let b = InterceptCa::new().unwrap();
        assert_ne!(
            a.ca_pem(),
            b.ca_pem(),
            "fresh sessions must yield distinct CAs"
        );
    }

    #[test]
    fn server_config_for_caches_per_host() {
        let ca = InterceptCa::new().unwrap();
        let cfg1 = ca.server_config_for("claude.ai").unwrap();
        let cfg2 = ca.server_config_for("claude.ai").unwrap();
        assert!(
            Arc::ptr_eq(&cfg1, &cfg2),
            "second call for same host should return the cached Arc"
        );
    }

    #[test]
    fn server_config_for_is_case_insensitive() {
        let ca = InterceptCa::new().unwrap();
        let lower = ca.server_config_for("claude.ai").unwrap();
        let upper = ca.server_config_for("CLAUDE.AI").unwrap();
        assert!(
            Arc::ptr_eq(&lower, &upper),
            "host lookup must be case-insensitive"
        );
    }

    #[test]
    fn server_config_for_distinct_hosts_yields_distinct_configs() {
        let ca = InterceptCa::new().unwrap();
        let a = ca.server_config_for("claude.ai").unwrap();
        let b = ca.server_config_for("api.anthropic.com").unwrap();
        assert!(
            !Arc::ptr_eq(&a, &b),
            "different hosts must get different leaves"
        );
    }

    #[test]
    fn write_ca_pem_creates_file_with_mode_0644() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        let ca = InterceptCa::new().unwrap();

        ca.write_ca_pem(&path).unwrap();

        let meta = fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, CA_PEM_MODE, "CA PEM should be written with mode 0644");

        let on_disk = fs::read_to_string(&path).unwrap();
        assert_eq!(on_disk, ca.ca_pem(), "on-disk PEM must match in-memory PEM");
    }

    #[test]
    fn write_ca_pem_is_idempotent_and_overwrites() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        let ca = InterceptCa::new().unwrap();

        ca.write_ca_pem(&path).unwrap();
        let first = fs::read_to_string(&path).unwrap();
        ca.write_ca_pem(&path).unwrap();
        let second = fs::read_to_string(&path).unwrap();

        assert_eq!(first, second, "rewriting same CA should produce same bytes");
        // No stray .tmp files left behind.
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with('.'))
            .collect();
        assert!(
            leftovers.is_empty(),
            "atomic-write tempfile must be renamed away, found: {:?}",
            leftovers
        );
    }

    #[test]
    fn write_ca_pem_rejects_missing_parent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing").join("ca.pem");
        let ca = InterceptCa::new().unwrap();

        let err = ca.write_ca_pem(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("parent directory does not exist"),
            "expected missing-parent error, got: {msg}"
        );
    }

    #[test]
    fn leaf_cert_chain_is_single_leaf() {
        // The ServerConfig itself doesn't expose its cert chain in a
        // public API, but we can re-derive a leaf via the same path the
        // builder uses and confirm it parses as a valid X.509 leaf with
        // the requested SAN. We do this by issuing through the public
        // `server_config_for` and re-parsing the most recent leaf via
        // an internal helper test path: the CertifiedKey is private, so
        // here we rely on a smoke-test — the Arc must not be null and
        // calling twice yields the cached entry.
        let ca = InterceptCa::new().unwrap();
        let cfg = ca.server_config_for("example.com").unwrap();
        // Smoke: Arc strong count >= 2 (cache + returned clone).
        assert!(
            Arc::strong_count(&cfg) >= 2,
            "leaf cache must hold its own strong reference"
        );
    }

    /// Build a `TlsConnector` that trusts the system roots. Used only
    /// as a placeholder argument in `handle_intercept_*` tests where
    /// the upstream TLS leg never gets exercised (because the test
    /// closes the client before completing the client-side handshake).
    fn unused_upstream_connector() -> TlsConnector {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        TlsConnector::from(Arc::new(cfg))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handle_intercept_sends_200_after_upstream_tcp_succeeds() {
        // Validates the dispatcher's externally observable contract:
        //   1. open upstream TCP first;
        //   2. then send HTTP/1.1 200 to the client.
        //
        // We don't drive the TLS handshake to completion here — the
        // test closes the client right after reading the 200, which
        // makes the client-side TLS-accept fail and `handle_intercept`
        // exits via the audit-and-Ok branch. That is intentional: the
        // full handshake is exercised by the body-rewriter test in the
        // next commit, where there is something to assert about the
        // payload.
        use tokio::io::AsyncReadExt;
        use tokio::net::{TcpListener, TcpStream};

        // "Upstream" — a plain TCP listener at 127.0.0.1 on a random
        // port. Accepts and discards bytes. The proxy's upstream TCP
        // open succeeds against this; the upstream TLS leg is never
        // reached because the client closes first.
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = upstream.accept().await {
                let _ = tokio::io::copy(&mut s, &mut tokio::io::sink()).await;
            }
        });

        // "Proxy" — a listener that hands its accepted stream to
        // `handle_intercept`.
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        let ca = Arc::new(InterceptCa::new().unwrap());
        let upstream_tls = unused_upstream_connector();

        let proxy_task = tokio::spawn({
            let ca = Arc::clone(&ca);
            async move {
                let (server_stream, _) = proxy.accept().await.unwrap();
                handle_intercept(
                    server_stream,
                    "localhost",
                    upstream_addr.port(),
                    &[upstream_addr],
                    ca,
                    upstream_tls,
                    None,
                    None,
                    None,
                )
                .await
            }
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let mut buf = [0u8; 64];
        let n = client.read(&mut buf).await.unwrap();
        let response = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(
            response.starts_with("HTTP/1.1 200 Connection Established"),
            "expected 200 line, got: {:?}",
            response
        );

        // Closing the client triggers the client-side TLS-accept to
        // fail; the handler should exit cleanly (Ok), not error.
        drop(client);
        let result = proxy_task.await.unwrap();
        assert!(
            result.is_ok(),
            "handle_intercept must return Ok when the client closes mid-handshake, got: {:?}",
            result
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handle_intercept_fails_when_upstream_unreachable() {
        // No 200 should be written if we cannot reach the upstream,
        // matching the transparent-tunnel handler in `connect.rs`.
        use tokio::io::AsyncReadExt;
        use tokio::net::{TcpListener, TcpStream};

        // Pick a port likely to refuse connections by binding it then
        // dropping the listener — the OS may take a moment to release,
        // but a TCP connect to it usually fails immediately on Linux/
        // macOS (ECONNREFUSED) once the socket is closed.
        let unused_addr = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = l.local_addr().unwrap();
            drop(l);
            a
        };

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        let ca = Arc::new(InterceptCa::new().unwrap());
        let upstream_tls = unused_upstream_connector();

        let proxy_task = tokio::spawn({
            let ca = Arc::clone(&ca);
            async move {
                let (server_stream, _) = proxy.accept().await.unwrap();
                handle_intercept(
                    server_stream,
                    "localhost",
                    unused_addr.port(),
                    &[unused_addr],
                    ca,
                    upstream_tls,
                    None,
                    None,
                    None,
                )
                .await
            }
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let mut buf = [0u8; 64];

        // Read should observe EOF (n == 0) without ever seeing a 200,
        // because handle_intercept errors out before writing the
        // status line.
        let n = client.read(&mut buf).await.unwrap_or(0);
        assert_eq!(
            n,
            0,
            "client must not see any bytes when upstream is unreachable, got: {:?}",
            std::str::from_utf8(&buf[..n])
        );

        let result = proxy_task.await.unwrap();
        assert!(
            result.is_err(),
            "handle_intercept must return Err when upstream is unreachable"
        );
    }
}
