use crate::cli::SandboxArgs;
use crate::launch_runtime::ProxyLaunchOptions;
use crate::mediation::broker::TokenBroker;
use crate::network_policy;
use crate::sandbox_prepare::{validate_external_proxy_bypass, PreparedSandbox};
use nono::{AccessMode, CapabilitySet, FsCapability, NonoError, Result};
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;
use tracing::warn;

pub(crate) struct ActiveProxyRuntime {
    pub(crate) env_vars: Vec<(String, String)>,
    pub(crate) handle: Option<nono_proxy::server::ProxyHandle>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct EffectiveProxySettings {
    pub(crate) network_profile: Option<String>,
    pub(crate) allow_domain: Vec<String>,
    pub(crate) credentials: Vec<String>,
}

pub(crate) fn prepare_proxy_launch_options(
    args: &SandboxArgs,
    prepared: &PreparedSandbox,
    silent: bool,
) -> Result<ProxyLaunchOptions> {
    validate_external_proxy_bypass(args, prepared)?;

    let effective_proxy = resolve_effective_proxy_settings(args, prepared);
    let network_profile = effective_proxy.network_profile;
    let allow_domain = effective_proxy.allow_domain;
    let credentials = effective_proxy.credentials;
    let allow_bind_ports = merge_dedup_ports(&prepared.listen_ports, &args.allow_bind);

    let upstream_proxy = if args.allow_net {
        None
    } else {
        args.external_proxy
            .clone()
            .or_else(|| prepared.upstream_proxy.clone())
    };

    let upstream_bypass = if args.allow_net {
        Vec::new()
    } else if args.external_proxy.is_some() {
        args.external_proxy_bypass.clone()
    } else {
        let mut bypass = prepared.upstream_bypass.clone();
        bypass.extend(args.external_proxy_bypass.clone());
        bypass
    };

    let active = if matches!(prepared.caps.network_mode(), nono::NetworkMode::Blocked) {
        if !credentials.is_empty()
            || network_profile.is_some()
            || !allow_domain.is_empty()
            || upstream_proxy.is_some()
        {
            warn!(
                "--block-net is active; ignoring proxy configuration \
                 that would re-enable network access"
            );
            if !silent {
                eprintln!(
                    "  [nono] Warning: --block-net overrides proxy/credential settings. \
                     Network remains fully blocked."
                );
            }
        }
        false
    } else {
        matches!(
            prepared.caps.network_mode(),
            nono::NetworkMode::ProxyOnly { .. }
        ) || !credentials.is_empty()
            || network_profile.is_some()
            || !allow_domain.is_empty()
            || upstream_proxy.is_some()
    };

    Ok(ProxyLaunchOptions {
        active,
        network_profile,
        allow_domain,
        credentials,
        custom_credentials: prepared.custom_credentials.clone(),
        upstream_proxy,
        upstream_bypass,
        allow_bind_ports,
        proxy_port: args.proxy_port,
        open_url_origins: prepared.open_url_origins.clone(),
        open_url_allow_localhost: prepared.open_url_allow_localhost,
        allow_launch_services_active: prepared.allow_launch_services_active,
        oauth_capture: prepared.oauth_capture,
    })
}

pub(crate) fn resolve_effective_proxy_settings(
    args: &SandboxArgs,
    prepared: &PreparedSandbox,
) -> EffectiveProxySettings {
    if args.allow_net {
        return EffectiveProxySettings {
            network_profile: None,
            allow_domain: Vec::new(),
            credentials: Vec::new(),
        };
    }

    let network_profile = args
        .network_profile
        .clone()
        .or_else(|| prepared.network_profile.clone());
    let mut allow_domain = prepared.allow_domain.clone();
    allow_domain.extend(args.allow_proxy.clone());
    let mut credentials = prepared.credentials.clone();
    credentials.extend(args.proxy_credential.clone());

    EffectiveProxySettings {
        network_profile,
        allow_domain,
        credentials,
    }
}

pub(crate) fn merge_dedup_ports(a: &[u16], b: &[u16]) -> Vec<u16> {
    let mut ports = a.to_vec();
    ports.extend_from_slice(b);
    ports.sort_unstable();
    ports.dedup();
    ports
}

pub(crate) fn build_proxy_config_from_flags(
    proxy: &ProxyLaunchOptions,
    workdir: &std::path::Path,
) -> Result<nono_proxy::config::ProxyConfig> {
    let net_policy_json = crate::config::embedded::embedded_network_policy_json();
    let net_policy = network_policy::load_network_policy(net_policy_json)?;

    let mut resolved = if let Some(ref profile_name) = proxy.network_profile {
        network_policy::resolve_network_profile(&net_policy, profile_name)?
    } else {
        network_policy::ResolvedNetworkPolicy {
            hosts: Vec::new(),
            suffixes: Vec::new(),
            routes: Vec::new(),
            profile_credentials: Vec::new(),
        }
    };

    let mut all_credentials = resolved.profile_credentials.clone();
    for cred in &proxy.credentials {
        if !all_credentials.contains(cred) {
            all_credentials.push(cred.clone());
        }
    }

    let routes = network_policy::resolve_credentials(
        &net_policy,
        &all_credentials,
        &proxy.custom_credentials,
        workdir,
    )?;
    resolved.routes = routes;

    let expanded_allow_domain =
        network_policy::expand_proxy_allow(&net_policy, &proxy.allow_domain);
    let mut proxy_config = network_policy::build_proxy_config(&resolved, &expanded_allow_domain);

    if let Some(ref addr) = proxy.upstream_proxy {
        proxy_config.external_proxy = Some(nono_proxy::config::ExternalProxyConfig {
            address: addr.clone(),
            auth: None,
            bypass_hosts: proxy.upstream_bypass.clone(),
        });
    }

    if let Some(port) = proxy.proxy_port {
        proxy_config.bind_port = port;
    }

    Ok(proxy_config)
}

pub(crate) fn start_proxy_runtime(
    proxy: &ProxyLaunchOptions,
    caps: &mut CapabilitySet,
    workdir: &std::path::Path,
) -> Result<ActiveProxyRuntime> {
    if !proxy.active {
        return Ok(ActiveProxyRuntime {
            env_vars: Vec::new(),
            handle: None,
        });
    }

    let mut proxy_config = build_proxy_config_from_flags(proxy, workdir)?;
    proxy_config.direct_connect_ports = caps.tcp_connect_ports().to_vec();

    // OAuth-capture wiring. Opt-in via the profile's `oauth_capture` field
    // (default false). When unset, proxy startup is identical to the
    // pre-OAuth-capture build: no intercept CA, no broker, no
    // NODE_EXTRA_CA_CERTS, real OAuth tokens flow to the keychain
    // unchanged.
    let (proxy_runtime, oauth_ca_path) = if proxy.oauth_capture {
        let (rt, path) = build_oauth_capture_runtime(&mut proxy_config, caps)?;
        (rt, Some(path))
    } else {
        (nono_proxy::ProxyRuntime::default(), None)
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| NonoError::SandboxInit(format!("Failed to start proxy runtime: {}", e)))?;
    let handle = rt
        .block_on(async {
            nono_proxy::server::start_with_runtime(proxy_config.clone(), proxy_runtime).await
        })
        .map_err(|e| NonoError::SandboxInit(format!("Failed to start proxy: {}", e)))?;

    let port = handle.port;
    if proxy.allow_bind_ports.is_empty() {
        info!("Network proxy started on localhost:{}", port);
    } else {
        info!(
            "Network proxy started on localhost:{}, bind ports: {:?}",
            port, proxy.allow_bind_ports
        );
    }
    // OAuth capture requires the child to bind a localhost port for the
    // browser redirect callback server. Ensure network-bind is enabled.
    // On macOS, Seatbelt's (allow network-bind) is blanket — it cannot
    // filter by port — so any non-empty bind_ports list suffices. Port 0
    // is the sentinel: it means "let the OS pick" and signals intent
    // without granting access to a specific port.
    let bind_ports = if oauth_ca_path.is_some() && proxy.allow_bind_ports.is_empty() {
        vec![0]
    } else {
        proxy.allow_bind_ports.clone()
    };
    caps.set_network_mode_mut(nono::NetworkMode::ProxyOnly { port, bind_ports });

    let mut env_vars: Vec<(String, String)> = Vec::new();
    for (key, value) in handle.env_vars() {
        env_vars.push((key, value));
    }

    for (key, value) in handle.credential_env_vars(&proxy_config) {
        env_vars.push((key, value));
    }

    // Push the trust-store env vars only after the proxy is up so a
    // failure in the OAuth-capture wiring (CA gen, file write) does not
    // leave the child trusting a CA that no proxy is presenting.
    if let Some(path) = oauth_ca_path {
        let path_str = path.display().to_string();
        env_vars.push(("NODE_EXTRA_CA_CERTS".to_string(), path_str.clone()));
        // Defensive companion knob: under the Bun-compiled Claude Code
        // 2.1.x binary, the app-level CA loader early-returns if both
        // env vars are unset. Setting CLAUDE_CODE_CERT_STORE forces it
        // to run regardless. See verification section in the design
        // doc.
        env_vars.push((
            "CLAUDE_CODE_CERT_STORE".to_string(),
            "bundled,system".to_string(),
        ));
        info!(
            "OAuth capture: child will trust session CA via NODE_EXTRA_CA_CERTS={}",
            path_str
        );
    }

    std::mem::forget(rt);

    Ok(ActiveProxyRuntime {
        env_vars,
        handle: Some(handle),
    })
}

/// Build the [`nono_proxy::ProxyRuntime`] for the OAuth-capture path:
/// generate a session CA, materialize the public PEM under
/// `$TMPDIR/nono-pid-<pid>-<rand>/`, mount it as readable in the child's
/// capability set, and inject the `claude-oauth` route into the proxy
/// config so the dispatcher TLS-terminates `claude.ai:443`.
///
/// Returns the runtime plus the absolute path to the CA PEM so the
/// caller can export it via `NODE_EXTRA_CA_CERTS`.
fn build_oauth_capture_runtime(
    proxy_config: &mut nono_proxy::config::ProxyConfig,
    caps: &mut CapabilitySet,
) -> Result<(nono_proxy::ProxyRuntime, PathBuf)> {
    // Ensure the intercept routes are present. We add three routes:
    // api.anthropic.com, claude.ai, and platform.claude.com. Binary
    // analysis confirmed TOKEN_URL is on platform.claude.com — the PKCE
    // code exchange goes there, not to api.anthropic.com or claude.ai.
    // All three are intercepted so we capture whichever host the client
    // actually calls.
    //
    // Each prefix lives in the reserved `__nono_` namespace
    // ([`nono_proxy::RESERVED_PREFIX_NAMESPACE`]) so user profiles cannot
    // declare a colliding route — `RouteStore::load` rejects user routes
    // whose prefix sits in that namespace. The dedup loop below is a
    // safety net for re-entry within a single nono process (e.g. if a
    // future caller invokes `build_oauth_capture_runtime` more than once
    // against the same `proxy_config`); it is no longer the user-collision
    // defence.
    for route in oauth_capture_routes() {
        if !proxy_config.routes.iter().any(|r| r.prefix == route.prefix) {
            proxy_config.routes.push(route);
        }
    }

    let ca = Arc::new(
        nono_proxy::intercept::InterceptCa::new()
            .map_err(|e| NonoError::SandboxInit(format!("OAuth-capture CA generation: {e}")))?,
    );

    let ca_dir = ensure_session_ca_dir()?;
    let ca_path = ca_dir.join("ca.pem");
    ca.write_ca_pem(&ca_path).map_err(|e| {
        NonoError::SandboxInit(format!("write CA PEM to {}: {e}", ca_path.display()))
    })?;

    caps.add_fs(FsCapability::new_file(&ca_path, AccessMode::Read)?);

    // Session-scoped broker, optionally backed by durable storage so
    // captured OAuth pairs survive across nono sessions. Persistence is
    // best-effort: if hydrate fails (no keystore backend, headless Linux
    // without secret-service, etc.), fall back to an in-memory broker —
    // capture still works for this session, only cross-session resume is
    // degraded.
    let resolver: Arc<dyn nono_proxy::TokenResolver> = Arc::new(build_broker());

    Ok((
        nono_proxy::ProxyRuntime {
            intercept_ca: Some(ca),
            token_resolver: Some(resolver),
        },
        ca_path,
    ))
}

/// Construct the OAuth-capture broker, attempting to back it with a
/// durable [`crate::mediation::broker_store::KeystoreBrokerStore`] so
/// captured pairs persist across sessions. On any error initialising
/// the store (e.g. no keyring backend available), fall back to an
/// in-memory broker and log a warning — capture still works for this
/// session; only cross-session resume is lost.
fn build_broker() -> TokenBroker {
    #[cfg(feature = "system-keyring")]
    {
        use crate::mediation::broker_store::KeystoreBrokerStore;
        let store = Arc::new(KeystoreBrokerStore::default_for_claude_oauth());
        match TokenBroker::with_store(store) {
            Ok(broker) => return broker,
            Err(e) => {
                warn!(
                    "OAuth broker keystore backend init failed; using in-memory broker only \
                     (cross-session OAuth resume disabled this run): {e}"
                );
            }
        }
    }
    TokenBroker::new()
}

/// Per-session directory that holds the materialized session CA PEM.
///
/// Path shape: `$TMPDIR/nono-pid-<pid>-<32-hex>` where the suffix is 128
/// random bits from the OS RNG. The dir is created exclusively with mode
/// 0700 in a single syscall (`mkdir(2)` via `DirBuilder::create` — fails
/// with `EEXIST` if the path already exists).
///
/// This shape closes a TOCTOU/symlink window in the previous design,
/// where `$TMPDIR/nono-pid-<pid>` was predictable on Linux with shared
/// `/tmp`: a local attacker could pre-create the dir or plant a symlink,
/// then the subsequent `set_permissions` call (which follows symlinks)
/// would `chmod` the symlink target. The exclusive-create + unguessable
/// suffix means the path is never reused and never reachable by an
/// attacker who hasn't observed the suffix.
///
/// The cert itself is public; the 0700 dir mode just keeps other local
/// users from listing siblings inside the session directory.
fn ensure_session_ca_dir() -> Result<PathBuf> {
    let tmpdir = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
    create_session_ca_dir_in(std::path::Path::new(&tmpdir))
}

/// Inner helper that takes the parent dir explicitly, for testability.
fn create_session_ca_dir_in(parent: &std::path::Path) -> Result<PathBuf> {
    use rand::RngExt;
    let mut rng = rand::rng();
    let suffix: [u8; 16] = rng.random();
    let mut suffix_hex = String::with_capacity(32);
    for byte in suffix {
        suffix_hex.push_str(&format!("{:02x}", byte));
    }
    let dir = parent.join(format!("nono-pid-{}-{}", std::process::id(), suffix_hex));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|e| {
            NonoError::SandboxInit(format!(
                "failed to create OAuth-capture CA dir {} (mode 0700, exclusive): {e}",
                dir.display()
            ))
        })?;
    Ok(dir)
}

/// Prefix for the OAuth-capture intercept route targeting
/// `api.anthropic.com`. Lives in the reserved `__nono_` namespace
/// (see [`nono_proxy::RESERVED_PREFIX_NAMESPACE`]) so user profiles
/// cannot declare a colliding prefix.
const OAUTH_PREFIX_ANTHROPIC: &str = "__nono_oauth_anthropic";

/// Prefix for the OAuth-capture intercept route targeting `claude.ai`.
const OAUTH_PREFIX_CLAUDEAI: &str = "__nono_oauth_claudeai";

/// Prefix for the OAuth-capture intercept route targeting
/// `platform.claude.com`. The PKCE token exchange (Layer 1.2) lands
/// here per binary analysis of the Claude Code CLI.
const OAUTH_PREFIX_PLATFORM: &str = "__nono_oauth_platform";

/// The intercept routes injected during OAuth capture (Layer 1 of
/// `2026-04-27-capture-anthropic-auth.md`).
///
/// Binary analysis (`strings claude | grep TOKEN_URL`) confirms:
///   TOKEN_URL = "https://platform.claude.com/v1/oauth/token"
///
/// The PKCE code exchange (POST /v1/oauth/token) goes to
/// `platform.claude.com`, NOT `api.anthropic.com` or `claude.ai`.
/// All three hosts are intercepted so we catch the exchange regardless of
/// which OAuth server handles it.
///
/// Each prefix sits in the reserved `__nono_` namespace; user-supplied
/// routes with that prefix are rejected by `RouteStore::load`. The
/// previous prefix names (`claude-oauth`, `claude-oauth-claudeai`,
/// `claude-oauth-platform`) looked like ordinary service names and could
/// be silently shadowed by a user route — switching to the reserved
/// namespace closes that gap.
fn oauth_capture_routes() -> Vec<nono_proxy::config::RouteConfig> {
    use nono_proxy::config::{InjectMode, RouteConfig};
    let make = |prefix: &str, upstream: &str| RouteConfig {
        prefix: prefix.to_string(),
        upstream: upstream.to_string(),
        credential_key: None,
        inject_mode: InjectMode::OauthCapture {
            token_url_match: "/v1/oauth/token".to_string(),
            refresh_url_match: "/v1/oauth/token".to_string(),
        },
        inject_header: "Authorization".to_string(),
        credential_format: "Bearer {}".to_string(),
        path_pattern: None,
        path_replacement: None,
        query_param_name: None,
        proxy: None,
        env_var: None,
        endpoint_rules: vec![],
        tls_ca: None,
        tls_client_cert: None,
        tls_client_key: None,
        oauth2: None,
        tls_intercept: true,
    };
    vec![
        make(OAUTH_PREFIX_ANTHROPIC, "https://api.anthropic.com"),
        make(OAUTH_PREFIX_CLAUDEAI, "https://claude.ai"),
        make(OAUTH_PREFIX_PLATFORM, "https://platform.claude.com"),
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod ca_dir_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn create_session_ca_dir_in_creates_dir_with_mode_0700() {
        let parent = tempfile::tempdir().unwrap();
        let dir = create_session_ca_dir_in(parent.path()).unwrap();

        assert!(dir.is_dir(), "session CA dir should exist after create");
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "session CA dir must be created with mode 0700");
    }

    #[test]
    fn create_session_ca_dir_in_path_shape_includes_pid_and_random_suffix() {
        let parent = tempfile::tempdir().unwrap();
        let dir = create_session_ca_dir_in(parent.path()).unwrap();
        let name = dir.file_name().unwrap().to_string_lossy().to_string();
        let expected_prefix = format!("nono-pid-{}-", std::process::id());
        assert!(
            name.starts_with(&expected_prefix),
            "name {name:?} should start with {expected_prefix:?}"
        );
        let suffix = &name[expected_prefix.len()..];
        assert_eq!(
            suffix.len(),
            32,
            "random suffix should be 32 hex chars (128 bits), got {suffix:?}"
        );
        assert!(
            suffix.chars().all(|c| c.is_ascii_hexdigit()),
            "random suffix must be lowercase hex, got {suffix:?}"
        );
    }

    #[test]
    fn create_session_ca_dir_in_yields_distinct_paths_each_call() {
        // Two consecutive invocations must yield different paths because
        // the 128-bit suffix is fresh on each call. This is what makes
        // the path unguessable to a local attacker.
        let parent = tempfile::tempdir().unwrap();
        let a = create_session_ca_dir_in(parent.path()).unwrap();
        let b = create_session_ca_dir_in(parent.path()).unwrap();
        assert_ne!(a, b, "two invocations must yield distinct dirs");
    }

    #[test]
    fn create_session_ca_dir_in_is_exclusive_against_preexisting_dir() {
        // If an attacker pre-creates the exact target path, the create
        // must fail rather than reuse the dir. Probability of guessing
        // the 128-bit suffix is negligible in practice; this test forces
        // the collision to confirm the EEXIST branch is wired correctly.
        let parent = tempfile::tempdir().unwrap();

        // Build the same path the helper would, but pre-create it
        // ourselves with the wrong mode (simulating an attacker's
        // pre-placed dir). We can't share the random suffix with the
        // helper, so we reach into a deterministic name and call the
        // raw `DirBuilder::create` directly to confirm EEXIST behaviour.
        let attacker_path = parent.path().join("nono-pid-attacker-fixed");
        std::fs::DirBuilder::new()
            .mode(0o755)
            .create(&attacker_path)
            .unwrap();

        // Re-creating with `DirBuilder::create` (the same call the
        // helper uses) on an existing path must fail with AlreadyExists.
        let err = std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&attacker_path)
            .unwrap_err();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::AlreadyExists,
            "DirBuilder::create on a pre-existing path must error AlreadyExists"
        );
    }
}

#[cfg(test)]
mod oauth_capture_routes_tests {
    use super::*;

    #[test]
    fn oauth_capture_routes_use_reserved_namespace() {
        // Sanity-check: every injected route sits in the reserved
        // namespace so a user route with the same prefix is rejected at
        // config load and cannot shadow a capture route.
        for route in oauth_capture_routes() {
            assert!(
                nono_proxy::is_reserved_prefix(&route.prefix),
                "OAuth-capture route prefix {:?} must use the reserved namespace",
                route.prefix
            );
        }
    }

    #[test]
    fn oauth_capture_routes_distinct_prefixes() {
        let routes = oauth_capture_routes();
        let mut prefixes: Vec<_> = routes.iter().map(|r| r.prefix.clone()).collect();
        prefixes.sort();
        prefixes.dedup();
        assert_eq!(
            prefixes.len(),
            routes.len(),
            "every OAuth-capture route should have a distinct prefix"
        );
    }
}
