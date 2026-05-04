use crate::cli::SandboxArgs;
use crate::launch_runtime::ProxyLaunchOptions;
use crate::mediation::broker::TokenBroker;
use crate::network_policy;
use crate::sandbox_prepare::{validate_external_proxy_bypass, PreparedSandbox};
use nono::{AccessMode, CapabilitySet, FsCapability, NonoError, Result};
use std::os::unix::fs::PermissionsExt;
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
/// `$TMPDIR/nono-pid-<pid>/`, mount it as readable in the child's
/// capability set, and inject the `claude-oauth` route into the proxy
/// config so the dispatcher TLS-terminates `claude.ai:443`.
///
/// Returns the runtime plus the absolute path to the CA PEM so the
/// caller can export it via `NODE_EXTRA_CA_CERTS`.
fn build_oauth_capture_runtime(
    proxy_config: &mut nono_proxy::config::ProxyConfig,
    caps: &mut CapabilitySet,
) -> Result<(nono_proxy::ProxyRuntime, PathBuf)> {
    // Ensure the intercept routes are present. Idempotent: skip any whose
    // prefix is already configured (operator may have wired declaratively).
    // We add three routes: api.anthropic.com, claude.ai, and
    // platform.claude.com. Binary analysis confirmed TOKEN_URL is on
    // platform.claude.com — the PKCE code exchange goes there, not to
    // api.anthropic.com or claude.ai. All three are intercepted so we
    // capture whichever host the client actually calls.
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

    // Session-scoped vault. Layer 2 of the design will make this the
    // same instance the mediation server holds for command-mediation
    // phantom tokens; for now the proxy owns its own.
    let resolver: Arc<dyn nono_proxy::TokenResolver> = Arc::new(TokenBroker::new());

    Ok((
        nono_proxy::ProxyRuntime {
            intercept_ca: Some(ca),
            token_resolver: Some(resolver),
        },
        ca_path,
    ))
}

/// Per-process directory that holds the materialized session CA PEM.
/// Created with mode 0700 the first time this runs; the PEM file
/// itself is mode 0644 (set by `InterceptCa::write_ca_pem`) — the cert
/// is public information and the directory mode is what gates other
/// local users from reading it.
fn ensure_session_ca_dir() -> Result<PathBuf> {
    let tmpdir = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
    let dir = std::path::Path::new(&tmpdir).join(format!("nono-pid-{}", std::process::id()));
    if !dir.exists() {
        std::fs::create_dir_all(&dir).map_err(|e| {
            NonoError::SandboxInit(format!(
                "failed to create OAuth-capture CA dir {}: {e}",
                dir.display()
            ))
        })?;
    }
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
        NonoError::SandboxInit(format!(
            "failed to set OAuth-capture CA dir mode to 0700 {}: {e}",
            dir.display()
        ))
    })?;
    Ok(dir)
}

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
        make("claude-oauth", "https://api.anthropic.com"),
        make("claude-oauth-claudeai", "https://claude.ai"),
        make("claude-oauth-platform", "https://platform.claude.com"),
    ]
}
