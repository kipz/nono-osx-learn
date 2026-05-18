//! Pre-flight rewrite of existing Anthropic credentials when
//! `oauth_capture: true` is set.
//!
//! Without this, the OAuth-capture feature is a no-op for any user who
//! was already authenticated before turning the flag on. Claude reads the
//! existing real `sk-ant-…` bearer from the macOS keychain entry, from
//! `~/.claude/.credentials.json`, or from environment variables, and uses
//! it directly. The proxy never sees a `nono_<hex>` nonce because nothing
//! minted one. The real token reaches Claude's process memory and can be
//! exfiltrated by anything running under the same uid.
//!
//! This module closes that gap by sweeping every documented credential
//! surface before the child starts, capturing any real token into the
//! broker, and rewriting the surface to hold the broker-issued nonce.
//! Surfaces handled:
//!
//! - macOS keychain entry `Claude Code-credentials` (the `claudeAiOauth`
//!   JSON blob with `accessToken` / `refreshToken`).
//! - `~/.claude/.credentials.json` (same JSON shape; primary store on
//!   Linux, optional fallback on macOS).
//! - Environment variables that carry OAuth bearers:
//!   `CLAUDE_CODE_OAUTH_TOKEN`, `CLAUDE_CODE_OAUTH_REFRESH_TOKEN`,
//!   `ANTHROPIC_AUTH_TOKEN`. Each is rewritten with a `nono_<hex>` nonce
//!   in the child's environment (the parent shell is untouched).
//!
//! Surfaces that carry an API key (not an OAuth bearer) are *not*
//! rewritable because the proxy's TLS-intercept layer translates
//! `Authorization: Bearer nono_<hex>` but not `x-api-key: nono_<hex>` —
//! the child would 401 on every request. When any API-key surface is
//! detected alongside `oauth_capture: true` we fail closed with a clear
//! message asking the user to clear it or disable the feature:
//!
//! - environment: `ANTHROPIC_API_KEY`, `CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR`
//! - macOS keychain entry `Claude Code` (no `-credentials` suffix)
//! - `primaryApiKey` field in `~/.claude.json`
//!
//! ### Idempotence
//!
//! Pre-flight is run on every nono session with `oauth_capture: true`. A
//! surface whose value already starts with `nono_` is left untouched, so
//! the second-run case is a quiet no-op rather than re-capture.
//!
//! ### Fail-secure
//!
//! Any unexpected error (write failure, broker error, malformed JSON the
//! surface previously held) returns `Err`. The proxy never starts and the
//! child never spawns. Better to bail loudly than to half-rewrite the
//! user's credentials.

use crate::exec_strategy::is_env_var_denied;
use crate::mediation::broker::TokenBroker;
use nono::{NonoError, Result};
use serde_json::Value;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

/// OAuth-bearer environment variables we rewrite. Claude reads each of
/// these as a long-lived bearer credential and sends it as
/// `Authorization: Bearer <value>`. The proxy's Layer 1.2 and Layer 2
/// paths both translate `Bearer nono_<hex>` back to the real bearer, so
/// substituting a nonce here is safe end-to-end.
const OAUTH_BEARER_ENV_VARS: &[&str] = &[
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_REFRESH_TOKEN",
    "ANTHROPIC_AUTH_TOKEN",
];

/// API-key environment variables. The proxy does not rewrite
/// `x-api-key: nono_<hex>` headers inside the CONNECT tunnel, so
/// capturing these into the broker would just produce a 401 on every
/// upstream request. Flag them as fatal instead of silently breaking
/// the child.
const API_KEY_ENV_VARS: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR",
    "ANTHROPIC_UNIX_SOCKET",
];

/// Outcome of a pre-flight pass.
///
/// `env_overrides` carries `(key, value)` pairs the caller must inject
/// into the child's environment with override priority — the proxy
/// runtime already returns the same shape from
/// `ActiveProxyRuntime.env_vars`, and exec_strategy's `env_clear` +
/// per-key `cmd.env()` semantics guarantee these override any inherited
/// parent value.
#[derive(Debug, Default)]
pub(crate) struct PreflightOutcome {
    pub env_overrides: Vec<(String, String)>,
}

/// Run the pre-flight rewrite if the target program is `claude` and
/// OAuth capture is active. For any other program this is a quiet
/// no-op — pre-flight is a Claude-Code-specific feature.
///
/// `denied_env_vars` is the profile's env-var deny list (the same list
/// that strips vars from the child's environment at exec time). Any
/// API-key var in that list is skipped by the fail-closed check —
/// if the profile would strip it before the child sees it, it poses
/// no capture risk.
pub(crate) fn run_oauth_preflight(
    broker: &TokenBroker,
    program: &OsStr,
    silent: bool,
    denied_env_vars: Option<&[String]>,
) -> Result<PreflightOutcome> {
    if !program_is_claude(program) {
        debug!("oauth_capture: target program is not claude; skipping pre-flight");
        return Ok(PreflightOutcome::default());
    }

    if let Some(reason) = detect_blocking_api_key_surface(denied_env_vars)? {
        return Err(NonoError::SandboxInit(format!(
            "oauth_capture is enabled but an API-key credential is already configured: {reason}. \
             The OAuth-capture path proxies Authorization: Bearer tokens; \
             x-api-key requests inside the CONNECT tunnel would fail authentication. \
             Either clear the API key (unset the env var, delete the keychain entry, \
             or remove `primaryApiKey` from ~/.claude.json) and re-run, or remove \
             `oauth_capture: true` from your profile to use API-key auth as-is."
        )));
    }

    let mut outcome = PreflightOutcome::default();
    capture_oauth_env_vars_from(broker, silent, |k| std::env::var_os(k), &mut outcome);

    // Rewrite surfaces with snapshot-restore: if the keychain write
    // succeeds but the file write subsequently fails, we restore the
    // keychain to avoid leaving the user with nonces that nothing can
    // resolve. Each rewrite function returns the original value when
    // it actually modified something (None = no-op / already nonces).
    let keychain_snapshot = rewrite_keychain_oauth_entry(broker, silent)?;

    if let Err(file_err) = rewrite_credentials_file(broker, silent) {
        #[cfg(target_os = "macos")]
        if let Some(original) = keychain_snapshot {
            if let Err(restore_err) = restore_keychain_entry(&original) {
                warn!(
                    "oauth_capture pre-flight: file rewrite failed AND keychain restore failed \
                     ({restore_err}); user may need to run `claude /login` to restore auth"
                );
            }
        }
        #[cfg(not(target_os = "macos"))]
        let _ = keychain_snapshot;
        return Err(file_err);
    }

    Ok(outcome)
}

/// Capture OAuth-bearer env vars whose values are real (non-empty,
/// non-`nono_`-prefixed) into `broker` and push `(key, nonce)`
/// overrides onto `outcome`. The env-reader is injected so unit tests
/// can run without mutating process-global env state.
fn capture_oauth_env_vars_from<F>(
    broker: &TokenBroker,
    silent: bool,
    env_reader: F,
    outcome: &mut PreflightOutcome,
) where
    F: Fn(&str) -> Option<std::ffi::OsString>,
{
    for &key in OAUTH_BEARER_ENV_VARS {
        if let Some(raw) = env_reader(key)
            && let Some(value) = raw.to_str()
            && !value.is_empty()
            && !value.starts_with("nono_")
        {
            let nonce = broker.issue(Zeroizing::new(value.to_string()));
            outcome.env_overrides.push((key.to_string(), nonce));
            log_capture(silent, &format!("env {key}"));
        }
    }
}

fn program_is_claude(program: &OsStr) -> bool {
    Path::new(program)
        .file_name()
        .and_then(OsStr::to_str)
        .map(|name| name == "claude")
        .unwrap_or(false)
}

fn log_capture(silent: bool, surface: &str) {
    info!("oauth_capture pre-flight: captured existing credential from {surface}");
    if !silent {
        eprintln!("  [nono] OAuth capture: replaced real token in {surface} with nono_ nonce");
    }
}

/// Returns `Some(reason)` if an API-key credential is present anywhere
/// pre-flight would otherwise need to handle. The caller treats this as
/// fatal — see the module docstring.
///
/// `denied_env_vars` is the profile's env-var deny list. Any API-key var
/// the profile would strip from the child's env is excluded from the
/// check — it won't reach the child regardless.
fn detect_blocking_api_key_surface(denied_env_vars: Option<&[String]>) -> Result<Option<String>> {
    if let Some(reason) =
        detect_api_key_env_var_from(|k| std::env::var_os(k), denied_env_vars)
    {
        return Ok(Some(reason));
    }

    if let Some(home) = dirs::home_dir() {
        let global_config = home.join(".claude.json");
        if let Some(reason) = detect_primary_api_key_in_file(&global_config)? {
            return Ok(Some(reason));
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(reason) = detect_api_key_keychain_macos()? {
            return Ok(Some(reason));
        }
    }

    Ok(None)
}

/// Test-friendly: scan `API_KEY_ENV_VARS` against an injected env reader,
/// skipping any var the profile's deny list would strip before the child
/// sees it.
fn detect_api_key_env_var_from<F>(env_reader: F, denied_env_vars: Option<&[String]>) -> Option<String>
where
    F: Fn(&str) -> Option<std::ffi::OsString>,
{
    for &key in API_KEY_ENV_VARS {
        // The profile would deny this var to the child anyway — skip it.
        if let Some(denied) = denied_env_vars {
            if is_env_var_denied(key, denied) {
                continue;
            }
        }
        if let Some(value) = env_reader(key)
            && !value.is_empty()
        {
            return Some(format!("environment variable {key}"));
        }
    }
    None
}

/// Test-friendly: scan a `.claude.json` for a non-empty `primaryApiKey`.
fn detect_primary_api_key_in_file(global_config: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(global_config) {
        Ok(raw) => {
            if global_config_has_primary_api_key(&raw)? {
                Ok(Some(format!(
                    "primaryApiKey in {}",
                    global_config.display()
                )))
            } else {
                Ok(None)
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(NonoError::SandboxInit(format!(
            "oauth_capture pre-flight: could not read {}: {err}",
            global_config.display()
        ))),
    }
}

fn global_config_has_primary_api_key(raw: &str) -> Result<bool> {
    let parsed: Value = serde_json::from_str(raw).map_err(|err| {
        NonoError::SandboxInit(format!(
            "oauth_capture pre-flight: could not parse ~/.claude.json: {err}"
        ))
    })?;
    Ok(parsed
        .get("primaryApiKey")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty()))
}

#[cfg(target_os = "macos")]
fn detect_api_key_keychain_macos() -> Result<Option<String>> {
    let (config_dir, explicit) = match claude_config_dir() {
        Ok(pair) => pair,
        Err(err) => {
            return Err(NonoError::SandboxInit(format!(
                "oauth_capture pre-flight: {err}"
            )));
        }
    };
    let service = claude_keychain_service_name(&config_dir, explicit, "");
    let account = claude_keychain_account_name();
    if read_keychain_item(&account, &service).is_some_and(|v| !v.trim().is_empty()) {
        return Ok(Some(format!(
            "macOS keychain entry service \"{service}\" account \"{account}\""
        )));
    }
    Ok(None)
}

/// Rewrite the macOS keychain `Claude Code-credentials` entry if it
/// currently holds a real Anthropic OAuth pair.
///
/// Returns `Some(original_json)` when the entry was rewritten (the
/// caller uses this as a rollback snapshot if a later step fails), or
/// `None` when no modification was made (entry absent, already has
/// nonces, or no `claudeAiOauth` object).
#[cfg(target_os = "macos")]
fn rewrite_keychain_oauth_entry(
    broker: &TokenBroker,
    silent: bool,
) -> Result<Option<Zeroizing<String>>> {
    let (config_dir, explicit) = claude_config_dir()
        .map_err(|err| NonoError::SandboxInit(format!("oauth_capture pre-flight: {err}")))?;
    let service = claude_keychain_service_name(&config_dir, explicit, "-credentials");
    let account = claude_keychain_account_name();

    let raw = match read_keychain_item(&account, &service) {
        Some(value) if !value.trim().is_empty() => value,
        _ => return Ok(None),
    };

    let mut parsed: Value = serde_json::from_str(&raw).map_err(|err| {
        NonoError::SandboxInit(format!(
            "oauth_capture pre-flight: keychain entry \"{service}\" is not valid JSON: {err}"
        ))
    })?;

    let oauth = match parsed
        .as_object_mut()
        .and_then(|obj| obj.get_mut("claudeAiOauth"))
        .and_then(Value::as_object_mut)
    {
        Some(obj) => obj,
        None => {
            debug!(
                "oauth_capture pre-flight: keychain entry has no claudeAiOauth object; nothing to capture"
            );
            return Ok(None);
        }
    };

    let access = oauth
        .get("accessToken")
        .and_then(Value::as_str)
        .map(str::to_string);
    let refresh = oauth
        .get("refreshToken")
        .and_then(Value::as_str)
        .map(str::to_string);

    if access.as_deref().is_none_or(str::is_empty)
        || access.as_deref().is_some_and(|v| v.starts_with("nono_"))
    {
        return Ok(None);
    }

    let access_token = access.ok_or_else(|| {
        NonoError::SandboxInit(
            "oauth_capture pre-flight: keychain entry has no accessToken to capture".to_string(),
        )
    })?;

    let (access_nonce, refresh_nonce) = match refresh.as_deref() {
        Some(real_refresh) if !real_refresh.is_empty() && !real_refresh.starts_with("nono_") => {
            broker.capture_oauth_pair(
                Zeroizing::new(access_token),
                Zeroizing::new(real_refresh.to_string()),
            )
        }
        _ => {
            let access_nonce = broker.issue(Zeroizing::new(access_token));
            let refresh_nonce = refresh.unwrap_or_default();
            (access_nonce, refresh_nonce)
        }
    };

    oauth.insert(
        "accessToken".to_string(),
        Value::String(access_nonce.clone()),
    );
    if !refresh_nonce.is_empty() {
        oauth.insert(
            "refreshToken".to_string(),
            Value::String(refresh_nonce.clone()),
        );
    }

    let rewritten = serde_json::to_string(&parsed).map_err(|err| {
        NonoError::SandboxInit(format!(
            "oauth_capture pre-flight: could not re-serialise keychain payload: {err}"
        ))
    })?;

    write_keychain_item(&service, &account, &rewritten)?;
    log_capture(silent, &format!("keychain \"{service}\""));
    Ok(Some(Zeroizing::new(raw)))
}

#[cfg(not(target_os = "macos"))]
fn rewrite_keychain_oauth_entry(
    _broker: &TokenBroker,
    _silent: bool,
) -> Result<Option<Zeroizing<String>>> {
    Ok(None)
}

/// Restore the macOS `Claude Code-credentials` keychain entry to
/// `original` after a subsequent pre-flight step failed. Best-effort:
/// logs a warning on failure rather than returning an error (we're
/// already in an error path).
#[cfg(target_os = "macos")]
fn restore_keychain_entry(original: &Zeroizing<String>) -> Result<()> {
    let (config_dir, explicit) = claude_config_dir()
        .map_err(|err| NonoError::SandboxInit(format!("oauth_capture restore: {err}")))?;
    let service = claude_keychain_service_name(&config_dir, explicit, "-credentials");
    let account = claude_keychain_account_name();
    write_keychain_item(&service, &account, original)
}

/// Rewrite `~/.claude/.credentials.json` (or `$CLAUDE_CONFIG_DIR/.credentials.json`)
/// if it holds a real OAuth pair. Cross-platform.
///
/// The return value mirrors `rewrite_keychain_oauth_entry`: `Some((path,
/// original_content))` when the file was rewritten, `None` otherwise.
/// Not used by the caller today (file is the last step, so there is
/// nothing to roll back on its failure), but kept symmetric for clarity.
fn rewrite_credentials_file(broker: &TokenBroker, silent: bool) -> Result<()> {
    let config_dir = match claude_config_dir_cross_platform() {
        Some(dir) => dir,
        None => return Ok(()),
    };
    rewrite_credentials_file_at(&config_dir, broker, silent)
}

/// Test-friendly variant: rewrite `<config_dir>/.credentials.json`. The
/// production code path resolves `config_dir` from `CLAUDE_CONFIG_DIR`
/// or `~/.claude`; tests inject a path directly so they don't have to
/// mutate process-global env vars (which race under cargo's parallel
/// test runner).
fn rewrite_credentials_file_at(
    config_dir: &Path,
    broker: &TokenBroker,
    silent: bool,
) -> Result<()> {
    let path = config_dir.join(".credentials.json");
    let raw = match std::fs::read_to_string(&path) {
        Ok(r) => r,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(NonoError::SandboxInit(format!(
                "oauth_capture pre-flight: could not read {}: {err}",
                path.display()
            )));
        }
    };

    let mut parsed: Value = serde_json::from_str(&raw).map_err(|err| {
        NonoError::SandboxInit(format!(
            "oauth_capture pre-flight: {} is not valid JSON: {err}",
            path.display()
        ))
    })?;

    let oauth = match parsed
        .as_object_mut()
        .and_then(|obj| obj.get_mut("claudeAiOauth"))
        .and_then(Value::as_object_mut)
    {
        Some(obj) => obj,
        None => return Ok(()),
    };

    let access = oauth
        .get("accessToken")
        .and_then(Value::as_str)
        .map(str::to_string);
    let refresh = oauth
        .get("refreshToken")
        .and_then(Value::as_str)
        .map(str::to_string);

    if access.as_deref().is_none_or(str::is_empty)
        || access.as_deref().is_some_and(|v| v.starts_with("nono_"))
    {
        return Ok(());
    }

    let access_token = access.ok_or_else(|| {
        NonoError::SandboxInit(format!(
            "oauth_capture pre-flight: {} has no accessToken to capture",
            path.display()
        ))
    })?;

    let (access_nonce, refresh_nonce) = match refresh.as_deref() {
        Some(real_refresh) if !real_refresh.is_empty() && !real_refresh.starts_with("nono_") => {
            broker.capture_oauth_pair(
                Zeroizing::new(access_token),
                Zeroizing::new(real_refresh.to_string()),
            )
        }
        _ => {
            let access_nonce = broker.issue(Zeroizing::new(access_token));
            let refresh_nonce = refresh.unwrap_or_default();
            (access_nonce, refresh_nonce)
        }
    };

    oauth.insert(
        "accessToken".to_string(),
        Value::String(access_nonce.clone()),
    );
    if !refresh_nonce.is_empty() {
        oauth.insert("refreshToken".to_string(), Value::String(refresh_nonce));
    }

    let rewritten = serde_json::to_string(&parsed).map_err(|err| {
        NonoError::SandboxInit(format!(
            "oauth_capture pre-flight: could not re-serialise {}: {err}",
            path.display()
        ))
    })?;

    atomic_write(&path, &rewritten)?;
    log_capture(silent, &format!("file {}", path.display()));
    Ok(())
}

/// Atomic file replace preserving owner-only permissions on Unix. Writes
/// to a sibling `.tmp` file, fsyncs, then renames into place.
fn atomic_write(path: &Path, content: &str) -> Result<()> {
    use std::io::Write;

    let parent = path.parent().ok_or_else(|| {
        NonoError::SandboxInit(format!(
            "oauth_capture pre-flight: {} has no parent directory",
            path.display()
        ))
    })?;
    let tmp = parent.join(format!(".credentials.json.nono-{}", std::process::id()));

    let mut open_opts = std::fs::OpenOptions::new();
    open_opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open_opts.mode(0o600);
    }

    let mut file = open_opts.open(&tmp).map_err(|err| {
        NonoError::SandboxInit(format!(
            "oauth_capture pre-flight: could not open {} for write: {err}",
            tmp.display()
        ))
    })?;
    file.write_all(content.as_bytes()).map_err(|err| {
        NonoError::SandboxInit(format!(
            "oauth_capture pre-flight: write to {} failed: {err}",
            tmp.display()
        ))
    })?;
    file.sync_all().map_err(|err| {
        NonoError::SandboxInit(format!(
            "oauth_capture pre-flight: fsync {} failed: {err}",
            tmp.display()
        ))
    })?;
    drop(file);

    std::fs::rename(&tmp, path).map_err(|err| {
        let _ = std::fs::remove_file(&tmp);
        NonoError::SandboxInit(format!(
            "oauth_capture pre-flight: rename {} -> {} failed: {err}",
            tmp.display(),
            path.display()
        ))
    })?;
    Ok(())
}

/// Resolve the Claude config directory the same way `claude` itself does.
/// Returns `None` if `HOME` is unset (very rare, like an empty CI env).
fn claude_config_dir_cross_platform() -> Option<PathBuf> {
    if let Some(value) = std::env::var_os("CLAUDE_CONFIG_DIR") {
        return Some(PathBuf::from(value));
    }
    dirs::home_dir().map(|h| h.join(".claude"))
}

// --- macOS keychain helpers (duplicated thin wrappers around the same
//     ones in `sandbox_prepare`; kept private here so this module stays
//     self-contained and re-usable in tests without dragging the full
//     `SandboxArgs` machinery into the test fixtures). ---

#[cfg(target_os = "macos")]
fn claude_config_dir() -> std::result::Result<(PathBuf, bool), String> {
    if let Some(value) = std::env::var_os("CLAUDE_CONFIG_DIR") {
        return Ok((PathBuf::from(value), true));
    }
    let home = dirs::home_dir().ok_or_else(|| "no HOME set".to_string())?;
    Ok((home.join(".claude"), false))
}

#[cfg(target_os = "macos")]
fn claude_keychain_service_name(
    config_dir: &Path,
    config_dir_explicit: bool,
    service_suffix: &str,
) -> String {
    use sha2::{Digest, Sha256};

    let dir_hash = if config_dir_explicit {
        let digest = Sha256::digest(config_dir.to_string_lossy().as_bytes());
        let prefix = digest[..4]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("-{prefix}")
    } else {
        String::new()
    };
    format!(
        "Claude Code{}{}{}",
        claude_oauth_suffix_macos(),
        service_suffix,
        dir_hash
    )
}

#[cfg(target_os = "macos")]
fn claude_oauth_suffix_macos() -> &'static str {
    if std::env::var_os("CLAUDE_CODE_CUSTOM_OAUTH_URL").is_some() {
        return "-custom-oauth";
    }
    if std::env::var("USER_TYPE").ok().as_deref() == Some("ant") {
        if env_truthy_macos("USE_LOCAL_OAUTH") {
            return "-local-oauth";
        }
        if env_truthy_macos("USE_STAGING_OAUTH") {
            return "-staging-oauth";
        }
    }
    ""
}

#[cfg(target_os = "macos")]
fn env_truthy_macos(key: &str) -> bool {
    std::env::var(key).ok().is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

#[cfg(target_os = "macos")]
fn claude_keychain_account_name() -> String {
    std::env::var("USER").unwrap_or_else(|_| "claude-code-user".to_string())
}

#[cfg(target_os = "macos")]
fn read_keychain_item(account: &str, service: &str) -> Option<String> {
    let output = std::process::Command::new("/usr/bin/security")
        .args(["find-generic-password", "-a", account, "-s", service, "-w"])
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    Some(stdout.trim_end_matches(['\r', '\n']).to_string())
}

/// Replace an existing macOS keychain generic-password entry with
/// `payload`. Uses `security add-generic-password -U` so the existing
/// ACL is preserved (the entry was originally created by `claude`, which
/// puts itself in the trusted-apps list).
///
/// Piping the payload via stdin keeps it off argv where `ps` could see
/// it. The `-w` flag with no argument tells `security` to read from
/// `readpassphrase(3)`, which on macOS reads from the controlling
/// terminal — we wire stdin to a pipe so the binary uses our payload
/// without prompting.
///
/// Note: `readpassphrase(3)` has a 128-byte buffer that truncates longer
/// payloads. The claudeAiOauth JSON blob fits (typical Anthropic OAuth
/// tokens make this ~300 bytes), so we use the `keyring` crate for write
/// in `broker_store.rs` for that reason. For pre-flight we *expect* the
/// keychain entry to be larger than 128 bytes; we therefore call
/// `set_password` via the `keyring` crate, which uses `SecItemUpdate`
/// directly and has no length cap.
#[cfg(target_os = "macos")]
fn write_keychain_item(service: &str, account: &str, payload: &str) -> Result<()> {
    let entry = keyring::Entry::new(service, account).map_err(|err| {
        NonoError::SandboxInit(format!(
            "oauth_capture pre-flight: keyring init for {service}/{account}: {err}"
        ))
    })?;
    entry.set_password(payload).map_err(|err| {
        NonoError::SandboxInit(format!(
            "oauth_capture pre-flight: keychain write {service}/{account} failed: {err}. \
             macOS may have prompted and the user denied access; allow the prompt and re-run, \
             or disable oauth_capture and re-run /login outside nono."
        ))
    })?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn program_is_claude_matches_basename_only() {
        assert!(program_is_claude(OsStr::new("/opt/homebrew/bin/claude")));
        assert!(program_is_claude(OsStr::new("claude")));
        assert!(!program_is_claude(OsStr::new("/usr/bin/codex")));
        assert!(!program_is_claude(OsStr::new("claude-wrapper")));
    }

    #[test]
    fn run_oauth_preflight_no_op_when_target_is_not_claude() {
        // Even with a real-token-bearing env var, pre-flight skips when
        // the program isn't claude. (Other binaries don't read these.)
        let broker = TokenBroker::new();
        let outcome =
            run_oauth_preflight(&broker, OsStr::new("/usr/bin/codex"), true, None).unwrap();
        assert!(outcome.env_overrides.is_empty());
    }

    #[test]
    fn global_config_has_primary_api_key_handles_shapes() {
        assert!(
            !global_config_has_primary_api_key(r#"{"primaryApiKey":""}"#).unwrap(),
            "empty string must not count as having a key"
        );
        assert!(
            global_config_has_primary_api_key(r#"{"primaryApiKey":"sk-ant-api03-xxx"}"#).unwrap()
        );
        assert!(!global_config_has_primary_api_key(r#"{}"#).unwrap());
        assert!(!global_config_has_primary_api_key(r#"{"primaryApiKey":null}"#).unwrap());
        assert!(global_config_has_primary_api_key("not json").is_err());
    }

    fn write_credentials_at(config_dir: &Path, contents: &str) -> PathBuf {
        std::fs::create_dir_all(config_dir).unwrap();
        let path = config_dir.join(".credentials.json");
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn rewrite_credentials_file_replaces_real_pair_with_nonces() {
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path().join(".claude");
        let path = write_credentials_at(
            &config_dir,
            r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-real-access","refreshToken":"sk-ant-ort01-real-refresh","subscriptionType":"max"}}"#,
        );

        let broker = TokenBroker::new();
        rewrite_credentials_file_at(&config_dir, &broker, true).unwrap();

        let rewritten = std::fs::read_to_string(&path).unwrap();
        let parsed: Value = serde_json::from_str(&rewritten).unwrap();
        let oauth = parsed.get("claudeAiOauth").unwrap();
        let new_access = oauth.get("accessToken").unwrap().as_str().unwrap();
        let new_refresh = oauth.get("refreshToken").unwrap().as_str().unwrap();
        assert!(
            new_access.starts_with("nono_"),
            "access not nonced: {new_access}"
        );
        assert!(
            new_refresh.starts_with("nono_"),
            "refresh not nonced: {new_refresh}"
        );
        assert_ne!(new_access, new_refresh);
        assert_eq!(
            oauth.get("subscriptionType").unwrap().as_str().unwrap(),
            "max",
            "non-oauth fields must be preserved across rewrite"
        );

        assert_eq!(
            broker.resolve(new_access).unwrap().as_str(),
            "sk-ant-oat01-real-access"
        );
        assert_eq!(
            broker.resolve(new_refresh).unwrap().as_str(),
            "sk-ant-ort01-real-refresh"
        );
    }

    #[test]
    fn rewrite_credentials_file_is_idempotent_when_nonces_already_present() {
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path().join(".claude");
        let original = r#"{"claudeAiOauth":{"accessToken":"nono_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","refreshToken":"nono_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}"#;
        let path = write_credentials_at(&config_dir, original);

        let broker = TokenBroker::new();
        rewrite_credentials_file_at(&config_dir, &broker, true).unwrap();

        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(after, original, "nonce-bearing file must be left untouched");
    }

    #[test]
    fn rewrite_credentials_file_handles_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path().join(".claude");
        std::fs::create_dir_all(&config_dir).unwrap();

        let broker = TokenBroker::new();
        rewrite_credentials_file_at(&config_dir, &broker, true).unwrap();
    }

    #[test]
    fn rewrite_credentials_file_returns_err_on_malformed_json() {
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path().join(".claude");
        write_credentials_at(&config_dir, "not json at all");

        let broker = TokenBroker::new();
        let err = rewrite_credentials_file_at(&config_dir, &broker, true).unwrap_err();
        assert!(err.to_string().contains("not valid JSON"), "got: {err}");
    }

    #[test]
    #[allow(non_snake_case)]
    fn rewrite_credentials_file_no_claudeAiOauth_object_is_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path().join(".claude");
        let original = r#"{"otherField":"value"}"#;
        let path = write_credentials_at(&config_dir, original);

        let broker = TokenBroker::new();
        rewrite_credentials_file_at(&config_dir, &broker, true).unwrap();

        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(after, original);
    }

    /// Helper: build an env-reader closure from a static slice of pairs.
    fn fake_env(
        pairs: &'static [(&'static str, &'static str)],
    ) -> impl Fn(&str) -> Option<std::ffi::OsString> {
        move |k| {
            pairs
                .iter()
                .find(|(name, _)| *name == k)
                .map(|(_, v)| std::ffi::OsString::from(*v))
        }
    }

    #[test]
    fn capture_oauth_env_vars_swaps_real_oauth_bearer_for_nonce() {
        let broker = TokenBroker::new();
        let mut outcome = PreflightOutcome::default();
        capture_oauth_env_vars_from(
            &broker,
            true,
            fake_env(&[("CLAUDE_CODE_OAUTH_TOKEN", "sk-ant-oat01-real")]),
            &mut outcome,
        );

        assert_eq!(outcome.env_overrides.len(), 1);
        let (key, nonce) = &outcome.env_overrides[0];
        assert_eq!(key, "CLAUDE_CODE_OAUTH_TOKEN");
        assert!(nonce.starts_with("nono_"));
        assert_eq!(
            broker.resolve(nonce).unwrap().as_str(),
            "sk-ant-oat01-real",
            "broker must resolve the nonce back to the captured real token"
        );
    }

    #[test]
    fn capture_oauth_env_vars_skips_empty_and_nonce_prefixed_values() {
        let broker = TokenBroker::new();
        let mut outcome = PreflightOutcome::default();
        capture_oauth_env_vars_from(
            &broker,
            true,
            fake_env(&[
                ("CLAUDE_CODE_OAUTH_TOKEN", ""),
                ("CLAUDE_CODE_OAUTH_REFRESH_TOKEN", "nono_already_captured"),
                ("ANTHROPIC_AUTH_TOKEN", "real_value"),
            ]),
            &mut outcome,
        );
        assert_eq!(
            outcome.env_overrides.len(),
            1,
            "only ANTHROPIC_AUTH_TOKEN should be captured"
        );
        assert_eq!(outcome.env_overrides[0].0, "ANTHROPIC_AUTH_TOKEN");
    }

    #[test]
    fn capture_oauth_env_vars_handles_all_three_known_bearer_vars() {
        let broker = TokenBroker::new();
        let mut outcome = PreflightOutcome::default();
        capture_oauth_env_vars_from(
            &broker,
            true,
            fake_env(&[
                ("CLAUDE_CODE_OAUTH_TOKEN", "access_token"),
                ("CLAUDE_CODE_OAUTH_REFRESH_TOKEN", "refresh_token"),
                ("ANTHROPIC_AUTH_TOKEN", "auth_token"),
            ]),
            &mut outcome,
        );
        assert_eq!(outcome.env_overrides.len(), 3);
        // Each captured original must round-trip through the broker.
        for (key, nonce) in &outcome.env_overrides {
            let expected = match key.as_str() {
                "CLAUDE_CODE_OAUTH_TOKEN" => "access_token",
                "CLAUDE_CODE_OAUTH_REFRESH_TOKEN" => "refresh_token",
                "ANTHROPIC_AUTH_TOKEN" => "auth_token",
                other => panic!("unexpected key {other}"),
            };
            assert_eq!(broker.resolve(nonce).unwrap().as_str(), expected);
        }
    }

    #[test]
    fn detect_api_key_env_var_flags_first_non_empty_match() {
        assert_eq!(detect_api_key_env_var_from(fake_env(&[]), None), None);
        assert_eq!(
            detect_api_key_env_var_from(fake_env(&[("ANTHROPIC_API_KEY", "")]), None),
            None,
            "empty value must not count"
        );
        assert_eq!(
            detect_api_key_env_var_from(
                fake_env(&[("ANTHROPIC_API_KEY", "sk-ant-api03-xxx")]),
                None
            )
            .unwrap(),
            "environment variable ANTHROPIC_API_KEY"
        );
    }

    #[test]
    fn detect_api_key_env_var_skips_vars_denied_by_profile() {
        // A var the profile would deny to the child should not trigger
        // the fail-closed check — the child won't see it regardless.
        let denied = vec!["ANTHROPIC_API_KEY".to_string()];
        assert_eq!(
            detect_api_key_env_var_from(
                fake_env(&[("ANTHROPIC_API_KEY", "sk-ant-api03-real")]),
                Some(&denied),
            ),
            None,
            "denied var must not trigger fail-closed"
        );
        // A different API-key var that is NOT in the deny list should still block.
        assert!(
            detect_api_key_env_var_from(
                fake_env(&[
                    ("ANTHROPIC_API_KEY", "sk-ant-api03-real"),
                    ("ANTHROPIC_UNIX_SOCKET", "/tmp/socket"),
                ]),
                Some(&denied),
            )
            .is_some(),
            "non-denied API-key var must still trigger fail-closed"
        );
    }

    #[test]
    fn detect_api_key_env_var_respects_glob_patterns_in_deny_list() {
        // Profile deny lists can use glob-like patterns (e.g. GITHUB_*).
        // Verify the check delegates to `is_env_var_denied` correctly.
        let denied = vec!["ANTHROPIC_*".to_string()];
        assert_eq!(
            detect_api_key_env_var_from(
                fake_env(&[("ANTHROPIC_API_KEY", "sk-ant-api03-real")]),
                Some(&denied),
            ),
            None,
            "glob-matched denied var must not trigger fail-closed"
        );
    }

    #[test]
    fn detect_primary_api_key_in_file_flags_non_empty_value() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(".claude.json");

        std::fs::write(&path, r#"{"primaryApiKey":"sk-ant-api03-xxx"}"#).unwrap();
        assert!(
            detect_primary_api_key_in_file(&path)
                .unwrap()
                .unwrap()
                .contains("primaryApiKey")
        );

        std::fs::write(&path, r#"{"primaryApiKey":""}"#).unwrap();
        assert!(detect_primary_api_key_in_file(&path).unwrap().is_none());

        std::fs::write(&path, r#"{}"#).unwrap();
        assert!(detect_primary_api_key_in_file(&path).unwrap().is_none());

        std::fs::remove_file(&path).unwrap();
        assert!(
            detect_primary_api_key_in_file(&path).unwrap().is_none(),
            "missing file must not be an error"
        );
    }

    #[test]
    fn rewrite_credentials_file_only_access_token_uses_issue_not_capture_pair() {
        // If the file only has accessToken (no refresh), we still mint a
        // nonce for the access token via `issue` and leave the refresh
        // slot untouched (or empty). `capture_oauth_pair` wouldn't be a
        // good fit because it always persists a pair to the broker store;
        // single-token surfaces just get a session-scoped resolve.
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path().join(".claude");
        let path = write_credentials_at(
            &config_dir,
            r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-only"}}"#,
        );

        let broker = TokenBroker::new();
        rewrite_credentials_file_at(&config_dir, &broker, true).unwrap();

        let after: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let oauth = after.get("claudeAiOauth").unwrap();
        let new_access = oauth.get("accessToken").unwrap().as_str().unwrap();
        assert!(new_access.starts_with("nono_"));
        assert_eq!(
            broker.resolve(new_access).unwrap().as_str(),
            "sk-ant-oat01-only"
        );
        assert!(
            oauth.get("refreshToken").is_none(),
            "must not invent a refresh slot we didn't have"
        );
    }
}
