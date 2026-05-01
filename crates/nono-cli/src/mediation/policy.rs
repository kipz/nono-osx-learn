//! Policy engine for the mediation server.
//!
//! For each incoming `ShimRequest`, this module:
//! 1. Finds the matching `ResolvedCommand` entry.
//! 2. Checks `intercept` rules in order (positional subcommand match).
//! 3. If matched with `Respond`: returns the configured `ShimResponse` without calling the binary.
//! 4. If matched with `Capture`: runs the real binary (or a script), stores output in the broker,
//!    returns a `nono_<hex>` nonce to the sandbox.
//! 5. If not matched: execs the real binary. Nonce-bearing env vars from the sandbox are promoted
//!    (replaced with real values); all other sandbox env vars are discarded.

use super::approval::ApprovalGate;
use super::broker::TokenBroker;
use super::session::{ResolvedAction, ResolvedCommand};
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::os::unix::io::OwnedFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

/// Request forwarded from the shim binary to the mediation server.
///
/// The shim sends this JSON request followed by a single SCM_RIGHTS message
/// carrying stdin/stdout/stderr fds together. The fds are received out-of-band
/// by the server and threaded into `apply` — they are not part of this struct.
#[derive(Debug, Default, Deserialize)]
pub struct ShimRequest {
    pub command: String,
    pub args: Vec<String>,
    /// Session authentication token. Must match the token injected via
    /// `NONO_SESSION_TOKEN`. Requests with a missing or wrong token are
    /// silently rejected. Old shims missing this field fail deserialization
    /// and receive a 127 error — the correct security behaviour.
    pub session_token: String,
    /// Environment variables from the sandbox at invocation time.
    /// Used only for nonce promotion — all non-nonce vars are discarded.
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// PID of the shim process itself — the process that ran this command.
    /// Used to populate `command_pid` in the audit log.
    #[serde(default)]
    pub pid: u32,
    /// Working directory of the shim at invocation time — the caller's cwd.
    /// Used to set the spawned real binary's cwd via `Command::current_dir`.
    /// Without this, the spawned binary inherits the mediation server's cwd
    /// (the nono launch cwd), which silently breaks tools that resolve config
    /// from cwd — git in a worktree being the canonical case. `None` (older
    /// shim, or unreadable cwd) preserves the legacy behaviour.
    #[serde(default)]
    pub cwd: Option<String>,
}

/// Response the mediation server sends back to the shim binary.
#[derive(Debug, Serialize)]
pub struct ShimResponse {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// Mediation session context passed to policy functions.
///
/// Bundles the per-session paths and token needed by `apply` and `exec_passthrough`.
pub struct SessionCtx<'a> {
    pub shim_dir: &'a std::path::Path,
    pub socket_path: &'a std::path::Path,
    pub session_token: &'a str,
    /// Working directory of the nono session (the parent launch cwd or
    /// `--workdir`). Threaded into `expand_vars` so `$WORKDIR` in mediated
    /// sandbox paths resolves consistently across the main and per-command
    /// sandboxes.
    pub workdir: &'a std::path::Path,
}

/// Env var names that must never receive a nonce-promoted value, even if a
/// nonce-bearing var with this name appears in the sandbox env.
static DANGEROUS_ENV_VAR_NAMES: &[&str] = &[
    "PATH",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FORCE_FLAT_NAMESPACE",
    "NONO_SANDBOX_CONTEXT",
];

/// Returns true if a sandbox-supplied env var name is a NONO_GATE_* test-knob
/// that must never be forwarded into a mediated child. NONO_GATE_FORCE_DENY
/// (and similar) force the approval gate into known verdicts; an agent that
/// could smuggle them via `request.env` would bypass the gate. The wider
/// NONO_ prefix is intentionally NOT filtered: nono itself sets
/// NONO_SESSION_TOKEN, NONO_MEDIATION_SOCKET, NONO_BROKER_SOCKET, and
/// NONO_CALLER for sandboxed children.
fn is_nono_gate_var(key: &str) -> bool {
    key.starts_with("NONO_GATE_")
}

/// Apply policy to a shim request and produce a response.
///
/// - If the command is unknown: returns an error response (not found).
/// - If an intercept rule matches with `Respond`: returns the pre-resolved output.
/// - If an intercept rule matches with `Capture`: runs the binary/script, issues a nonce.
/// - Otherwise: execs the real binary with strict env filtering.
///
/// `stdin_fd`/`stdout_fd`/`stderr_fd` are the shim's stdio fds, received via
/// SCM_RIGHTS. The streaming passthrough path moves them into the spawned
/// child via `Stdio::from(...)` so binary streams (ssh/git) are not buffered
/// or corrupted. The `Capture`/`Respond`/`Approve` paths drop them and keep
/// the existing `Stdio::piped()` + `wait_with_output` behaviour.
#[allow(clippy::too_many_arguments)]
pub async fn apply(
    request: ShimRequest,
    commands: &[ResolvedCommand],
    broker: Arc<TokenBroker>,
    ctx: &SessionCtx<'_>,
    approval: Arc<dyn ApprovalGate + Send + Sync>,
    allowlist: Arc<super::allowlist::AllowlistStore>,
    stdin_fd: OwnedFd,
    stdout_fd: OwnedFd,
    stderr_fd: OwnedFd,
) -> (ShimResponse, &'static str) {
    // Note: `allowlist` is not yet consumed by the caller-policy gate below —
    // plan 4.1 will wire it into the on_mismatch=Approve flow there. It is
    // threaded through `apply` once now so future plans can reuse it without
    // another plumbing pass. The argv_shape branch (further down) is the
    // first consumer.
    // Find matching command entry
    let Some(cmd) = commands.iter().find(|c| c.name == request.command) else {
        warn!("mediation: unknown command '{}'", request.command);
        return (
            ShimResponse {
                stdout: String::new(),
                stderr: format!(
                    "nono-mediation: command '{}' not configured\n",
                    request.command
                ),
                exit_code: 127,
            },
            "unknown",
        );
    };

    // Caller-policy gate. Decides whether this caller is permitted to invoke
    // the command at all, before any intercept / sandbox logic runs.
    //
    // - No NONO_SANDBOX_CONTEXT → caller is the agent (primary sandbox).
    //   Reject unless `agent_allowed` is true.
    // - NONO_SANDBOX_CONTEXT present → caller is a mediated parent.
    //   If `allowed_parents` is `Some(list)`, the parent name (resolved via
    //   the broker nonce) must be in `list`. `Some(empty list)` denies all
    //   mediated parents. `None` allows any.
    let caller_parent = request
        .env
        .get("NONO_SANDBOX_CONTEXT")
        .and_then(|nonce| broker.resolve(nonce));
    // Decide whether the caller-policy gate rejects this caller and, if so,
    // whether to hard-deny or consult `approve_with_save_option`.
    //
    // The `parent_name` slot ("agent" or the resolved parent command name) is
    // also the value persisted in the `(cmd, parent, argv)` allowlist key, so
    // a future invocation with the same caller bypasses the gate.
    enum CallerPolicyGate {
        Pass,
        HardDeny { stderr: String },
        Consult { parent_name: String, reason: String },
    }
    let gate_decision = match &caller_parent {
        None => {
            if cmd.caller_policy.agent_allowed {
                CallerPolicyGate::Pass
            } else if cmd.caller_policy.deny_agent_strict {
                warn!(
                    "mediation: hard-denying '{}' from primary sandbox (agent_allowed=false, deny_agent_strict=true)",
                    request.command
                );
                CallerPolicyGate::HardDeny {
                    stderr: format!(
                        "nono-mediation: '{}' cannot be invoked from the primary sandbox\n",
                        request.command
                    ),
                }
            } else {
                let reason = format!(
                    "'{}' attempted by agent — caller-policy denies the agent",
                    request.command
                );
                CallerPolicyGate::Consult {
                    parent_name: "agent".to_string(),
                    reason,
                }
            }
        }
        Some(parent) => {
            let parent_name: &str = parent;
            match &cmd.caller_policy.allowed_parents {
                Some(allowed) if !allowed.iter().any(|p| p == parent_name) => {
                    let reason = format!(
                        "'{}' invoked from unexpected parent '{}' — only {:?} are allowed",
                        request.command, parent_name, allowed
                    );
                    CallerPolicyGate::Consult {
                        parent_name: parent_name.to_string(),
                        reason,
                    }
                }
                _ => CallerPolicyGate::Pass,
            }
        }
    };
    match gate_decision {
        CallerPolicyGate::Pass => {}
        CallerPolicyGate::HardDeny { stderr } => {
            drop(stdin_fd);
            drop(stdout_fd);
            drop(stderr_fd);
            return (
                ShimResponse {
                    stdout: String::new(),
                    stderr,
                    exit_code: 126,
                },
                "denied",
            );
        }
        CallerPolicyGate::Consult { parent_name, reason } => {
            let key = super::allowlist::AllowlistKey {
                kind: super::allowlist::AllowlistKind::CallerPolicy,
                payload: serde_json::json!({
                    "cmd": &cmd.name,
                    "parent": &parent_name,
                    "argv": &request.args,
                }),
            };
            if !allowlist.is_approved(&key) {
                let cmd_name = cmd.name.clone();
                let cmd_args = request.args.clone();
                let approval_clone = Arc::clone(&approval);
                let verdict = tokio::task::spawn_blocking(move || {
                    approval_clone.approve_with_save_option(&cmd_name, &cmd_args, &reason)
                })
                .await
                .unwrap_or(super::approval::ApprovalVerdict::Deny);
                match verdict {
                    super::approval::ApprovalVerdict::AllowOnce => {}
                    super::approval::ApprovalVerdict::AllowAlways => {
                        if let Err(e) = allowlist.record(&key) {
                            warn!(
                                "mediation: allowlist record failed for caller-policy '{}': {}",
                                request.command, e
                            );
                            // Treat as Allow-once on persistence failure.
                        }
                    }
                    super::approval::ApprovalVerdict::Deny => {
                        warn!(
                            "mediation: caller-policy gate denied '{}' (parent={})",
                            request.command, parent_name
                        );
                        drop(stdin_fd);
                        drop(stdout_fd);
                        drop(stderr_fd);
                        return (
                            ShimResponse {
                                stdout: String::new(),
                                stderr: format!(
                                    "nono-mediation: '{}' caller-policy denied by user\n",
                                    request.command
                                ),
                                exit_code: 126,
                            },
                            "denied",
                        );
                    }
                }
            } else {
                debug!(
                    "mediation: caller-policy gate allowlisted '{}' (parent={})",
                    request.command, parent_name
                );
            }
        }
    }

    // If the request comes from within a per-command sandbox (via allow_commands),
    // skip intercepts — credentials flow between trusted sub-processes, not to the agent.
    // The sandbox context nonce is unforgeable (only the server can issue valid nonces).
    if let Some(ctx_nonce) = request.env.get("NONO_SANDBOX_CONTEXT") {
        if let Some(parent_name) = broker.resolve(ctx_nonce) {
            if let Some(parent_cmd) = commands.iter().find(|c| c.name == **parent_name) {
                if let Some(ref sb) = parent_cmd.sandbox {
                    if sb.allow_commands.contains(&request.command) {
                        debug!(
                            "mediation: skipping intercepts for '{}' (called from '{}' via allow_commands)",
                            request.command, &**parent_name
                        );
                        // No per-command sandbox — same as the capture path.
                        // The real binary needs full access to system resources
                        // (e.g. Keychain, vault) to fetch credentials. Security
                        // comes from the parent's sandbox, not the child's.
                        // Stream stdio directly through the shim's fds.
                        let result = exec_passthrough(
                            cmd,
                            &request.args,
                            &request.env,
                            &broker,
                            None,
                            ctx,
                            commands,
                            Some((stdin_fd, stdout_fd, stderr_fd)),
                            request.cwd.as_deref(),
                        )
                        .await;
                        return (result, "passthrough");
                    }
                }
            }
        }
    }

    // Check intercept rules in order
    for rule in &cmd.intercepts {
        // Decide whether this rule fires for this invocation. Three outcomes:
        //   - matched=true: rule fires; proceed to action below.
        //   - matched=false: rule does NOT fire; continue the for-loop.
        //   - early-return with exit 126: argv_shape on_mismatch=Approve +
        //     Deny verdict.
        let matched = match &rule.argv_shape {
            Some(shape) => match argv_shape_matches(shape, &request.args) {
                Ok(()) => true,
                Err(reason) => match shape.on_mismatch {
                    super::OnMismatchPolicy::Deny => false,
                    super::OnMismatchPolicy::Approve => {
                        // Build the allowlist key for this argv-shape mismatch.
                        // Plans 4.1 / 4.3 will use other variants against the
                        // same store.
                        let key = super::allowlist::AllowlistKey {
                            kind: super::allowlist::AllowlistKind::ArgvShape,
                            payload: serde_json::json!({
                                "cmd": &request.command,
                                "argv": &request.args,
                            }),
                        };
                        if allowlist.is_approved(&key) {
                            debug!(
                                "mediation: argv_shape mismatch for '{}' but allowlisted; treating as match",
                                request.command
                            );
                            true
                        } else {
                            // Pop the approval dialog. The reason is
                            // included so the user sees WHY the strict
                            // matcher rejected this exact argv.
                            let cmd_name = request.command.clone();
                            let cmd_args = request.args.clone();
                            let reason_msg = format!(
                                "argv shape mismatch on rule for '{}': {}",
                                cmd_name, reason
                            );
                            let approval_clone = Arc::clone(&approval);
                            let verdict = tokio::task::spawn_blocking(move || {
                                approval_clone.approve_with_save_option(
                                    &cmd_name,
                                    &cmd_args,
                                    &reason_msg,
                                )
                            })
                            .await
                            .unwrap_or(super::approval::ApprovalVerdict::Deny);

                            match verdict {
                                super::approval::ApprovalVerdict::AllowOnce => true,
                                super::approval::ApprovalVerdict::AllowAlways => {
                                    if let Err(e) = allowlist.record(&key) {
                                        warn!(
                                            "mediation: allowlist record failed for '{}': {}",
                                            request.command, e
                                        );
                                        // Treat as Allow-once on persistence failure.
                                    }
                                    true
                                }
                                super::approval::ApprovalVerdict::Deny => {
                                    drop(stdin_fd);
                                    drop(stdout_fd);
                                    drop(stderr_fd);
                                    return (
                                        ShimResponse {
                                            stdout: String::new(),
                                            stderr: format!(
                                                "nono: '{}' was not approved\n",
                                                request.command
                                            ),
                                            exit_code: 126,
                                        },
                                        "denied",
                                    );
                                }
                            }
                        }
                    }
                },
            },
            None => subcommand_matches(&rule.args_prefix, &request.args),
        };
        if matched {
            debug!(
                "mediation: intercepting '{}' (prefix={:?}, argv_shape={})",
                request.command,
                rule.args_prefix,
                rule.argv_shape.is_some()
            );

            // Admin gate: require user authentication before executing this rule.
            if rule.admin {
                let command = request.command.clone();
                let args = request.args.clone();
                let approval_clone = Arc::clone(&approval);
                let allowed =
                    tokio::task::spawn_blocking(move || approval_clone.approve(&command, &args))
                        .await
                        .unwrap_or(false);
                if !allowed {
                    let invocation = if request.args.is_empty() {
                        request.command.clone()
                    } else {
                        format!("{} {}", request.command, request.args.join(" "))
                    };
                    let action_type = match &rule.action {
                        ResolvedAction::Respond { .. } => "respond",
                        ResolvedAction::Capture { .. } => "capture",
                        ResolvedAction::Approve { .. } => "approve",
                    };
                    return (
                        ShimResponse {
                            stdout: String::new(),
                            stderr: format!("nono: '{}' was not approved\n", invocation),
                            exit_code: 126,
                        },
                        action_type,
                    );
                }
            }

            // Buffered intercept paths: the passed stdio fds are not used —
            // the duplicated fds drop here, leaving the originals open in the
            // shim so it can write the buffered response to them.
            drop(stdin_fd);
            drop(stdout_fd);
            drop(stderr_fd);

            return match &rule.action {
                ResolvedAction::Respond { stdout } => (
                    ShimResponse {
                        stdout: stdout.clone(),
                        stderr: String::new(),
                        exit_code: rule.exit_code,
                    },
                    "respond",
                ),
                ResolvedAction::Capture { script } => {
                    let result = match script {
                        Some(sh) => exec_script(sh, &request.env, &broker).await,
                        None => {
                            // No per-command sandbox during capture — the real binary needs
                            // full access to system resources (e.g. Keychain) to fetch the credential.
                            exec_passthrough(
                                cmd,
                                &request.args,
                                &request.env,
                                &broker,
                                None,
                                ctx,
                                commands,
                                None,
                                request.cwd.as_deref(),
                            )
                            .await
                        }
                    };
                    if result.exit_code != 0 {
                        return (result, "capture");
                    }
                    let nonce = broker.issue(Zeroizing::new(result.stdout.trim().to_string()));
                    (
                        ShimResponse {
                            stdout: format!("{}\n", nonce),
                            stderr: String::new(),
                            exit_code: 0,
                        },
                        "capture",
                    )
                }
                ResolvedAction::Approve { script } => {
                    // Run the real binary (or script) and return the actual output.
                    // Typically used with admin: true to gate behind approval.
                    //
                    // No per-command sandbox is applied (None). The real binary
                    // needs unrestricted access to system resources (e.g. macOS
                    // Keychain via mach-lookup to securityd) that a Seatbelt
                    // sandbox would block. Protection comes from the profile
                    // author's deliberate choice of which commands get `approve`.
                    let resp = match script {
                        Some(sh) => exec_script(sh, &request.env, &broker).await,
                        None => {
                            exec_passthrough(
                                cmd,
                                &request.args,
                                &request.env,
                                &broker,
                                None,
                                ctx,
                                commands,
                                None,
                                request.cwd.as_deref(),
                            )
                            .await
                        }
                    };
                    (resp, "approve")
                }
            };
        }
    }

    // No intercept matched — pass through to the real binary, streaming stdio.
    debug!(
        "mediation: passthrough '{}' {:?} -> {}",
        request.command,
        request.args,
        cmd.real_path.display()
    );
    let resp = exec_passthrough(
        cmd,
        &request.args,
        &request.env,
        &broker,
        effective_sandbox(cmd, caller_parent.as_deref().map(|s| s.as_str())),
        ctx,
        commands,
        Some((stdin_fd, stdout_fd, stderr_fd)),
        request.cwd.as_deref(),
    )
    .await;
    (resp, "passthrough")
}

/// Execute the real binary without any mediation — no intercept rules, no env
/// var filtering, no nonce promotion. Used when admin mode is active.
///
/// This is an intentional bypass. The operator explicitly granted admin mode
/// via biometric or password auth. All calls are logged at WARN level.
///
/// Stdio is streamed directly through the shim's passed fds so binary
/// streams (e.g. ssh/git) work correctly under admin mode too.
pub async fn admin_passthrough(
    request: &ShimRequest,
    commands: &[ResolvedCommand],
    stdin_fd: OwnedFd,
    stdout_fd: OwnedFd,
    stderr_fd: OwnedFd,
) -> (ShimResponse, &'static str) {
    let Some(cmd) = commands.iter().find(|c| c.name == request.command) else {
        warn!("admin passthrough: unknown command '{}'", request.command);
        return (
            ShimResponse {
                stdout: String::new(),
                stderr: format!(
                    "nono-mediation: command '{}' not configured\n",
                    request.command
                ),
                exit_code: 127,
            },
            "admin_passthrough",
        );
    };

    // Build env from parent process — no filtering, no nonce promotion.
    let env: HashMap<String, String> = std::env::vars().collect();
    let args = request.args.clone();
    let real_path = cmd.real_path.clone();
    let cmd_name = cmd.name.clone();
    // Resolve caller cwd off the blocking thread so the warning is emitted on
    // the tokio runtime thread.
    let spawn_cwd: Option<std::path::PathBuf> = request.cwd.as_deref().and_then(|cwd| {
        let path = std::path::Path::new(cwd);
        if path.is_dir() {
            Some(path.to_path_buf())
        } else {
            warn!(
                "admin passthrough: caller cwd '{}' is not a directory, spawning '{}' with server cwd",
                cwd, cmd_name
            );
            None
        }
    });

    let result = tokio::task::spawn_blocking(move || -> nono::Result<ShimResponse> {
        use std::process::{Command, Stdio};

        let mut cmd_builder = Command::new(&real_path);
        cmd_builder
            .args(&args)
            .env_clear()
            .envs(&env)
            .stdin(Stdio::from(stdin_fd))
            .stdout(Stdio::from(stdout_fd))
            .stderr(Stdio::from(stderr_fd));
        if let Some(ref cwd) = spawn_cwd {
            cmd_builder.current_dir(cwd);
        }

        let mut child = cmd_builder
            .spawn()
            .map_err(nono::NonoError::CommandExecution)?;

        let status = child.wait().map_err(nono::NonoError::CommandExecution)?;

        Ok(ShimResponse {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: status.code().unwrap_or(1),
        })
    })
    .await;

    let resp = match result {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => ShimResponse {
            stdout: String::new(),
            stderr: format!("nono-mediation: admin passthrough exec failed: {}\n", e),
            exit_code: 1,
        },
        Err(e) => ShimResponse {
            stdout: String::new(),
            stderr: format!("nono-mediation: internal error: {}\n", e),
            exit_code: 1,
        },
    };
    (resp, "admin_passthrough")
}

/// Check if the invocation's positional args start with the given prefix.
///
/// Flags (args starting with `-`) are ignored, allowing matches regardless of
/// flag placement. E.g. `["auth", "github", "token"]` matches both
/// `ddtool auth github token` and `ddtool --debug auth github token`.
pub fn subcommand_matches(prefix: &[String], args: &[String]) -> bool {
    if prefix.is_empty() {
        return true;
    }
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    if prefix.len() > positional.len() {
        return false;
    }
    prefix.iter().zip(positional.iter()).all(|(p, a)| p == *a)
}

/// Match an invocation against a strict `ResolvedArgvShape`.
///
/// Returns Ok(()) on match, Err(reason) on no-match. The Err carries a short
/// reason string useful for tracing/audit. Callers should treat any Err the
/// same way (no match → fall through to the next intercept rule or to
/// passthrough); the reason is not surfaced to the agent.
///
/// Matching semantics (see `ArgvShape` doc):
/// - args[0] must equal shape.subcommand.
/// - Each declared flag must appear exactly once with the declared value
///   (or with no value if Boolean).
/// - With ExtrasPolicy::Deny, any unknown flag or extra positional after
///   args[0] causes a no-match.
/// - With ExtrasPolicy::Allow, extras are tolerated; required-flag rules
///   still apply.
pub fn argv_shape_matches(
    shape: &super::session::ResolvedArgvShape,
    args: &[String],
) -> std::result::Result<(), String> {
    use super::session::ResolvedFlagSpec;
    use super::ExtrasPolicy;

    if args.is_empty() || args[0] != shape.subcommand {
        return Err(format!(
            "subcommand mismatch (want '{}', got args[0]={:?})",
            shape.subcommand,
            args.first()
        ));
    }

    // Walk the rest of args left-to-right, tracking which declared flags
    // we have seen (each must appear exactly once).
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut i = 1usize;
    while i < args.len() {
        let token = args[i].as_str();

        if let Some(spec) = shape.flags.get(token) {
            if !seen.insert(token) {
                return Err(format!("flag '{}' appears more than once", token));
            }
            match spec {
                ResolvedFlagSpec::Required { value } => {
                    let next = args
                        .get(i + 1)
                        .ok_or_else(|| format!("flag '{}' missing required value", token))?;
                    if next != value {
                        return Err(format!(
                            "flag '{}' value mismatch (want '{}', got '{}')",
                            token, value, next
                        ));
                    }
                    i += 2;
                }
                ResolvedFlagSpec::Boolean => {
                    i += 1;
                }
            }
            continue;
        }

        // Token not in declared flags. Either an unknown flag or an extra
        // positional. Both are governed by `extras`.
        match shape.extras {
            ExtrasPolicy::Deny => {
                return Err(format!("unknown token '{}' (extras=Deny)", token));
            }
            ExtrasPolicy::Allow => {
                // Skip unknown token. If it looks like a flag with a value
                // (`-X foo`), we cannot know whether it consumes the next
                // arg. Be conservative: skip just this token. The next iter
                // will inspect the would-be-value; if it equals one of our
                // declared flags, we will see it (correct); if it equals
                // some unknown token, extras=Allow tolerates that too.
                i += 1;
            }
        }
    }

    // Verify every declared flag was seen.
    for declared in shape.flags.keys() {
        if !seen.contains(declared.as_str()) {
            return Err(format!("required flag '{}' not present", declared));
        }
    }
    Ok(())
}

/// Pick the per-command sandbox to apply to a passthrough exec.
///
/// If the request comes from a mediated parent listed in `parent_sandbox`,
/// return that override. Otherwise fall back to the command's default
/// sandbox (which may itself be `None`). Agent callers (no parent) always
/// receive the default sandbox.
fn effective_sandbox(
    cmd: &ResolvedCommand,
    caller_parent: Option<&str>,
) -> Option<super::CommandSandbox> {
    if let Some(parent) = caller_parent {
        if let Some(sb) = cmd.caller_policy.parent_sandbox.get(parent) {
            return Some(sb.clone());
        }
    }
    cmd.sandbox.clone()
}

/// Execute a shell script and collect its output.
///
/// Uses the same strict env-building as `exec_passthrough`: starts from the
/// trusted parent env, promotes nonce-bearing sandbox vars, blocks dangerous names.
async fn exec_script(
    script: &str,
    sandbox_env: &HashMap<String, String>,
    broker: &Arc<TokenBroker>,
) -> ShimResponse {
    let env = build_exec_env(sandbox_env, broker);
    let script = script.to_string();

    let result = tokio::task::spawn_blocking(move || -> Result<ShimResponse> {
        use std::process::{Command, Stdio};

        let child = Command::new("sh")
            .args(["-c", &script])
            .env_clear()
            .envs(&env)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(NonoError::CommandExecution)?;

        let output = child
            .wait_with_output()
            .map_err(NonoError::CommandExecution)?;
        Ok(ShimResponse {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            exit_code: output.status.code().unwrap_or(1),
        })
    })
    .await;

    match result {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => ShimResponse {
            stdout: String::new(),
            stderr: format!("nono-mediation: script exec failed: {}\n", e),
            exit_code: 1,
        },
        Err(e) => ShimResponse {
            stdout: String::new(),
            stderr: format!("nono-mediation: internal error: {}\n", e),
            exit_code: 1,
        },
    }
}

/// Atomic counter for generating unique filtered shim directory names.
static FILTERED_SHIM_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Execute the real binary and collect its output.
///
/// Env building:
/// - Starts from the trusted parent (mediation server) environment.
/// - Prepends `shim_dir` to PATH so subprocess invocations of mediated commands
///   route through the mediation server instead of running directly inside the
///   per-command sandbox (where network is restricted).
/// - From the sandbox env, promotes only nonce-bearing vars (`nono_` prefix).
///   All other sandbox env vars are discarded to prevent sandbox injection.
/// - Dangerous var names (PATH, LD_PRELOAD, etc.) are blocked even with valid nonces.
/// - Arg nonces: any arg starting with `nono_` is replaced with the real value.
///
/// When `allow_commands` is non-empty on the sandbox, a filtered shim directory is
/// created containing symlinks only for commands NOT in the allow list. Allowed
/// commands run directly (real binary) inside the per-command sandbox.
///
/// `stdio_fds`:
/// - `Some((stdin, stdout, stderr))`: streaming mode — the real binary inherits
///   the shim's fds directly, the response carries empty stdout/stderr and the
///   call uses `wait()` instead of `wait_with_output()`. This is required for
///   binary streams (ssh, git over ssh) and avoids buffering for any
///   long-running command (gh, kubectl, dd-attest, etc.).
/// - `None`: buffered mode — the real binary's stdout/stderr are captured
///   into the `ShimResponse` (used by Capture/Approve flows so the server can
///   inspect or relay the output).
#[allow(clippy::too_many_arguments)]
async fn exec_passthrough(
    cmd: &ResolvedCommand,
    args: &[String],
    sandbox_env: &HashMap<String, String>,
    broker: &Arc<TokenBroker>,
    sandbox: Option<super::CommandSandbox>,
    ctx: &SessionCtx<'_>,
    all_commands: &[ResolvedCommand],
    stdio_fds: Option<(OwnedFd, OwnedFd, OwnedFd)>,
    request_cwd: Option<&str>,
) -> ShimResponse {
    let mut env = build_exec_env(sandbox_env, broker);

    // Build the effective shim directory and PATH.
    // When allow_commands is set, create a filtered shim dir that excludes allowed
    // commands so they resolve to their real binaries instead of routing through mediation.
    let allow_commands = sandbox
        .as_ref()
        .map(|sb| &sb.allow_commands)
        .filter(|ac| !ac.is_empty());

    let (effective_shim_dir, _filtered_dir_guard) = if let Some(allow_cmds) = allow_commands {
        match build_filtered_shim_dir(ctx.shim_dir, allow_cmds, all_commands) {
            Ok((dir, guard)) => (dir, Some(guard)),
            Err(e) => {
                return ShimResponse {
                    stdout: String::new(),
                    stderr: format!(
                        "nono-mediation: failed to create filtered shim dir: {}\n",
                        e
                    ),
                    exit_code: 1,
                };
            }
        }
    } else {
        (ctx.shim_dir.to_path_buf(), None)
    };

    let shim_dir_str = effective_shim_dir.to_string_lossy().to_string();
    let parent_path = env
        .get("PATH")
        .cloned()
        .unwrap_or_else(|| "/usr/bin:/bin".to_string());

    // For allowed commands, prepend their real binary directories after the shim dir
    // so they resolve to the real binary (which won't have a shim in the filtered dir).
    let mut path_parts = vec![shim_dir_str.clone()];
    if let Some(allow_cmds) = allow_commands {
        let mut seen_dirs: HashSet<String> = HashSet::new();
        for allowed_name in allow_cmds {
            if let Some(allowed_cmd) = all_commands.iter().find(|c| c.name == *allowed_name) {
                // Only add real binary dirs for commands without their own mediation.
                // Commands with intercepts or sandbox keep their shim and route through
                // the mediation server, so they don't need the real binary on PATH.
                let has_mediation =
                    !allowed_cmd.intercepts.is_empty() || allowed_cmd.sandbox.is_some();
                if has_mediation {
                    continue;
                }
                if let Some(parent) = allowed_cmd.real_path.parent() {
                    let dir_str = parent.to_string_lossy().to_string();
                    if seen_dirs.insert(dir_str.clone()) {
                        path_parts.push(dir_str);
                    }
                }
            }
        }
    }
    path_parts.push(parent_path);
    env.insert("PATH".to_string(), path_parts.join(":"));

    // Update NONO_SHIM_DIR to point to the effective shim dir (which may be a
    // filtered shim dir when allow_commands is set). The nono-shim binary uses
    // this to skip its own directory when resolving the real binary. Without
    // this, shims in the filtered dir would skip the wrong directory and find
    // themselves again, causing infinite exec recursion (EAGAIN).
    env.insert("NONO_SHIM_DIR".to_string(), shim_dir_str.clone());

    // Inject mediation socket path and session token so the shim binaries
    // invoked by the exec'd command can authenticate to the mediation server.
    // This allows exec plugins (e.g. kubectl's credential plugin) to route
    // through mediation rather than running directly in the per-command sandbox.
    env.insert(
        "NONO_MEDIATION_SOCKET".to_string(),
        ctx.socket_path.to_string_lossy().to_string(),
    );
    env.insert(
        "NONO_SESSION_TOKEN".to_string(),
        ctx.session_token.to_string(),
    );

    // Inject a sandbox context nonce so the mediation server can identify
    // shim requests originating from within this per-command sandbox.
    // This allows the server to skip intercepts for allow_commands calls
    // (credentials flow between trusted sub-processes, not to the agent).
    // The nonce is unforgeable — only the server can issue valid nonces.
    let sandbox_context_nonce = broker.issue(Zeroizing::new(cmd.name.clone()));
    env.insert("NONO_SANDBOX_CONTEXT".to_string(), sandbox_context_nonce);

    // Promote nonce values in args
    let args: Vec<String> = args
        .iter()
        .map(|a| {
            if a.starts_with("nono_") {
                broker
                    .resolve(a)
                    .map(|r| r.as_str().to_string())
                    .unwrap_or_else(|| a.clone())
            } else {
                a.clone()
            }
        })
        .collect();

    let real_path = cmd.real_path.clone();
    let cmd_name = cmd.name.clone();
    // Owned shim paths for use in spawn_blocking (which requires 'static captures).
    let shim_dir_buf = effective_shim_dir.clone();
    let real_shim_binary = std::fs::canonicalize(ctx.shim_dir.join(&cmd.name)).ok();
    // Own the session workdir for use inside spawn_blocking (profile::expand_vars
    // borrows it).
    let workdir_buf = ctx.workdir.to_path_buf();

    // Collect allowed command binary directories for sandbox read capabilities.
    let allowed_binary_dirs: Vec<std::path::PathBuf> = sandbox
        .as_ref()
        .map(|sb| &sb.allow_commands)
        .filter(|ac| !ac.is_empty())
        .map(|allow_cmds| {
            allow_cmds
                .iter()
                .filter_map(|name| {
                    all_commands
                        .iter()
                        .find(|c| c.name == *name)
                        .and_then(|c| c.real_path.parent())
                        .filter(|p| p.exists())
                        .map(|p| p.to_path_buf())
                })
                .collect()
        })
        .unwrap_or_default();

    // Start a per-command proxy if allowed_hosts is configured (and block is not set).
    let mut proxy_handle: Option<nono_proxy::ProxyHandle> = None;
    let mut proxy_port: Option<u16> = None;

    if let Some(ref sb) = sandbox {
        if !sb.network.allowed_hosts.is_empty() && !sb.network.block {
            let proxy_config = nono_proxy::ProxyConfig {
                allowed_hosts: sb.network.allowed_hosts.clone(),
                ..Default::default()
            };
            match nono_proxy::start(proxy_config).await {
                Ok(handle) => {
                    for (k, v) in handle.env_vars() {
                        env.insert(k, v);
                    }
                    proxy_port = Some(handle.port);
                    proxy_handle = Some(handle);
                }
                Err(e) => {
                    return ShimResponse {
                        stdout: String::new(),
                        stderr: format!("nono-mediation: failed to start network proxy: {}\n", e),
                        exit_code: 1,
                    };
                }
            }
        }
    }

    let maybe_sandbox = sandbox;

    let streaming = stdio_fds.is_some();

    // Resolve the spawn cwd once, off the spawn_blocking thread, so we can log
    // a warning if the caller's cwd is unusable. We only honour it when it
    // points at an existing directory; otherwise the spawned binary inherits
    // the server's cwd (legacy behaviour). `None` (older shim or unreadable
    // cwd) also falls back to legacy behaviour.
    let spawn_cwd: Option<std::path::PathBuf> = request_cwd.and_then(|cwd| {
        let path = std::path::Path::new(cwd);
        if path.is_dir() {
            Some(path.to_path_buf())
        } else {
            warn!(
                "mediation: caller cwd '{}' is not a directory, spawning '{}' with server cwd",
                cwd, cmd_name
            );
            None
        }
    });

    let result = tokio::task::spawn_blocking(move || -> Result<ShimResponse> {
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};

        let mut cmd_builder = Command::new(&real_path);
        cmd_builder.args(&args).env_clear().envs(&env);
        if let Some(ref cwd) = spawn_cwd {
            cmd_builder.current_dir(cwd);
        }

        // Streaming: child inherits the shim's stdio fds directly so binary
        // data (ssh/git) flows through unmodified. Buffered: capture stdout
        // and stderr so the server can read them (e.g. Capture nonce flow).
        match stdio_fds {
            Some((stdin_fd, stdout_fd, stderr_fd)) => {
                cmd_builder
                    .stdin(Stdio::from(stdin_fd))
                    .stdout(Stdio::from(stdout_fd))
                    .stderr(Stdio::from(stderr_fd));
            }
            None => {
                cmd_builder
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
            }
        }

        if let Some(sb) = maybe_sandbox {
            let mut caps = nono::CapabilitySet::new();

            // Apply platform system read+write paths so the binary can actually exec
            // and use standard devices (e.g. /dev/null). Mirrors the system groups
            // applied to the main sandbox.
            if let Ok(policy) = crate::policy::load_embedded_policy() {
                let (read_group, write_group) = if cfg!(target_os = "macos") {
                    ("system_read_macos", "system_write_macos")
                } else {
                    ("system_read_linux", "system_write_linux")
                };
                let _ = crate::policy::resolve_groups(
                    &policy,
                    &[read_group.to_string(), write_group.to_string()],
                    &mut caps,
                );
            }

            // Also allow the binary's own directory, in case it lives outside the standard
            // system paths (e.g. ~/dd/devtools/bin/gh). Use the ORIGINAL (pre-canonicalize)
            // parent so FsCapability emits Seatbelt rules for both the symlink path and the
            // resolved canonical path — Seatbelt checks paths as-accessed (pre-resolution).
            if let Some(parent) = real_path.parent() {
                if parent.exists() {
                    caps = caps.allow_path(parent, nono::AccessMode::Read)?;
                }
            }

            // Allow the shim directory and the nono-shim binary so that subprocesses
            // of the exec'd command (e.g. kubectl's exec credential plugin) can exec
            // the shim binaries and route through the mediation server.
            caps = caps.allow_path(&shim_dir_buf, nono::AccessMode::Read)?;
            if let Some(ref real_shim) = real_shim_binary {
                caps = caps.allow_file(real_shim, nono::AccessMode::Read)?;
            }

            // Allow read access to directories of allowed commands so they can exec
            // their real binaries directly (bypassing the shim).
            for dir in &allowed_binary_dirs {
                caps = caps.allow_path(dir, nono::AccessMode::Read)?;
            }

            // Add command-specific configured paths. `~` and `$VAR` tokens
            // (including $WORKDIR, $HOME, XDG dirs, and any env var set at
            // launch time such as $GIT_ROOT) are resolved via `expand_vars`
            // so they behave identically to top-level sandbox paths.
            for path in &sb.fs_read {
                let expanded = expand_sandbox_path(path, &workdir_buf, &cmd_name);
                caps = add_sandbox_dir(caps, &expanded, nono::AccessMode::Read, &cmd_name)?;
            }
            for path in &sb.fs_read_file {
                let expanded = expand_sandbox_path(path, &workdir_buf, &cmd_name);
                caps = add_sandbox_file(caps, &expanded, nono::AccessMode::Read, &cmd_name)?;
            }
            for path in &sb.fs_write {
                let expanded = expand_sandbox_path(path, &workdir_buf, &cmd_name);
                caps = add_sandbox_dir(caps, &expanded, nono::AccessMode::Write, &cmd_name)?;
            }
            for path in &sb.fs_write_file {
                let expanded = expand_sandbox_path(path, &workdir_buf, &cmd_name);
                caps = add_sandbox_file(caps, &expanded, nono::AccessMode::Write, &cmd_name)?;
            }
            // macOS Keychain access: grant read to keychain DB files so the
            // Seatbelt profile skips its mach-lookup denies for security daemons.
            // This allows the command to retrieve credentials from the system
            // keychain without exposing them to the agent (the token flows through
            // the command's internal auth, not stdout).
            #[cfg(target_os = "macos")]
            if sb.keychain_access {
                if let Ok(home) = std::env::var("HOME") {
                    let login = format!("{}/Library/Keychains/login.keychain-db", home);
                    let metadata = format!("{}/Library/Keychains/metadata.keychain-db", home);
                    caps = add_sandbox_file(caps, &login, nono::AccessMode::Read, &cmd_name)?;
                    caps = add_sandbox_file(caps, &metadata, nono::AccessMode::Read, &cmd_name)?;
                }
            }

            if sb.network.block {
                caps = caps.block_network();
            } else if let Some(port) = proxy_port {
                caps = caps.proxy_only(port);
            }

            // Nono is responsible for ensuring sandboxed child processes can always
            // reach the mediation server via its Unix domain socket, regardless of
            // network mode. The shim injected into PATH needs AF_UNIX socket creation
            // (system-socket) and the ability to connect to a unix-socket path
            // (network-outbound). Without these, nested nono-mediated commands (e.g.
            // `git remote -v` called from a git hook) cannot reach the mediation server
            // even under AllowAll network mode, because (deny default) blocks
            // system-socket() calls unless explicitly allowed.
            for rule in [
                "(allow system-socket (socket-domain AF_UNIX))",
                "(allow network-outbound (remote unix-socket))",
            ] {
                if let Err(e) = caps.add_platform_rule(rule) {
                    warn!("mediation: failed to add mediation socket rule: {}", e);
                }
            }
            unsafe {
                cmd_builder.pre_exec(move || {
                    nono::Sandbox::apply(&caps).map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::PermissionDenied, e.to_string())
                    })
                });
            }
        }

        let mut child = cmd_builder.spawn().map_err(NonoError::CommandExecution)?;

        if streaming {
            // Streaming: stdio is connected directly to the shim's fds. Just
            // wait for exit; there is no buffered output to collect.
            let status = child.wait().map_err(NonoError::CommandExecution)?;
            Ok(ShimResponse {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: status.code().unwrap_or(1),
            })
        } else {
            let output = child
                .wait_with_output()
                .map_err(NonoError::CommandExecution)?;
            Ok(ShimResponse {
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                exit_code: output.status.code().unwrap_or(1),
            })
        }
    })
    .await;

    if let Some(handle) = proxy_handle {
        handle.shutdown();
    }

    match result {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => ShimResponse {
            stdout: String::new(),
            stderr: format!("nono-mediation: exec failed: {}\n", e),
            exit_code: 1,
        },
        Err(e) => ShimResponse {
            stdout: String::new(),
            stderr: format!("nono-mediation: internal error: {}\n", e),
            exit_code: 1,
        },
    }
}

/// Build a filtered shim directory containing symlinks only for commands NOT
/// in the `allow_commands` list. Returns the path and a guard that cleans up
/// on drop. The directory is created under the session dir (derived from the
/// shim_dir's parent) so `SessionHandle::drop` also cleans it up.
fn build_filtered_shim_dir(
    shim_dir: &std::path::Path,
    allow_commands: &[String],
    all_commands: &[ResolvedCommand],
) -> Result<(std::path::PathBuf, FilteredShimDirGuard)> {
    let allow_set: HashSet<&str> = allow_commands.iter().map(|s| s.as_str()).collect();

    // Derive directory under the session dir for automatic cleanup.
    let session_dir = shim_dir
        .parent()
        .ok_or_else(|| NonoError::SandboxInit("mediation: shim_dir has no parent".to_string()))?;
    let counter = FILTERED_SHIM_COUNTER.fetch_add(1, Ordering::Relaxed);
    let filtered_dir = session_dir.join(format!("filtered-shims-{}", counter));

    std::fs::create_dir_all(&filtered_dir).map_err(|e| {
        NonoError::SandboxInit(format!(
            "mediation: failed to create filtered shim dir {}: {}",
            filtered_dir.display(),
            e
        ))
    })?;

    // For each shim in the original shim_dir, symlink it into the filtered dir
    // unless the command is in the allow list.
    let entries = std::fs::read_dir(shim_dir).map_err(|e| {
        NonoError::SandboxInit(format!(
            "mediation: failed to read shim dir {}: {}",
            shim_dir.display(),
            e
        ))
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| {
            NonoError::SandboxInit(format!("mediation: failed to read shim dir entry: {}", e))
        })?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if allow_set.contains(name_str.as_ref()) {
            // If the allowed command has its own mediation rules (intercepts or sandbox),
            // keep the shim so it routes through the mediation server. Only exclude
            // commands that have no mediation and should resolve to real binaries directly.
            let has_mediation = all_commands
                .iter()
                .any(|c| c.name == name_str && (!c.intercepts.is_empty() || c.sandbox.is_some()));
            if has_mediation {
                debug!(
                    "mediation: keeping shim for '{}' in filtered dir (has own mediation rules)",
                    name_str
                );
            } else {
                debug!(
                    "mediation: allowing direct exec for '{}' (excluded from filtered shim dir)",
                    name_str
                );
                continue;
            }
        }

        // Symlink the original shim (which itself points to nono-shim)
        let src = entry.path();
        let dst = filtered_dir.join(&name);
        std::os::unix::fs::symlink(&src, &dst).map_err(|e| {
            NonoError::SandboxInit(format!(
                "mediation: failed to symlink {} -> {}: {}",
                dst.display(),
                src.display(),
                e
            ))
        })?;
    }

    // Log the allowed commands and their real paths for auditability.
    for allowed_name in allow_commands {
        if let Some(cmd) = all_commands.iter().find(|c| c.name == *allowed_name) {
            debug!(
                "mediation: allow_commands '{}' -> {} (direct exec in per-command sandbox)",
                allowed_name,
                cmd.real_path.display()
            );
        }
    }

    let guard = FilteredShimDirGuard {
        path: filtered_dir.clone(),
    };
    Ok((filtered_dir, guard))
}

/// RAII guard that removes the filtered shim directory on drop.
/// The session dir cleanup also handles this, but this ensures prompt cleanup
/// when the exec_passthrough call completes.
struct FilteredShimDirGuard {
    path: std::path::PathBuf,
}

impl Drop for FilteredShimDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Expand `~` and `$VAR` / `${VAR}` tokens in a per-command sandbox path.
///
/// Delegates to `crate::profile::expand_vars`, which matches the main-sandbox
/// expansion (supports `$WORKDIR`, `$HOME`, XDG vars, `$TMPDIR`, `$UID`, and
/// generic env vars). On failure (e.g. invalid `$HOME`), falls back to the
/// raw path — `add_sandbox_*` will then log "does not exist, skipping" which
/// is the same outcome as an unset variable. This preserves robustness: a
/// misconfigured env var in one entry never aborts the whole session.
fn expand_sandbox_path(path: &str, workdir: &std::path::Path, cmd_name: &str) -> String {
    match crate::profile::expand_vars(path, workdir) {
        Ok(buf) => buf.to_string_lossy().into_owned(),
        Err(e) => {
            warn!(
                "mediation: command '{}' failed to expand sandbox path '{}': {}",
                cmd_name, path, e
            );
            path.to_string()
        }
    }
}

/// Add a directory capability to the sandbox.
/// Warns and skips on non-existent paths.
fn add_sandbox_dir(
    caps: nono::CapabilitySet,
    path: &str,
    access: nono::AccessMode,
    command_name: &str,
) -> Result<nono::CapabilitySet> {
    match nono::FsCapability::new_dir(path, access) {
        Ok(cap) => {
            let mut caps = caps;
            caps.add_fs(cap);
            Ok(caps)
        }
        Err(NonoError::PathNotFound(_)) => {
            warn!(
                "mediation: command '{}' sandbox dir '{}' does not exist, skipping",
                command_name, path
            );
            Ok(caps)
        }
        Err(e) => Err(e),
    }
}

/// Add a file capability to the sandbox.
/// Warns and skips on non-existent paths.
fn add_sandbox_file(
    caps: nono::CapabilitySet,
    path: &str,
    access: nono::AccessMode,
    command_name: &str,
) -> Result<nono::CapabilitySet> {
    match nono::FsCapability::new_file(path, access) {
        Ok(cap) => {
            let mut caps = caps;
            caps.add_fs(cap);
            Ok(caps)
        }
        Err(NonoError::PathNotFound(_)) => {
            warn!(
                "mediation: command '{}' sandbox file '{}' does not exist, skipping",
                command_name, path
            );
            Ok(caps)
        }
        Err(e) => Err(e),
    }
}

/// Build the environment map for an exec'd child.
///
/// Starts from the trusted parent env, then promotes nonce-bearing sandbox vars.
/// Non-nonce sandbox vars and dangerous var names are silently discarded.
fn build_exec_env(
    sandbox_env: &HashMap<String, String>,
    broker: &Arc<TokenBroker>,
) -> HashMap<String, String> {
    // Start from parent (trusted) env
    let mut env: HashMap<String, String> = std::env::vars().collect();

    // From sandbox env: promote nonce-bearing vars and forward all other non-dangerous
    // vars. If a var was not blocked by the profile's `env.block` list it is permitted
    // to flow through to mediated commands. System execution vars (PATH, LD_PRELOAD,
    // etc.) are always blocked as defense-in-depth regardless of profile configuration.
    for (key, value) in sandbox_env {
        if DANGEROUS_ENV_VAR_NAMES.contains(&key.as_str()) {
            warn!("mediation: blocked dangerous var {} from sandbox env", key);
            continue;
        }
        if is_nono_gate_var(key) {
            warn!(
                "mediation: blocked NONO_GATE_* test-knob {} from sandbox env",
                key
            );
            continue;
        }
        if value.starts_with("nono_") {
            if let Some(real) = broker.resolve(value) {
                env.insert(key.clone(), real.as_str().to_string());
            }
            // Unknown nonce: silently discard — don't let sandbox probe broker contents.
        } else {
            env.insert(key.clone(), value.clone());
        }
    }

    env
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediation::approval::{AlwaysAllow, AlwaysDeny};
    use crate::mediation::session::{ResolvedCommand, ResolvedIntercept};
    use crate::mediation::CallerPolicy;
    use std::path::PathBuf;

    fn make_broker() -> Arc<TokenBroker> {
        Arc::new(TokenBroker::new())
    }

    fn always_allow() -> Arc<dyn ApprovalGate + Send + Sync> {
        Arc::new(AlwaysAllow)
    }

    fn always_deny() -> Arc<dyn ApprovalGate + Send + Sync> {
        Arc::new(AlwaysDeny)
    }

    fn make_cmd(intercepts: Vec<ResolvedIntercept>) -> ResolvedCommand {
        ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/true"),
            intercepts,
            sandbox: None,
            caller_policy: CallerPolicy::default(),
        }
    }

    /// Test harness for the streaming-passthrough fd protocol.
    ///
    /// Holds the test-side of the three socketpairs that back the child's
    /// stdin/stdout/stderr. Tests call `make_passthrough_fds()` to get the
    /// child fds (to pass into `apply`) plus this harness. Drainer threads
    /// (started by `apply_capture`) consume the child's output concurrently
    /// so a chatty child can't block on a full socketpair buffer.
    struct PassthroughHarness {
        stdin_writer: std::os::unix::net::UnixStream,
        stdout_reader: std::os::unix::net::UnixStream,
        stderr_reader: std::os::unix::net::UnixStream,
    }

    /// Create three socketpair-backed fds for streaming passthrough tests.
    ///
    /// Returns `(child_stdin, child_stdout, child_stderr, harness)`. Pass the
    /// three `OwnedFd`s into `apply`; keep `harness` bound until after `apply`
    /// returns so the child does not see EPIPE while writing.
    fn make_passthrough_fds() -> (OwnedFd, OwnedFd, OwnedFd, PassthroughHarness) {
        use std::os::unix::net::UnixStream;
        let (child_in, test_in) = UnixStream::pair().expect("socketpair stdin");
        let (child_out, test_out) = UnixStream::pair().expect("socketpair stdout");
        let (child_err, test_err) = UnixStream::pair().expect("socketpair stderr");
        (
            OwnedFd::from(child_in),
            OwnedFd::from(child_out),
            OwnedFd::from(child_err),
            PassthroughHarness {
                stdin_writer: test_in,
                stdout_reader: test_out,
                stderr_reader: test_err,
            },
        )
    }

    /// Test wrapper around `apply` that handles the new fd-passing protocol.
    ///
    /// Creates a streaming socketpair harness, drains stdout/stderr in
    /// background threads while the child runs (so a chatty child cannot
    /// block on a full socketpair buffer), and merges what the child
    /// streamed into the returned `ShimResponse` so existing tests can
    /// continue to assert on `resp.stdout`/`resp.stderr` regardless of
    /// whether the path was streaming (passthrough) or buffered (Capture/
    /// Respond/Approve).
    /// Build a fresh tempdir-backed allowlist for tests. The tempdir is
    /// leaked so its lifetime spans the test process — acceptable here.
    fn make_allowlist() -> Arc<crate::mediation::allowlist::AllowlistStore> {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("argv-allowlist.json");
        std::mem::forget(dir);
        Arc::new(
            crate::mediation::allowlist::AllowlistStore::open_at(path)
                .expect("open allowlist"),
        )
    }

    async fn apply_capture(
        req: ShimRequest,
        cmds: &[ResolvedCommand],
        broker: Arc<TokenBroker>,
        ctx: &SessionCtx<'_>,
        approval: Arc<dyn ApprovalGate + Send + Sync>,
    ) -> (ShimResponse, &'static str) {
        apply_capture_with_allowlist(req, cmds, broker, ctx, approval, make_allowlist()).await
    }

    async fn apply_capture_with_allowlist(
        req: ShimRequest,
        cmds: &[ResolvedCommand],
        broker: Arc<TokenBroker>,
        ctx: &SessionCtx<'_>,
        approval: Arc<dyn ApprovalGate + Send + Sync>,
        allowlist: Arc<crate::mediation::allowlist::AllowlistStore>,
    ) -> (ShimResponse, &'static str) {
        let (stdin_fd, stdout_fd, stderr_fd, harness) = make_passthrough_fds();

        // Close the parent-side stdin writer so any child that reads stdin
        // sees an immediate EOF instead of hanging.
        drop(harness.stdin_writer);

        let stdout_reader = harness.stdout_reader;
        let stderr_reader = harness.stderr_reader;
        let stdout_handle = std::thread::spawn(move || {
            use std::io::Read;
            let mut buf = Vec::new();
            let _ = (&stdout_reader).read_to_end(&mut buf);
            buf
        });
        let stderr_handle = std::thread::spawn(move || {
            use std::io::Read;
            let mut buf = Vec::new();
            let _ = (&stderr_reader).read_to_end(&mut buf);
            buf
        });

        let (mut resp, action) = apply(
            req, cmds, broker, ctx, approval, allowlist, stdin_fd, stdout_fd, stderr_fd,
        )
        .await;

        let stdout_streamed = stdout_handle.join().unwrap_or_default();
        let stderr_streamed = stderr_handle.join().unwrap_or_default();

        if resp.stdout.is_empty() {
            resp.stdout = String::from_utf8_lossy(&stdout_streamed).into_owned();
        }
        if resp.stderr.is_empty() {
            resp.stderr = String::from_utf8_lossy(&stderr_streamed).into_owned();
        }
        (resp, action)
    }

    #[tokio::test]
    async fn test_unknown_command_returns_127() {
        let req = ShimRequest {
            command: "doesnotexist".to_string(),
            args: vec![],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, _action_type) = apply_capture(
            req,
            &[],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;
        assert_eq!(resp.exit_code, 127);
    }

    // --- caller_policy gate ---

    fn ctx() -> SessionCtx<'static> {
        SessionCtx {
            shim_dir: std::path::Path::new("/tmp"),
            socket_path: std::path::Path::new("/tmp/test.sock"),
            session_token: "test_token",
            workdir: std::path::Path::new("/tmp"),
        }
    }

    /// Default `CallerPolicy` (agent_allowed=true, allowed_parents=None) lets
    /// the agent invoke a command. Regression for backward compatibility:
    /// existing profiles that omit `caller_policy` keep the old behaviour.
    #[tokio::test]
    async fn test_caller_policy_agent_allowed_by_default() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec![],
            argv_shape: None,
            action: ResolvedAction::Respond {
                stdout: "ok\n".to_string(),
            },
            exit_code: 0,
            admin: false,
        }]);
        // Default caller_policy from make_cmd.
        assert!(cmd.caller_policy.agent_allowed);
        assert!(cmd.caller_policy.allowed_parents.is_none());

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            // No NONO_SANDBOX_CONTEXT — caller is the agent.
            ..Default::default()
        };
        let (resp, action) =
            apply_capture(req, &[cmd], make_broker(), &ctx(), always_allow()).await;
        assert_eq!(action, "respond");
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, "ok\n");
    }

    /// `agent_allowed: false` consults the approval gate; on `Deny` the call
    /// is rejected with exit 126. `always_deny()` simulates the user choosing
    /// "deny" at the prompt.
    #[tokio::test]
    async fn test_caller_policy_rejects_agent_when_agent_allowed_false() {
        let mut cmd = make_cmd(vec![]);
        cmd.caller_policy = CallerPolicy {
            agent_allowed: false,
            allowed_parents: Some(vec!["git".to_string()]),
            parent_sandbox: std::collections::HashMap::new(),
            deny_agent_strict: false,
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, action) =
            apply_capture(req, &[cmd], make_broker(), &ctx(), always_deny()).await;
        assert_eq!(action, "denied");
        assert_eq!(resp.exit_code, 126);
        assert!(
            resp.stderr.contains("caller-policy denied"),
            "stderr should mention caller-policy denial: {}",
            resp.stderr
        );
    }

    /// `allowed_parents: Some(["git"])` permits ssh-from-git: the broker
    /// resolves the request's NONO_SANDBOX_CONTEXT nonce to "git" and the
    /// gate falls through to the existing policy logic.
    #[tokio::test]
    async fn test_caller_policy_allows_listed_parent() {
        let mut cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec![],
            argv_shape: None,
            action: ResolvedAction::Respond {
                stdout: "from_git\n".to_string(),
            },
            exit_code: 0,
            admin: false,
        }]);
        cmd.caller_policy = CallerPolicy {
            agent_allowed: false,
            allowed_parents: Some(vec!["git".to_string()]),
            parent_sandbox: std::collections::HashMap::new(),
            deny_agent_strict: false,
        };

        let broker = make_broker();
        let nonce = broker.issue(Zeroizing::new("git".to_string()));
        let mut env = HashMap::new();
        env.insert("NONO_SANDBOX_CONTEXT".to_string(), nonce);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            env,
            pid: 0,
            cwd: None,
        };
        let (resp, action) = apply_capture(req, &[cmd], broker, &ctx(), always_allow()).await;
        assert_eq!(action, "respond", "stderr: {}", resp.stderr);
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, "from_git\n");
    }

    /// A parent not in `allowed_parents` consults the gate; on `Deny` the
    /// call is rejected with exit 126.
    #[tokio::test]
    async fn test_caller_policy_rejects_unlisted_parent() {
        let mut cmd = make_cmd(vec![]);
        cmd.caller_policy = CallerPolicy {
            agent_allowed: true,
            allowed_parents: Some(vec!["git".to_string()]),
            parent_sandbox: std::collections::HashMap::new(),
            deny_agent_strict: false,
        };

        let broker = make_broker();
        // Caller is "kubectl", not in the allowed list.
        let nonce = broker.issue(Zeroizing::new("kubectl".to_string()));
        let mut env = HashMap::new();
        env.insert("NONO_SANDBOX_CONTEXT".to_string(), nonce);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            env,
            pid: 0,
            cwd: None,
        };
        let (resp, action) = apply_capture(req, &[cmd], broker, &ctx(), always_deny()).await;
        assert_eq!(action, "denied");
        assert_eq!(resp.exit_code, 126);
        assert!(
            resp.stderr.contains("caller-policy denied"),
            "stderr should mention caller-policy denial: {}",
            resp.stderr
        );
    }

    /// `allowed_parents: Some(vec![])` (explicit empty list) blocks every
    /// mediated parent. With `agent_allowed: true` the command is still
    /// reachable from the agent — useful for "agent-only" tools. The gate
    /// still mediates: `always_deny()` here simulates the user denying.
    #[tokio::test]
    async fn test_caller_policy_empty_allowed_parents_blocks_all_parents() {
        let mut cmd = make_cmd(vec![]);
        cmd.caller_policy = CallerPolicy {
            agent_allowed: true,
            allowed_parents: Some(vec![]),
            parent_sandbox: std::collections::HashMap::new(),
            deny_agent_strict: false,
        };

        let broker = make_broker();
        let nonce = broker.issue(Zeroizing::new("git".to_string()));
        let mut env = HashMap::new();
        env.insert("NONO_SANDBOX_CONTEXT".to_string(), nonce);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            env,
            pid: 0,
            cwd: None,
        };
        let (resp, action) = apply_capture(req, &[cmd], broker, &ctx(), always_deny()).await;
        assert_eq!(action, "denied");
        assert_eq!(resp.exit_code, 126);
    }

    /// `allowed_parents: None` (the default) accepts any mediated parent —
    /// preserves backward compatibility with profiles that don't set the field.
    #[tokio::test]
    async fn test_caller_policy_none_allowed_parents_accepts_any() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec![],
            argv_shape: None,
            action: ResolvedAction::Respond {
                stdout: "any_parent_ok\n".to_string(),
            },
            exit_code: 0,
            admin: false,
        }]);
        // Confirm default state.
        assert!(cmd.caller_policy.allowed_parents.is_none());

        let broker = make_broker();
        let nonce = broker.issue(Zeroizing::new("anything".to_string()));
        let mut env = HashMap::new();
        env.insert("NONO_SANDBOX_CONTEXT".to_string(), nonce);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            env,
            pid: 0,
            cwd: None,
        };
        let (resp, action) = apply_capture(req, &[cmd], broker, &ctx(), always_allow()).await;
        assert_eq!(action, "respond");
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, "any_parent_ok\n");
    }

    #[tokio::test]
    async fn test_intercept_respond_exact_prefix_match() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec![
                "auth".to_string(),
                "github".to_string(),
                "token".to_string(),
            ],
            argv_shape: None,
            action: ResolvedAction::Respond {
                stdout: "static_output\n".to_string(),
            },
            exit_code: 0,
            admin: false,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![
                "auth".to_string(),
                "github".to_string(),
                "token".to_string(),
            ],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, _action_type) = apply_capture(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, "static_output\n");
    }

    // --- argv_shape integration tests ---

    /// End-to-end: an `argv_shape` rule with extras=Deny rejects the
    /// duplicate-`-s` bypass. The malicious invocation falls through to a
    /// fallback rule, NOT the strict rule's output.
    #[tokio::test]
    async fn test_apply_argv_shape_rejects_duplicate_flag_bypass() {
        use crate::mediation::session::{ResolvedArgvShape, ResolvedFlagSpec};
        use crate::mediation::{ExtrasPolicy, OnMismatchPolicy};

        let strict = ResolvedIntercept {
            args_prefix: vec![],
            argv_shape: Some(ResolvedArgvShape {
                subcommand: "find-generic-password".to_string(),
                flags: {
                    let mut m = std::collections::BTreeMap::new();
                    m.insert(
                        "-a".to_string(),
                        ResolvedFlagSpec::Required {
                            value: "tester".to_string(),
                        },
                    );
                    m.insert(
                        "-s".to_string(),
                        ResolvedFlagSpec::Required {
                            value: "Claude Code-credentials".to_string(),
                        },
                    );
                    m.insert("-w".to_string(), ResolvedFlagSpec::Boolean);
                    m
                },
                extras: ExtrasPolicy::Deny,
                on_mismatch: OnMismatchPolicy::Deny,
            }),
            action: ResolvedAction::Respond {
                stdout: "STRICT_APPROVED\n".to_string(),
            },
            exit_code: 0,
            admin: false,
        };
        let fallback = ResolvedIntercept {
            args_prefix: vec!["find-generic-password".to_string()],
            argv_shape: None,
            action: ResolvedAction::Respond {
                stdout: "FALLBACK_CAPTURE\n".to_string(),
            },
            exit_code: 0,
            admin: false,
        };
        let cmd = ResolvedCommand {
            name: "security".to_string(),
            real_path: PathBuf::from("/usr/bin/true"),
            intercepts: vec![strict, fallback],
            sandbox: None,
            caller_policy: CallerPolicy::default(),
        };

        // Malicious: appends a second `-s evil-service`.
        let req = ShimRequest {
            command: "security".to_string(),
            args: vec![
                "find-generic-password".to_string(),
                "-a".to_string(),
                "tester".to_string(),
                "-s".to_string(),
                "Claude Code-credentials".to_string(),
                "-s".to_string(),
                "evil-service".to_string(),
                "-w".to_string(),
            ],
            session_token: String::new(),
            ..Default::default()
        };

        let (resp, _) = apply_capture(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;
        assert_eq!(
            resp.stdout, "FALLBACK_CAPTURE\n",
            "duplicate-flag attack must NOT match strict rule; got: {:?}",
            resp.stdout
        );
    }

    /// Canonical invocation hits the strict rule.
    #[tokio::test]
    async fn test_apply_argv_shape_matches_canonical_invocation() {
        use crate::mediation::session::{ResolvedArgvShape, ResolvedFlagSpec};
        use crate::mediation::{ExtrasPolicy, OnMismatchPolicy};

        let strict = ResolvedIntercept {
            args_prefix: vec![],
            argv_shape: Some(ResolvedArgvShape {
                subcommand: "find-generic-password".to_string(),
                flags: {
                    let mut m = std::collections::BTreeMap::new();
                    m.insert(
                        "-a".to_string(),
                        ResolvedFlagSpec::Required {
                            value: "tester".to_string(),
                        },
                    );
                    m.insert(
                        "-s".to_string(),
                        ResolvedFlagSpec::Required {
                            value: "Claude Code-credentials".to_string(),
                        },
                    );
                    m.insert("-w".to_string(), ResolvedFlagSpec::Boolean);
                    m
                },
                extras: ExtrasPolicy::Deny,
                on_mismatch: OnMismatchPolicy::Deny,
            }),
            action: ResolvedAction::Respond {
                stdout: "STRICT_APPROVED\n".to_string(),
            },
            exit_code: 0,
            admin: false,
        };
        let cmd = ResolvedCommand {
            name: "security".to_string(),
            real_path: PathBuf::from("/usr/bin/true"),
            intercepts: vec![strict],
            sandbox: None,
            caller_policy: CallerPolicy::default(),
        };

        let req = ShimRequest {
            command: "security".to_string(),
            args: vec![
                "find-generic-password".to_string(),
                "-a".to_string(),
                "tester".to_string(),
                "-s".to_string(),
                "Claude Code-credentials".to_string(),
                "-w".to_string(),
            ],
            session_token: String::new(),
            ..Default::default()
        };

        let (resp, _) = apply_capture(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;
        assert_eq!(resp.stdout, "STRICT_APPROVED\n");
    }

    /// argv_shape with on_mismatch=Approve and a Deny verdict from the gate
    /// returns exit 126 and does NOT fall through to the next rule.
    #[tokio::test]
    async fn test_apply_argv_shape_on_mismatch_approve_deny_returns_126() {
        use crate::mediation::session::{ResolvedArgvShape, ResolvedFlagSpec};
        use crate::mediation::{ExtrasPolicy, OnMismatchPolicy};

        let strict = ResolvedIntercept {
            args_prefix: vec![],
            argv_shape: Some(ResolvedArgvShape {
                subcommand: "find-generic-password".to_string(),
                flags: {
                    let mut m = std::collections::BTreeMap::new();
                    m.insert(
                        "-a".to_string(),
                        ResolvedFlagSpec::Required {
                            value: "tester".to_string(),
                        },
                    );
                    m
                },
                extras: ExtrasPolicy::Deny,
                on_mismatch: OnMismatchPolicy::Approve,
            }),
            action: ResolvedAction::Respond {
                stdout: "MATCHED\n".to_string(),
            },
            exit_code: 0,
            admin: false,
        };
        let fallback = ResolvedIntercept {
            args_prefix: vec!["find-generic-password".to_string()],
            argv_shape: None,
            action: ResolvedAction::Respond {
                stdout: "FALLBACK\n".to_string(),
            },
            exit_code: 0,
            admin: false,
        };
        let cmd = ResolvedCommand {
            name: "security".to_string(),
            real_path: PathBuf::from("/usr/bin/true"),
            intercepts: vec![strict, fallback],
            sandbox: None,
            caller_policy: CallerPolicy::default(),
        };

        // Mismatching args (no -a) trigger Approve flow with AlwaysDeny gate.
        let req = ShimRequest {
            command: "security".to_string(),
            args: vec!["find-generic-password".to_string()],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, action) = apply_capture(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_deny(),
        )
        .await;
        assert_eq!(action, "denied");
        assert_eq!(resp.exit_code, 126);
        // CRUCIAL: must NOT have fallen through to the FALLBACK rule.
        assert_ne!(
            resp.stdout, "FALLBACK\n",
            "Approve+Deny must short-circuit, not fall through"
        );
    }

    /// argv_shape with on_mismatch=Approve and an AllowOnce verdict treats
    /// the rule as matched — its action fires.
    #[tokio::test]
    async fn test_apply_argv_shape_on_mismatch_approve_allow_once_fires_action() {
        use crate::mediation::approval::AlwaysAllowOnce;
        use crate::mediation::session::{ResolvedArgvShape, ResolvedFlagSpec};
        use crate::mediation::{ExtrasPolicy, OnMismatchPolicy};

        let strict = ResolvedIntercept {
            args_prefix: vec![],
            argv_shape: Some(ResolvedArgvShape {
                subcommand: "find-generic-password".to_string(),
                flags: {
                    let mut m = std::collections::BTreeMap::new();
                    m.insert(
                        "-a".to_string(),
                        ResolvedFlagSpec::Required {
                            value: "tester".to_string(),
                        },
                    );
                    m
                },
                extras: ExtrasPolicy::Deny,
                on_mismatch: OnMismatchPolicy::Approve,
            }),
            action: ResolvedAction::Respond {
                stdout: "MATCHED\n".to_string(),
            },
            exit_code: 0,
            admin: false,
        };
        let cmd = ResolvedCommand {
            name: "security".to_string(),
            real_path: PathBuf::from("/usr/bin/true"),
            intercepts: vec![strict],
            sandbox: None,
            caller_policy: CallerPolicy::default(),
        };

        let req = ShimRequest {
            command: "security".to_string(),
            args: vec!["find-generic-password".to_string()],
            session_token: String::new(),
            ..Default::default()
        };
        let approval: Arc<dyn ApprovalGate + Send + Sync> = Arc::new(AlwaysAllowOnce);
        let (resp, _) = apply_capture(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            approval,
        )
        .await;
        assert_eq!(resp.stdout, "MATCHED\n");
    }

    /// argv_shape with on_mismatch=Approve and an AllowAlways verdict
    /// records the (command, argv) tuple in the allowlist AND fires the
    /// action. A second invocation with the same argv hits the allowlist
    /// and skips the prompt — even with a Deny gate.
    #[tokio::test]
    async fn test_apply_argv_shape_on_mismatch_approve_allow_always_persists() {
        use crate::mediation::approval::{AlwaysAllowAlways, AlwaysDeny};
        use crate::mediation::session::{ResolvedArgvShape, ResolvedFlagSpec};
        use crate::mediation::{ExtrasPolicy, OnMismatchPolicy};

        let strict = ResolvedIntercept {
            args_prefix: vec![],
            argv_shape: Some(ResolvedArgvShape {
                subcommand: "find-generic-password".to_string(),
                flags: {
                    let mut m = std::collections::BTreeMap::new();
                    m.insert(
                        "-a".to_string(),
                        ResolvedFlagSpec::Required {
                            value: "tester".to_string(),
                        },
                    );
                    m
                },
                extras: ExtrasPolicy::Deny,
                on_mismatch: OnMismatchPolicy::Approve,
            }),
            action: ResolvedAction::Respond {
                stdout: "MATCHED\n".to_string(),
            },
            exit_code: 0,
            admin: false,
        };
        let cmd = ResolvedCommand {
            name: "security".to_string(),
            real_path: PathBuf::from("/usr/bin/true"),
            intercepts: vec![strict],
            sandbox: None,
            caller_policy: CallerPolicy::default(),
        };

        // Single shared allowlist across both invocations.
        let dir = tempfile::tempdir().expect("tempdir");
        let allowlist = Arc::new(
            crate::mediation::allowlist::AllowlistStore::open_at(
                dir.path().join("argv-allowlist.json"),
            )
            .expect("open"),
        );

        // First invocation: AlwaysAllowAlways -> record + fire.
        {
            let req = ShimRequest {
                command: "security".to_string(),
                args: vec!["find-generic-password".to_string()],
                session_token: String::new(),
                ..Default::default()
            };
            let approval: Arc<dyn ApprovalGate + Send + Sync> = Arc::new(AlwaysAllowAlways);
            let (resp, _) = apply_capture_with_allowlist(
                req,
                std::slice::from_ref(&cmd),
                make_broker(),
                &SessionCtx {
                    shim_dir: std::path::Path::new("/tmp"),
                    socket_path: std::path::Path::new("/tmp/test.sock"),
                    session_token: "test_token",
                    workdir: std::path::Path::new("/tmp"),
                },
                approval,
                Arc::clone(&allowlist),
            )
            .await;
            assert_eq!(resp.stdout, "MATCHED\n", "first invocation should fire action");
        }

        // Verify the allowlist actually persisted the entry.
        let key = crate::mediation::allowlist::AllowlistKey {
            kind: crate::mediation::allowlist::AllowlistKind::ArgvShape,
            payload: serde_json::json!({
                "cmd": "security",
                "argv": ["find-generic-password"],
            }),
        };
        assert!(
            allowlist.is_approved(&key),
            "AllowAlways must record to the allowlist"
        );

        // Second invocation: SAME args, AlwaysDeny gate. Allowlist hit means
        // we skip the prompt entirely; gate is never consulted.
        {
            let req = ShimRequest {
                command: "security".to_string(),
                args: vec!["find-generic-password".to_string()],
                session_token: String::new(),
                ..Default::default()
            };
            let approval: Arc<dyn ApprovalGate + Send + Sync> = Arc::new(AlwaysDeny);
            let (resp, _) = apply_capture_with_allowlist(
                req,
                &[cmd],
                make_broker(),
                &SessionCtx {
                    shim_dir: std::path::Path::new("/tmp"),
                    socket_path: std::path::Path::new("/tmp/test.sock"),
                    session_token: "test_token",
                    workdir: std::path::Path::new("/tmp"),
                },
                approval,
                Arc::clone(&allowlist),
            )
            .await;
            assert_eq!(
                resp.stdout, "MATCHED\n",
                "second invocation should hit allowlist and skip the deny gate"
            );
        }
    }

    /// Cross-plan smoke test: the caller-policy gate returns exit 126 for an
    /// agent caller when `agent_allowed: false` and the user denies, even
    /// though `apply` now receives an additional `allowlist` parameter and
    /// the gate is consulted instead of hard-denied (plan 4.1 task 3.5).
    #[tokio::test]
    async fn test_apply_caller_policy_gate_unchanged_with_allowlist_param() {
        let mut cmd = make_cmd(vec![]);
        cmd.caller_policy = CallerPolicy {
            agent_allowed: false,
            allowed_parents: Some(vec!["git".to_string()]),
            parent_sandbox: std::collections::HashMap::new(),
            deny_agent_strict: false,
        };
        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            ..Default::default()
        };
        // Use the allowlist-aware helper to assert the param is plumbed.
        let allowlist = make_allowlist();
        let (resp, action) = apply_capture_with_allowlist(
            req,
            &[cmd],
            make_broker(),
            &ctx(),
            always_deny(),
            allowlist,
        )
        .await;
        assert_eq!(action, "denied");
        assert_eq!(resp.exit_code, 126);
        assert!(
            resp.stderr.contains("caller-policy denied"),
            "stderr should mention caller-policy denial: {}",
            resp.stderr
        );
    }

    #[tokio::test]
    async fn test_intercept_prefix_matches_longer_args() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec!["auth".to_string()],
            argv_shape: None,
            action: ResolvedAction::Respond {
                stdout: "matched\n".to_string(),
            },
            exit_code: 0,
            admin: false,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["auth".to_string(), "github".to_string()],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, _action_type) = apply_capture(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, "matched\n");
    }

    #[tokio::test]
    async fn test_no_intercept_match_falls_through() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec!["auth".to_string(), "github".to_string()],
            argv_shape: None,
            action: ResolvedAction::Respond {
                stdout: "secret\n".to_string(),
            },
            exit_code: 0,
            admin: false,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["status".to_string()],
            session_token: String::new(),
            ..Default::default()
        };
        // Falls through to passthrough exec of /usr/bin/true
        let (resp, _action_type) = apply_capture(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;
        assert_eq!(resp.exit_code, 0);
    }

    #[tokio::test]
    async fn test_admin_rule_allow_proceeds() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec!["repo".to_string(), "delete".to_string()],
            argv_shape: None,
            action: ResolvedAction::Respond {
                stdout: "deleted\n".to_string(),
            },
            exit_code: 0,
            admin: true,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["repo".to_string(), "delete".to_string()],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, _action_type) = apply_capture(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, "deleted\n");
    }

    #[tokio::test]
    async fn test_admin_rule_deny_blocks() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec!["repo".to_string(), "delete".to_string()],
            argv_shape: None,
            action: ResolvedAction::Respond {
                stdout: "deleted\n".to_string(),
            },
            exit_code: 0,
            admin: true,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["repo".to_string(), "delete".to_string()],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, _action_type) = apply_capture(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_deny(),
        )
        .await;
        assert_eq!(resp.exit_code, 126);
        assert!(resp.stderr.contains("was not approved"));
    }

    #[tokio::test]
    async fn test_non_admin_rule_skips_gate() {
        // admin=false rule with AlwaysDeny gate — gate must NOT be called, action executes.
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec!["status".to_string()],
            argv_shape: None,
            action: ResolvedAction::Respond {
                stdout: "ok\n".to_string(),
            },
            exit_code: 0,
            admin: false,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["status".to_string()],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, _action_type) = apply_capture(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_deny(),
        )
        .await;
        // Gate not consulted; action executes normally.
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, "ok\n");
    }

    // --- subcommand_matches tests ---

    #[test]
    fn test_subcommand_matches_basic() {
        assert!(subcommand_matches(
            &["a".to_string(), "b".to_string()],
            &["a".to_string(), "b".to_string(), "c".to_string()]
        ));
        assert!(subcommand_matches(&[], &["a".to_string()]));
        assert!(!subcommand_matches(
            &["a".to_string(), "b".to_string()],
            &["a".to_string()]
        ));
        assert!(!subcommand_matches(&["a".to_string()], &["b".to_string()]));
    }

    #[test]
    fn test_subcommand_matches_ignores_leading_flags() {
        // --debug before positional args should not break matching
        assert!(subcommand_matches(
            &[
                "auth".to_string(),
                "github".to_string(),
                "token".to_string()
            ],
            &[
                "--debug".to_string(),
                "auth".to_string(),
                "github".to_string(),
                "token".to_string(),
            ]
        ));
    }

    #[test]
    fn test_subcommand_matches_ignores_interleaved_flags() {
        // flags between subcommands should be ignored
        assert!(subcommand_matches(
            &["auth".to_string(), "github".to_string()],
            &[
                "auth".to_string(),
                "--verbose".to_string(),
                "github".to_string(),
            ]
        ));
    }

    #[test]
    fn test_subcommand_matches_empty_prefix_matches_anything() {
        assert!(subcommand_matches(&[], &[]));
        assert!(subcommand_matches(&[], &["anything".to_string()]));
    }

    #[test]
    fn test_subcommand_matches_flag_value_injection_does_not_defeat_prefix() {
        // Inserting a flag+value pair inserts an extra positional ("kipz"),
        // which shifts real positionals and defeats a prefix that relied on
        // their positions. This test documents the known limitation:
        // profiles must not rely on a value arg appearing at a specific
        // positional index — use a catch-all prefix for the subcommand instead.
        assert!(!subcommand_matches(
            &[
                "find-generic-password".to_string(),
                "gh:github.com".to_string(),
            ],
            &[
                "find-generic-password".to_string(),
                "-a".to_string(),
                "kipz".to_string(), // injected positional shifts "gh:github.com"
                "-s".to_string(),
                "gh:github.com".to_string(),
                "-w".to_string(),
            ]
        ));
    }

    // --- argv_shape_matches tests ---

    use crate::mediation::session::ResolvedArgvShape;
    use crate::mediation::session::ResolvedFlagSpec;
    use crate::mediation::{ExtrasPolicy, OnMismatchPolicy};

    fn shape(
        subcommand: &str,
        flags: &[(&str, ResolvedFlagSpec)],
        extras: ExtrasPolicy,
    ) -> ResolvedArgvShape {
        ResolvedArgvShape {
            subcommand: subcommand.to_string(),
            flags: flags
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
            extras,
            on_mismatch: OnMismatchPolicy::Deny,
        }
    }

    fn req(value: &str) -> ResolvedFlagSpec {
        ResolvedFlagSpec::Required {
            value: value.to_string(),
        }
    }

    fn s(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| a.to_string()).collect()
    }

    #[test]
    fn test_argv_shape_matches_canonical_security_invocation() {
        let shape = shape(
            "find-generic-password",
            &[("-a", req("kipz")), ("-s", req("Claude Code-credentials"))],
            ExtrasPolicy::Deny,
        );
        assert!(argv_shape_matches(
            &shape,
            &s(&["find-generic-password", "-a", "kipz", "-s", "Claude Code-credentials", "-w"]),
        ).is_err()); // "-w" is an extra → Deny → no match
    }

    #[test]
    fn test_argv_shape_matches_when_no_extras() {
        let shape = shape(
            "find-generic-password",
            &[("-a", req("kipz")), ("-s", req("Claude Code-credentials"))],
            ExtrasPolicy::Deny,
        );
        let r = argv_shape_matches(
            &shape,
            &s(&["find-generic-password", "-a", "kipz", "-s", "Claude Code-credentials"]),
        );
        assert!(r.is_ok(), "expected match, got: {:?}", r);
    }

    #[test]
    fn test_argv_shape_matches_with_boolean_flag() {
        let shape = shape(
            "find-generic-password",
            &[
                ("-a", req("kipz")),
                ("-s", req("Claude Code-credentials")),
                ("-w", ResolvedFlagSpec::Boolean),
            ],
            ExtrasPolicy::Deny,
        );
        let r = argv_shape_matches(
            &shape,
            &s(&["find-generic-password", "-a", "kipz", "-s", "Claude Code-credentials", "-w"]),
        );
        assert!(r.is_ok(), "expected match, got: {:?}", r);
    }

    #[test]
    fn test_argv_shape_rejects_duplicate_required_flag() {
        // The bypass: agent passes `-s Claude Code-credentials -s evil-service`.
        // security itself uses the LAST -s value (evil-service) but a prefix
        // matcher would happily approve based on the FIRST one. The shape
        // matcher must reject duplicates.
        let shape = shape(
            "find-generic-password",
            &[("-a", req("kipz")), ("-s", req("Claude Code-credentials"))],
            ExtrasPolicy::Deny,
        );
        let r = argv_shape_matches(
            &shape,
            &s(&["find-generic-password", "-a", "kipz", "-s", "Claude Code-credentials", "-s", "evil-service"]),
        );
        assert!(r.is_err(), "duplicate -s must reject the match");
    }

    #[test]
    fn test_argv_shape_rejects_wrong_flag_value() {
        let shape = shape(
            "find-generic-password",
            &[("-s", req("Claude Code-credentials"))],
            ExtrasPolicy::Deny,
        );
        let r = argv_shape_matches(
            &shape,
            &s(&["find-generic-password", "-s", "wrong-service"]),
        );
        assert!(r.is_err());
    }

    #[test]
    fn test_argv_shape_rejects_missing_required_flag() {
        let shape = shape(
            "find-generic-password",
            &[("-a", req("kipz")), ("-s", req("Claude Code-credentials"))],
            ExtrasPolicy::Deny,
        );
        let r = argv_shape_matches(
            &shape,
            &s(&["find-generic-password", "-s", "Claude Code-credentials"]),
        );
        assert!(r.is_err(), "missing -a must reject");
    }

    #[test]
    fn test_argv_shape_rejects_unknown_flag_when_extras_deny() {
        let shape = shape(
            "find-generic-password",
            &[("-a", req("kipz"))],
            ExtrasPolicy::Deny,
        );
        let r = argv_shape_matches(
            &shape,
            &s(&["find-generic-password", "-a", "kipz", "-x", "anything"]),
        );
        assert!(r.is_err(), "unknown flag with extras=Deny must reject");
    }

    #[test]
    fn test_argv_shape_tolerates_unknown_flag_when_extras_allow() {
        let shape = shape(
            "find-generic-password",
            &[("-a", req("kipz"))],
            ExtrasPolicy::Allow,
        );
        let r = argv_shape_matches(
            &shape,
            &s(&["find-generic-password", "-a", "kipz", "-x", "anything"]),
        );
        assert!(r.is_ok(), "unknown flag with extras=Allow must match");
    }

    #[test]
    fn test_argv_shape_rejects_wrong_subcommand() {
        let shape = shape("find-generic-password", &[], ExtrasPolicy::Deny);
        let r = argv_shape_matches(&shape, &s(&["delete-generic-password"]));
        assert!(r.is_err());
    }

    #[test]
    fn test_argv_shape_rejects_extra_positional_when_extras_deny() {
        let shape = shape(
            "find-generic-password",
            &[("-a", req("kipz"))],
            ExtrasPolicy::Deny,
        );
        let r = argv_shape_matches(
            &shape,
            &s(&["find-generic-password", "extra-positional", "-a", "kipz"]),
        );
        assert!(r.is_err());
    }

    #[test]
    fn test_argv_shape_boolean_flag_must_not_consume_next_arg() {
        // -w is boolean; the "kipz" that follows is the value of -a, not -w.
        let shape = shape(
            "find-generic-password",
            &[("-w", ResolvedFlagSpec::Boolean), ("-a", req("kipz"))],
            ExtrasPolicy::Deny,
        );
        let r = argv_shape_matches(
            &shape,
            &s(&["find-generic-password", "-w", "-a", "kipz"]),
        );
        assert!(r.is_ok(), "-w must not consume -a; got: {:?}", r);
    }

    /// Boundary test for the documented `extras=Allow` "skip just this token"
    /// semantic. argv is `["sub", "-x", "-a", "evil"]` with declared `-a $USER`.
    /// The matcher walks left-to-right: `-x` is unknown — under extras=Allow it
    /// is skipped (just this token, not the next). The next iter inspects `-a`,
    /// which IS declared as Required("kipz"). Its value-arg is "evil" (≠ "kipz"),
    /// so the match fails on the `-a` value mismatch — NOT because `-x` consumed
    /// `-a`. This pins down the conservative "skip one token" semantic from
    /// `argv_shape_matches`'s extras=Allow branch (see policy.rs comments). If
    /// a future refactor changes that branch to also skip the value-arg of an
    /// unknown flag, this test will start failing — which is the intended
    /// signal for re-reviewing the security implications.
    #[test]
    fn test_argv_shape_extras_allow_skips_only_unknown_token_not_its_value() {
        let shape = shape(
            "sub",
            &[("-a", req("kipz"))],
            ExtrasPolicy::Allow,
        );
        let r = argv_shape_matches(
            &shape,
            &s(&["sub", "-x", "-a", "evil"]),
        );
        assert!(
            r.is_err(),
            "declared -a must consume 'evil' (the token after -a) and reject the value mismatch; got: {:?}",
            r
        );
    }

    // --- Capture tests ---

    #[tokio::test]
    async fn test_capture_runs_real_binary_and_returns_nonce() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec!["auth".to_string()],
            argv_shape: None,
            action: ResolvedAction::Capture { script: None },
            exit_code: 0,
            admin: false,
        }]);
        // Use a command that outputs something: `echo hello` → "hello"
        let cmd = ResolvedCommand {
            real_path: PathBuf::from("/bin/echo"),
            ..cmd
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            // args passed to echo: "auth" "hello" → output "auth hello"
            args: vec!["auth".to_string(), "hello".to_string()],
            session_token: String::new(),
            ..Default::default()
        };
        let broker = make_broker();
        let (resp, _action_type) = apply_capture(
            req,
            &[cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;
        assert_eq!(resp.exit_code, 0);
        assert!(
            resp.stdout.trim().starts_with("nono_"),
            "stdout was: {}",
            resp.stdout
        );
        // The nonce resolves to the trimmed stdout of `echo auth hello`
        let nonce = resp.stdout.trim();
        let resolved = broker.resolve(nonce).expect("nonce should be in broker");
        assert_eq!(resolved.as_str(), "auth hello");
    }

    #[tokio::test]
    async fn test_capture_script_returns_nonce() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec!["auth".to_string()],
            argv_shape: None,
            action: ResolvedAction::Capture {
                script: Some("echo my_secret_token".to_string()),
            },
            exit_code: 0,
            admin: false,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["auth".to_string()],
            session_token: String::new(),
            ..Default::default()
        };
        let broker = make_broker();
        let (resp, _action_type) = apply_capture(
            req,
            &[cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;
        assert_eq!(resp.exit_code, 0);
        let nonce = resp.stdout.trim();
        assert!(nonce.starts_with("nono_"), "expected nonce, got: {}", nonce);
        let resolved = broker.resolve(nonce).expect("nonce should be in broker");
        assert_eq!(resolved.as_str(), "my_secret_token");
    }

    // --- Env filtering tests ---

    #[test]
    fn test_build_exec_env_forwards_context_vars_and_blocks_dangerous() {
        let broker = make_broker();
        let mut sandbox_env = HashMap::new();
        // Dangerous vars must never be forwarded.
        sandbox_env.insert("PATH".to_string(), "/evil".to_string());
        sandbox_env.insert("LD_PRELOAD".to_string(), "/evil.so".to_string());
        // Non-dangerous context vars (e.g. from kubectl exec plugin config) should
        // be forwarded when not already in the parent env. Use an unlikely-to-exist key.
        sandbox_env.insert(
            "NONO_TEST_CONTEXT_12345".to_string(),
            "context_value".to_string(),
        );

        let env = build_exec_env(&sandbox_env, &broker);

        // Dangerous vars must not be injected from sandbox.
        assert_ne!(env.get("PATH").map(|s| s.as_str()), Some("/evil"));
        assert_ne!(env.get("LD_PRELOAD").map(|s| s.as_str()), Some("/evil.so"));
        // Non-dangerous context var should be forwarded.
        assert_eq!(
            env.get("NONO_TEST_CONTEXT_12345").map(|s| s.as_str()),
            Some("context_value")
        );
    }

    #[test]
    fn test_build_exec_env_promotes_valid_nonce() {
        let broker = make_broker();
        let nonce = broker.issue(Zeroizing::new("real_credential".to_string()));

        let mut sandbox_env = HashMap::new();
        sandbox_env.insert("GH_TOKEN".to_string(), nonce.clone());

        let env = build_exec_env(&sandbox_env, &broker);
        assert_eq!(
            env.get("GH_TOKEN").map(|s| s.as_str()),
            Some("real_credential")
        );
    }

    #[test]
    fn test_build_exec_env_blocks_dangerous_var_even_with_valid_nonce() {
        let broker = make_broker();
        let nonce = broker.issue(Zeroizing::new("/evil/path".to_string()));

        let mut sandbox_env = HashMap::new();
        sandbox_env.insert("PATH".to_string(), nonce.clone());
        sandbox_env.insert("LD_PRELOAD".to_string(), nonce.clone());

        let env = build_exec_env(&sandbox_env, &broker);
        // PATH from sandbox must not be the injected value (parent PATH is used instead)
        assert_ne!(env.get("PATH").map(|s| s.as_str()), Some("/evil/path"));
        // LD_PRELOAD should not have been injected
        assert_ne!(
            env.get("LD_PRELOAD").map(|s| s.as_str()),
            Some("/evil/path")
        );
    }

    #[test]
    fn test_build_exec_env_discards_unknown_nonce() {
        let broker = make_broker();
        let mut sandbox_env = HashMap::new();
        // A nonce-like value that was never issued
        sandbox_env.insert(
            "MY_TOKEN".to_string(),
            "nono_0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        );

        let env = build_exec_env(&sandbox_env, &broker);
        // Unknown nonce: var should not be set to any nonce value
        assert_ne!(
            env.get("MY_TOKEN").map(|s| s.as_str()),
            Some("nono_0000000000000000000000000000000000000000000000000000000000000000")
        );
    }

    /// An agent must not be able to smuggle NONO_GATE_* test-knobs into a
    /// mediated child via `sandbox_env`. NONO_GATE_FORCE_DENY (and any other
    /// NONO_GATE_* var) forces the approval gate into a known verdict; a
    /// sandboxed agent that could set it would bypass the gate.
    #[test]
    fn test_build_exec_env_strips_nono_gate_prefix_from_sandbox_env() {
        let broker = make_broker();
        let mut sandbox_env = HashMap::new();
        sandbox_env.insert(
            "NONO_GATE_FORCE_DENY".to_string(),
            "from-agent-sandbox".to_string(),
        );
        sandbox_env.insert(
            "NONO_GATE_FUTURE_KNOB".to_string(),
            "from-agent-sandbox".to_string(),
        );
        // Sanity: a non-NONO_GATE_* var with a similar shape still flows.
        sandbox_env.insert(
            "NONO_TEST_PASSTHROUGH_98765".to_string(),
            "preserved".to_string(),
        );

        let env = build_exec_env(&sandbox_env, &broker);

        // The sandbox-supplied NONO_GATE_* values must never overwrite/inject.
        assert_ne!(
            env.get("NONO_GATE_FORCE_DENY").map(|s| s.as_str()),
            Some("from-agent-sandbox"),
            "NONO_GATE_FORCE_DENY from agent sandbox env must be stripped"
        );
        assert_ne!(
            env.get("NONO_GATE_FUTURE_KNOB").map(|s| s.as_str()),
            Some("from-agent-sandbox"),
            "NONO_GATE_* prefix-strip must cover future test knobs without code change"
        );
        // Unrelated vars still flow through (the strip is an exact prefix, not
        // wholesale "NONO_*" — nono itself sets NONO_SESSION_TOKEN etc. for
        // sandboxed children).
        assert_eq!(
            env.get("NONO_TEST_PASSTHROUGH_98765").map(|s| s.as_str()),
            Some("preserved")
        );
    }

    // --- Filtered shim dir tests ---

    #[test]
    fn test_filtered_shim_dir_excludes_allowed_commands() {
        // Create a temporary shim directory with some shim files
        let session_dir = tempfile::tempdir().expect("create temp dir");
        let shim_dir = session_dir.path().join("shims");
        std::fs::create_dir_all(&shim_dir).expect("create shim dir");

        // Create fake shim files
        for name in &["gh", "ddtool", "kubectl"] {
            std::fs::write(shim_dir.join(name), "fake-shim").expect("write shim");
        }

        let commands = vec![
            ResolvedCommand {
                name: "gh".to_string(),
                real_path: PathBuf::from("/usr/bin/gh"),
                intercepts: vec![],
                sandbox: None,
                caller_policy: CallerPolicy::default(),
            },
            ResolvedCommand {
                name: "ddtool".to_string(),
                real_path: PathBuf::from("/opt/homebrew/bin/ddtool"),
                intercepts: vec![],
                sandbox: None,
                caller_policy: CallerPolicy::default(),
            },
            ResolvedCommand {
                name: "kubectl".to_string(),
                real_path: PathBuf::from("/usr/local/bin/kubectl"),
                intercepts: vec![],
                sandbox: None,
                caller_policy: CallerPolicy::default(),
            },
        ];

        let allow_commands = vec!["ddtool".to_string()];

        let (filtered_dir, _guard) = build_filtered_shim_dir(&shim_dir, &allow_commands, &commands)
            .expect("build filtered shim dir");

        // ddtool should NOT be in the filtered dir (it's allowed)
        assert!(
            !filtered_dir.join("ddtool").exists(),
            "ddtool should be excluded from filtered shim dir"
        );
        // gh and kubectl should be symlinked
        assert!(
            filtered_dir.join("gh").exists(),
            "gh should be in filtered shim dir"
        );
        assert!(
            filtered_dir.join("kubectl").exists(),
            "kubectl should be in filtered shim dir"
        );
    }

    #[test]
    fn test_filtered_shim_dir_empty_allow_commands_copies_all() {
        let session_dir = tempfile::tempdir().expect("create temp dir");
        let shim_dir = session_dir.path().join("shims");
        std::fs::create_dir_all(&shim_dir).expect("create shim dir");

        for name in &["gh", "ddtool"] {
            std::fs::write(shim_dir.join(name), "fake-shim").expect("write shim");
        }

        let commands = vec![];
        // This function should not normally be called with empty allow_commands,
        // but if it is, all shims should be present.
        let allow_commands: Vec<String> = vec![];
        let (filtered_dir, _guard) = build_filtered_shim_dir(&shim_dir, &allow_commands, &commands)
            .expect("build filtered shim dir");

        assert!(filtered_dir.join("gh").exists());
        assert!(filtered_dir.join("ddtool").exists());
    }

    /// When `allow_commands` is set, `exec_passthrough` creates a filtered shim dir
    /// and sets NONO_SHIM_DIR to that dir. This ensures nono-shim's
    /// `resolve_real_binary` skips the correct directory and doesn't exec itself
    /// recursively (which would cause EAGAIN).
    #[tokio::test]
    async fn test_allow_commands_sets_nono_shim_dir_to_filtered_dir() {
        use crate::mediation::CommandSandbox;
        use crate::mediation::NetworkConfig;
        use std::os::unix::fs::PermissionsExt;

        let session_dir = tempfile::tempdir().expect("create temp dir");
        let shim_dir = session_dir.path().join("shims");
        std::fs::create_dir_all(&shim_dir).expect("create shim dir");

        // Create fake shim files (need to exist for build_filtered_shim_dir)
        for name in &["gh", "ddtool"] {
            let p = shim_dir.join(name);
            std::fs::write(&p, "fake-shim").expect("write shim");
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755))
                .expect("chmod shim");
        }

        let cmd = ResolvedCommand {
            name: "gh".to_string(),
            // Use /usr/bin/env so the child process prints its own environment.
            real_path: PathBuf::from("/usr/bin/env"),
            intercepts: vec![],
            sandbox: Some(CommandSandbox {
                network: NetworkConfig::default(),
                fs_read: vec![],
                fs_read_file: vec![],
                fs_write: vec![],
                fs_write_file: vec![],
                allow_commands: vec!["ddtool".to_string()],
                keychain_access: false,
            }),
            caller_policy: CallerPolicy::default(),
        };

        // Provide a ddtool entry so build_filtered_shim_dir can find its real path.
        let ddtool_cmd = ResolvedCommand {
            name: "ddtool".to_string(),
            real_path: PathBuf::from("/opt/homebrew/bin/ddtool"),
            intercepts: vec![],
            sandbox: None,
            caller_policy: CallerPolicy::default(),
        };

        let req = ShimRequest {
            command: "gh".to_string(),
            args: vec![],
            session_token: String::new(),
            ..Default::default()
        };

        let broker = make_broker();
        let (resp, _action_type) = apply_capture(
            req,
            &[cmd, ddtool_cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: &shim_dir,
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;

        assert_eq!(resp.exit_code, 0, "stderr: {}", resp.stderr);

        // Extract the value of NONO_SHIM_DIR from the child's printed environment.
        let shim_dir_line = resp
            .stdout
            .lines()
            .find(|l| l.starts_with("NONO_SHIM_DIR="))
            .expect("NONO_SHIM_DIR not found in env output");
        let child_shim_dir = shim_dir_line.trim_start_matches("NONO_SHIM_DIR=");

        // NONO_SHIM_DIR must NOT be the original shims/ directory — it should
        // be the filtered shim dir created by exec_passthrough.
        assert_ne!(
            child_shim_dir,
            shim_dir.to_string_lossy().as_ref(),
            "NONO_SHIM_DIR should be the filtered dir, not the original shim dir"
        );

        // NONO_SHIM_DIR must also be at the front of PATH so resolve_real_binary
        // in the shim finds it first when skipping its own directory.
        let path_line = resp
            .stdout
            .lines()
            .find(|l| l.starts_with("PATH="))
            .expect("PATH not found in env output");
        let child_path = path_line.trim_start_matches("PATH=");
        assert!(
            child_path.starts_with(child_shim_dir),
            "PATH should start with NONO_SHIM_DIR ({}), got: {}",
            child_shim_dir,
            child_path
        );
    }

    // --- Per-command proxy tests ---

    /// When `allowed_hosts` is configured, exec_passthrough injects HTTPS_PROXY
    /// pointing to 127.0.0.1 into the environment passed to the command.
    #[tokio::test]
    async fn test_allowed_hosts_injects_https_proxy() {
        use crate::mediation::CommandSandbox;
        use crate::mediation::NetworkConfig;

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),
            intercepts: vec![],
            sandbox: Some(CommandSandbox {
                network: NetworkConfig {
                    block: false,
                    allowed_hosts: vec!["github.com".to_string()],
                },
                fs_read: vec![],
                fs_read_file: vec![],
                fs_write: vec![],
                fs_write_file: vec![],
                allow_commands: vec![],
                keychain_access: false,
            }),
            caller_policy: CallerPolicy::default(),
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            // `env` prints its own environment; grep output for HTTPS_PROXY
            args: vec![],
            session_token: String::new(),
            ..Default::default()
        };

        let broker = make_broker();
        let (resp, _action_type) = apply_capture(
            req,
            &[cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;
        // The command ran (exit 0) and output should contain HTTPS_PROXY pointing to 127.0.0.1
        assert_eq!(resp.exit_code, 0, "stderr: {}", resp.stderr);
        assert!(
            resp.stdout.contains("HTTPS_PROXY=http://nono:"),
            "HTTPS_PROXY not found in env output: {}",
            resp.stdout
        );
        assert!(
            resp.stdout.contains("127.0.0.1"),
            "proxy addr not 127.0.0.1: {}",
            resp.stdout
        );
    }

    /// When `block: true` and `allowed_hosts` is also set, `block` takes
    /// precedence: no proxy is started, network is blocked at OS level.
    /// We verify this by checking the env printed by the child does NOT
    /// contain an HTTPS_PROXY entry.
    #[tokio::test]
    async fn test_block_takes_precedence_over_allowed_hosts() {
        use crate::mediation::CommandSandbox;
        use crate::mediation::NetworkConfig;

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),
            intercepts: vec![],
            sandbox: Some(CommandSandbox {
                network: NetworkConfig {
                    block: true,
                    allowed_hosts: vec!["github.com".to_string()],
                },
                fs_read: vec![],
                fs_read_file: vec![],
                fs_write: vec![],
                fs_write_file: vec![],
                allow_commands: vec![],
                keychain_access: false,
            }),
            caller_policy: CallerPolicy::default(),
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            ..Default::default()
        };

        let broker = make_broker();
        let (resp, _action_type) = apply_capture(
            req,
            &[cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;
        // Command may fail due to sandbox (network block applies via pre_exec),
        // but crucially HTTPS_PROXY must NOT have been injected.
        assert!(
            !resp.stdout.contains("HTTPS_PROXY=http://nono:"),
            "HTTPS_PROXY should not be set when block=true, got: {}",
            resp.stdout
        );
    }

    /// Approve action does NOT apply the per-command sandbox. The real binary
    /// needs unrestricted access to system resources (e.g. macOS Keychain via
    /// mach-lookup to securityd). Protection comes from the profile author's
    /// deliberate choice of which commands get `approve`.
    ///
    /// We verify by checking that HTTPS_PROXY is NOT injected even when the
    /// command has `allowed_hosts` configured, proving the sandbox was skipped.
    #[tokio::test]
    async fn test_approve_does_not_apply_per_command_sandbox() {
        use crate::mediation::CommandSandbox;
        use crate::mediation::NetworkConfig;

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),
            intercepts: vec![ResolvedIntercept {
                args_prefix: vec![],
                argv_shape: None,
                action: ResolvedAction::Approve { script: None },
                exit_code: 0,
                admin: false,
            }],
            sandbox: Some(CommandSandbox {
                network: NetworkConfig {
                    block: false,
                    allowed_hosts: vec!["api.github.com".to_string()],
                },
                fs_read: vec![],
                fs_read_file: vec![],
                fs_write: vec![],
                fs_write_file: vec![],
                allow_commands: vec![],
                keychain_access: false,
            }),
            caller_policy: CallerPolicy::default(),
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            env: HashMap::new(),
            pid: 0,
            cwd: None,
        };

        let broker = make_broker();
        let (resp, action_type) = apply_capture(
            req,
            &[cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;

        assert_eq!(action_type, "approve");
        assert_eq!(resp.exit_code, 0, "stderr: {}", resp.stderr);
        // HTTPS_PROXY must NOT be present — approve runs without per-command sandbox.
        assert!(
            !resp.stdout.contains("HTTPS_PROXY=http://nono:"),
            "Approve action should NOT apply per-command sandbox, but HTTPS_PROXY found: {}",
            resp.stdout
        );
    }

    // --- keychain_access tests ---

    /// Passthrough with `keychain_access: true` and `allowed_hosts` runs
    /// successfully and still applies network restrictions (HTTPS_PROXY).
    /// Proves keychain_access doesn't break the sandbox or disable network filtering.
    #[tokio::test]
    async fn test_passthrough_keychain_access_with_allowed_hosts() {
        use crate::mediation::CommandSandbox;
        use crate::mediation::NetworkConfig;

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),
            intercepts: vec![],
            sandbox: Some(CommandSandbox {
                network: NetworkConfig {
                    block: false,
                    allowed_hosts: vec!["api.github.com".to_string()],
                },
                fs_read: vec![],
                fs_read_file: vec![],
                fs_write: vec![],
                fs_write_file: vec![],
                allow_commands: vec![],
                keychain_access: true,
            }),
            caller_policy: CallerPolicy::default(),
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            env: HashMap::new(),
            pid: 0,
            cwd: None,
        };

        let broker = make_broker();
        let (resp, action_type) = apply_capture(
            req,
            &[cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;

        assert_eq!(action_type, "passthrough");
        assert_eq!(resp.exit_code, 0, "stderr: {}", resp.stderr);
        assert!(
            resp.stdout.contains("HTTPS_PROXY=http://nono:"),
            "keychain_access should not disable network restrictions, HTTPS_PROXY missing: {}",
            resp.stdout
        );
    }

    /// Passthrough with `keychain_access: false` (default) and `allowed_hosts`
    /// preserves existing behavior: runs successfully with network restrictions.
    #[tokio::test]
    async fn test_passthrough_keychain_access_false_default() {
        use crate::mediation::CommandSandbox;
        use crate::mediation::NetworkConfig;

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),
            intercepts: vec![],
            sandbox: Some(CommandSandbox {
                network: NetworkConfig {
                    block: false,
                    allowed_hosts: vec!["api.github.com".to_string()],
                },
                fs_read: vec![],
                fs_read_file: vec![],
                fs_write: vec![],
                fs_write_file: vec![],
                allow_commands: vec![],
                keychain_access: false,
            }),
            caller_policy: CallerPolicy::default(),
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            env: HashMap::new(),
            pid: 0,
            cwd: None,
        };

        let broker = make_broker();
        let (resp, action_type) = apply_capture(
            req,
            &[cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;

        assert_eq!(action_type, "passthrough");
        assert_eq!(resp.exit_code, 0, "stderr: {}", resp.stderr);
        assert!(
            resp.stdout.contains("HTTPS_PROXY=http://nono:"),
            "Default keychain_access=false should still apply network restrictions: {}",
            resp.stdout
        );
    }

    /// `keychain_access: true` with `network.block: true` — block takes
    /// precedence, no proxy started, HTTPS_PROXY not injected.
    /// Proves keychain_access doesn't interfere with network block mode.
    #[tokio::test]
    async fn test_keychain_access_does_not_disable_network_block() {
        use crate::mediation::CommandSandbox;
        use crate::mediation::NetworkConfig;

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),
            intercepts: vec![],
            sandbox: Some(CommandSandbox {
                network: NetworkConfig {
                    block: true,
                    allowed_hosts: vec!["github.com".to_string()],
                },
                fs_read: vec![],
                fs_read_file: vec![],
                fs_write: vec![],
                fs_write_file: vec![],
                allow_commands: vec![],
                keychain_access: true,
            }),
            caller_policy: CallerPolicy::default(),
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            env: HashMap::new(),
            pid: 0,
            cwd: None,
        };

        let broker = make_broker();
        let (resp, _action_type) = apply_capture(
            req,
            &[cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;

        assert!(
            !resp.stdout.contains("HTTPS_PROXY=http://nono:"),
            "keychain_access should not override network block, but HTTPS_PROXY found: {}",
            resp.stdout
        );
    }

    // --- Streaming passthrough fd-protocol tests ---

    /// Pipe binary data (every byte 0x00..=0xFF, including 0xFF) through the
    /// child's stdin and read it back via stdout. Verifies the new SCM_RIGHTS
    /// path streams bytes unchanged — no UTF-8 lossy conversion, no 50ms
    /// stdin truncation, no buffering.
    #[tokio::test]
    async fn test_passthrough_streams_binary_stdin_unchanged() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/bin/cat"),
            intercepts: vec![],
            sandbox: None,
            caller_policy: CallerPolicy::default(),
        };

        let (child_in, mut test_in) = UnixStream::pair().expect("pair stdin");
        let (child_out, test_out) = UnixStream::pair().expect("pair stdout");
        let (child_err, _test_err) = UnixStream::pair().expect("pair stderr");

        // 4 KiB of binary data covering every byte value, including 0xFF.
        let payload: Vec<u8> = (0u32..4096).map(|i| (i & 0xff) as u8).collect();

        // Drain stdout in a thread so cat doesn't block on a full buffer.
        let payload_clone = payload.clone();
        let drain = std::thread::spawn(move || {
            use std::io::Read;
            let mut received = Vec::with_capacity(payload_clone.len());
            let mut r = test_out;
            let _ = r.read_to_end(&mut received);
            received
        });

        // Write the payload, then close the writer so cat sees EOF and exits.
        test_in.write_all(&payload).expect("write payload");
        drop(test_in);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            ..Default::default()
        };

        let (resp, action_type) = apply(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
            make_allowlist(),
            OwnedFd::from(child_in),
            OwnedFd::from(child_out),
            OwnedFd::from(child_err),
        )
        .await;

        assert_eq!(action_type, "passthrough");
        assert_eq!(resp.exit_code, 0, "stderr: {}", resp.stderr);
        // Streaming path: the response carries no buffered output.
        assert!(
            resp.stdout.is_empty(),
            "expected empty resp.stdout in streaming mode, got {} bytes",
            resp.stdout.len()
        );
        assert!(
            resp.stderr.is_empty(),
            "expected empty resp.stderr in streaming mode, got {} bytes",
            resp.stderr.len()
        );

        let received = drain.join().expect("drain thread");
        assert_eq!(
            received,
            payload,
            "binary payload corrupted: lengths {} vs {}",
            received.len(),
            payload.len()
        );
    }

    /// Capture/Respond/Approve paths drop the passed fds and produce buffered
    /// output via the response. Verifies the dropped fds let the test side
    /// see EOF (no hang) and that the buffered stdout flows through normally.
    #[tokio::test]
    async fn test_buffered_paths_drop_passed_fds_and_buffer_output() {
        use std::io::Read;
        use std::os::unix::net::UnixStream;

        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec!["auth".to_string()],
            argv_shape: None,
            action: ResolvedAction::Respond {
                stdout: "buffered_response\n".to_string(),
            },
            exit_code: 0,
            admin: false,
        }]);

        let (child_in, _test_in) = UnixStream::pair().expect("pair stdin");
        let (child_out, mut test_out) = UnixStream::pair().expect("pair stdout");
        let (child_err, _test_err) = UnixStream::pair().expect("pair stderr");

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["auth".to_string()],
            session_token: String::new(),
            ..Default::default()
        };

        let (resp, action_type) = apply(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
            make_allowlist(),
            OwnedFd::from(child_in),
            OwnedFd::from(child_out),
            OwnedFd::from(child_err),
        )
        .await;

        assert_eq!(action_type, "respond");
        assert_eq!(resp.stdout, "buffered_response\n");

        // The Respond path dropped the child_out fd, so the test side
        // immediately sees EOF — read_to_end returns 0 bytes without
        // hanging because there are no other writers on the socketpair.
        let mut buf = Vec::new();
        let _ = test_out.read_to_end(&mut buf);
        assert!(
            buf.is_empty(),
            "Respond path should not write anything to passed stdout fd, got {:?}",
            buf
        );
    }

    /// Passthrough spawns the real binary with the caller's cwd from
    /// `ShimRequest.cwd`, not the mediation server's own cwd. Regression test
    /// for the worktree bug where `git` from a Claude worktree silently
    /// resolved to the main repo because the spawn inherited the server's
    /// launch cwd.
    #[tokio::test]
    async fn test_passthrough_uses_request_cwd() {
        use std::io::Read;
        use std::os::unix::net::UnixStream;

        // Use /bin/pwd because it prints its cwd and exits — independent of
        // any external binary on PATH.
        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/bin/pwd"),
            intercepts: vec![],
            sandbox: None,
            caller_policy: CallerPolicy::default(),
        };

        // Use a tempdir as the caller cwd so it differs from whatever cwd the
        // test runner has. Canonicalise because /bin/pwd resolves symlinks
        // (e.g. /tmp -> /private/tmp on macOS).
        let temp = tempfile::tempdir().expect("tempdir");
        let caller_cwd = std::fs::canonicalize(temp.path())
            .expect("canonicalize tempdir")
            .to_string_lossy()
            .into_owned();

        let (child_in, _test_in) = UnixStream::pair().expect("pair stdin");
        let (child_out, mut test_out) = UnixStream::pair().expect("pair stdout");
        let (child_err, _test_err) = UnixStream::pair().expect("pair stderr");

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            cwd: Some(caller_cwd.clone()),
            ..Default::default()
        };

        let (resp, action_type) = apply(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
            make_allowlist(),
            OwnedFd::from(child_in),
            OwnedFd::from(child_out),
            OwnedFd::from(child_err),
        )
        .await;

        assert_eq!(action_type, "passthrough");
        assert_eq!(resp.exit_code, 0, "stderr: {}", resp.stderr);

        let mut buf = Vec::new();
        let _ = test_out.read_to_end(&mut buf);
        let pwd_output = String::from_utf8(buf).expect("utf8 pwd output");
        assert_eq!(
            pwd_output.trim_end(),
            caller_cwd,
            "pwd should print the caller's cwd from ShimRequest.cwd"
        );
    }

    // --- parent_sandbox override (plan 4.1) ---

    /// When the resolved parent has a `parent_sandbox` entry, the keyed
    /// CommandSandbox replaces the default for the passthrough exec.
    /// Verified via the network policy: parent="gh" → block:true → no
    /// HTTPS_PROXY injected, even though the default sandbox would have
    /// allowed `github.com` via the proxy.
    #[tokio::test]
    async fn test_apply_uses_parent_sandbox_when_caller_matches() {
        use crate::mediation::{CommandSandbox, NetworkConfig};

        let mut parent_sandbox = std::collections::HashMap::new();
        parent_sandbox.insert(
            "gh".to_string(),
            CommandSandbox {
                network: NetworkConfig {
                    block: true,
                    allowed_hosts: vec![],
                },
                fs_read: vec![],
                fs_read_file: vec![],
                fs_write: vec![],
                fs_write_file: vec![],
                allow_commands: vec![],
                keychain_access: false,
            },
        );

        let default_sb = CommandSandbox {
            network: NetworkConfig {
                block: false,
                allowed_hosts: vec!["github.com".to_string()],
            },
            fs_read: vec![],
            fs_read_file: vec![],
            fs_write: vec![],
            fs_write_file: vec![],
            allow_commands: vec![],
            keychain_access: false,
        };

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),
            intercepts: vec![],
            sandbox: Some(default_sb),
            caller_policy: CallerPolicy {
                agent_allowed: true,
                allowed_parents: None,
                parent_sandbox,
                deny_agent_strict: false,
            },
        };

        let broker = make_broker();
        let nonce = broker.issue(Zeroizing::new("gh".to_string()));
        let mut env = std::collections::HashMap::new();
        env.insert("NONO_SANDBOX_CONTEXT".to_string(), nonce);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            env,
            pid: 0,
            ..Default::default()
        };

        let (resp, action) =
            apply_capture(req, &[cmd], Arc::clone(&broker), &ctx(), always_allow()).await;
        assert_eq!(action, "passthrough");
        assert!(
            !resp.stdout.contains("HTTPS_PROXY=http://nono:"),
            "parent_sandbox should have applied network.block, but HTTPS_PROXY was injected: {}",
            resp.stdout
        );
    }

    /// When the parent name is not present in `parent_sandbox`, the default
    /// sandbox is used. Caller is "git", parent_sandbox only has "gh", so the
    /// default sandbox (allowed_hosts) wins → HTTPS_PROXY is injected.
    #[tokio::test]
    async fn test_apply_uses_default_sandbox_when_no_parent_sandbox_match() {
        use crate::mediation::{CommandSandbox, NetworkConfig};

        let mut parent_sandbox = std::collections::HashMap::new();
        parent_sandbox.insert(
            "gh".to_string(),
            CommandSandbox {
                network: NetworkConfig {
                    block: true,
                    allowed_hosts: vec![],
                },
                fs_read: vec![],
                fs_read_file: vec![],
                fs_write: vec![],
                fs_write_file: vec![],
                allow_commands: vec![],
                keychain_access: false,
            },
        );

        let default_sb = CommandSandbox {
            network: NetworkConfig {
                block: false,
                allowed_hosts: vec!["github.com".to_string()],
            },
            fs_read: vec![],
            fs_read_file: vec![],
            fs_write: vec![],
            fs_write_file: vec![],
            allow_commands: vec![],
            keychain_access: false,
        };

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),
            intercepts: vec![],
            sandbox: Some(default_sb),
            caller_policy: CallerPolicy {
                agent_allowed: true,
                allowed_parents: None,
                parent_sandbox,
                deny_agent_strict: false,
            },
        };

        let broker = make_broker();
        let nonce = broker.issue(Zeroizing::new("git".to_string()));
        let mut env = std::collections::HashMap::new();
        env.insert("NONO_SANDBOX_CONTEXT".to_string(), nonce);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            env,
            pid: 0,
            ..Default::default()
        };

        let (resp, _) =
            apply_capture(req, &[cmd], Arc::clone(&broker), &ctx(), always_allow()).await;
        assert!(
            resp.stdout.contains("HTTPS_PROXY=http://nono:"),
            "should have used default sandbox (network.allowed_hosts) for parent not in map, got: {}",
            resp.stdout
        );
    }

    /// When the caller is the agent (no NONO_SANDBOX_CONTEXT), the default
    /// sandbox is used regardless of `parent_sandbox` contents.
    #[tokio::test]
    async fn test_apply_uses_default_sandbox_for_agent_caller() {
        use crate::mediation::{CommandSandbox, NetworkConfig};

        let mut parent_sandbox = std::collections::HashMap::new();
        parent_sandbox.insert(
            "gh".to_string(),
            CommandSandbox {
                network: NetworkConfig {
                    block: true,
                    allowed_hosts: vec![],
                },
                fs_read: vec![],
                fs_read_file: vec![],
                fs_write: vec![],
                fs_write_file: vec![],
                allow_commands: vec![],
                keychain_access: false,
            },
        );

        let default_sb = CommandSandbox {
            network: NetworkConfig {
                block: false,
                allowed_hosts: vec!["github.com".to_string()],
            },
            fs_read: vec![],
            fs_read_file: vec![],
            fs_write: vec![],
            fs_write_file: vec![],
            allow_commands: vec![],
            keychain_access: false,
        };

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),
            intercepts: vec![],
            sandbox: Some(default_sb),
            caller_policy: CallerPolicy {
                agent_allowed: true,
                allowed_parents: None,
                parent_sandbox,
                deny_agent_strict: false,
            },
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            env: std::collections::HashMap::new(),
            pid: 0,
            ..Default::default()
        };

        let broker = make_broker();
        let (resp, _) =
            apply_capture(req, &[cmd], Arc::clone(&broker), &ctx(), always_allow()).await;
        assert!(
            resp.stdout.contains("HTTPS_PROXY=http://nono:"),
            "agent caller should use default sandbox, expected HTTPS_PROXY, got: {}",
            resp.stdout
        );
    }

    // --- caller-policy gate prompt-on-deny (plan 4.1 task 3.5) ---

    use crate::mediation::allowlist::{AllowlistKey, AllowlistKind, AllowlistStore};
    use crate::mediation::approval::ApprovalVerdict;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test double for the caller-policy gate dispatch tests.
    ///
    /// Records a fixed `ApprovalVerdict` and counts how many times
    /// `approve_with_save_option` is invoked. Cloneable via the inner `Arc`,
    /// so a test can hand a clone to `apply` and still observe the call
    /// counter afterwards.
    #[derive(Clone)]
    struct MockApprovalGate {
        verdict: ApprovalVerdict,
        calls: Arc<AtomicUsize>,
    }

    impl MockApprovalGate {
        fn deny() -> Arc<Self> {
            Arc::new(Self {
                verdict: ApprovalVerdict::Deny,
                calls: Arc::new(AtomicUsize::new(0)),
            })
        }
        fn allow_once() -> Arc<Self> {
            Arc::new(Self {
                verdict: ApprovalVerdict::AllowOnce,
                calls: Arc::new(AtomicUsize::new(0)),
            })
        }
        fn allow_always() -> Arc<Self> {
            Arc::new(Self {
                verdict: ApprovalVerdict::AllowAlways,
                calls: Arc::new(AtomicUsize::new(0)),
            })
        }
        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl ApprovalGate for MockApprovalGate {
        fn approve(&self, _command: &str, _args: &[String]) -> bool {
            // Fallback used by callers that haven't migrated to the 3-way
            // form. The caller-policy gate uses approve_with_save_option, so
            // this branch is unused in these tests.
            !matches!(self.verdict, ApprovalVerdict::Deny)
        }
        fn approve_with_save_option(
            &self,
            _command: &str,
            _args: &[String],
            _reason: &str,
        ) -> ApprovalVerdict {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.verdict
        }
    }

    /// Thin newtype around a tempdir-backed `AllowlistStore` for tests that
    /// need to share the allowlist across multiple `apply` invocations and
    /// poke at its state directly.
    #[derive(Clone)]
    struct TestAllowlistStore {
        inner: Arc<AllowlistStore>,
    }

    impl TestAllowlistStore {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("argv-allowlist.json");
            std::mem::forget(dir);
            Self {
                inner: Arc::new(
                    AllowlistStore::open_at(path).expect("open allowlist"),
                ),
            }
        }
        fn is_approved(&self, key: &AllowlistKey) -> bool {
            self.inner.is_approved(key)
        }
    }

    impl From<TestAllowlistStore> for Arc<AllowlistStore> {
        fn from(t: TestAllowlistStore) -> Self {
            t.inner
        }
    }

    /// Default `CommandSandbox` for caller-policy gate tests. Inert (no
    /// network, no fs allowances) — the gate decision is what's under test,
    /// not sandbox enforcement.
    fn default_sandbox() -> super::super::CommandSandbox {
        use crate::mediation::{CommandSandbox, NetworkConfig};
        CommandSandbox {
            network: NetworkConfig {
                block: false,
                allowed_hosts: vec![],
            },
            fs_read: vec![],
            fs_read_file: vec![],
            fs_write: vec![],
            fs_write_file: vec![],
            allow_commands: vec![],
            keychain_access: false,
        }
    }

    /// (a) agent_allowed:false + deny_agent_strict:true → exit 126,
    /// gate not consulted at all.
    #[tokio::test]
    async fn caller_policy_gate_strict_hard_denies_without_consulting_gate() {
        let cmd = ResolvedCommand {
            name: "ssh".to_string(),
            real_path: PathBuf::from("/usr/bin/ssh"),
            intercepts: vec![],
            sandbox: None,
            caller_policy: CallerPolicy {
                agent_allowed: false,
                allowed_parents: Some(vec!["git".to_string()]),
                parent_sandbox: std::collections::HashMap::new(),
                deny_agent_strict: true,
            },
        };
        let req = ShimRequest {
            command: "ssh".to_string(),
            args: vec!["example.com".to_string()],
            session_token: String::new(),
            env: std::collections::HashMap::new(),
            pid: 0,
        };
        let gate = MockApprovalGate::deny(); // would deny if asked, but must not be asked
        let gate_for_apply: Arc<dyn ApprovalGate + Send + Sync> = gate.clone();
        let (resp, _) = apply_capture(
            req,
            &[cmd],
            make_broker(),
            &ctx(),
            gate_for_apply,
        )
        .await;
        assert_eq!(resp.exit_code, 126);
        assert_eq!(gate.call_count(), 0, "strict path must not consult gate");
    }

    /// (b) agent_allowed:false + deny_agent_strict:false + gate denies → exit 126.
    #[tokio::test]
    async fn caller_policy_gate_consults_gate_then_denies() {
        let cmd = ResolvedCommand {
            name: "git".to_string(),
            real_path: PathBuf::from("/usr/bin/git"),
            intercepts: vec![],
            sandbox: Some(default_sandbox()),
            caller_policy: CallerPolicy {
                agent_allowed: false,
                allowed_parents: Some(vec!["gh".to_string()]),
                parent_sandbox: std::collections::HashMap::new(),
                deny_agent_strict: false,
            },
        };
        let req = ShimRequest {
            command: "git".to_string(),
            args: vec!["status".to_string()],
            session_token: String::new(),
            env: std::collections::HashMap::new(), // agent
            pid: 0,
        };
        let gate = MockApprovalGate::deny();
        let gate_for_apply: Arc<dyn ApprovalGate + Send + Sync> = gate.clone();
        let (resp, _) = apply_capture(
            req,
            &[cmd],
            make_broker(),
            &ctx(),
            gate_for_apply,
        )
        .await;
        assert_eq!(resp.exit_code, 126);
        assert_eq!(gate.call_count(), 1);
    }

    /// (c) gate returns AllowOnce → request proceeds (passthrough), no
    /// allowlist entry persisted.
    #[tokio::test]
    async fn caller_policy_gate_allow_once_proceeds_without_persisting() {
        let cmd = ResolvedCommand {
            name: "git".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),
            intercepts: vec![],
            sandbox: Some(default_sandbox()),
            caller_policy: CallerPolicy {
                agent_allowed: false,
                allowed_parents: None,
                parent_sandbox: std::collections::HashMap::new(),
                deny_agent_strict: false,
            },
        };
        let req = ShimRequest {
            command: "git".to_string(),
            args: vec!["status".to_string()],
            session_token: String::new(),
            env: std::collections::HashMap::new(),
            pid: 0,
        };
        let gate = MockApprovalGate::allow_once();
        let allowlist = TestAllowlistStore::new();
        let gate_for_apply: Arc<dyn ApprovalGate + Send + Sync> = gate.clone();
        let (_resp, action) = apply_capture_with_allowlist(
            req,
            &[cmd],
            make_broker(),
            &ctx(),
            gate_for_apply,
            allowlist.clone().into(),
        )
        .await;
        assert_eq!(action, "passthrough");
        let key = AllowlistKey {
            kind: AllowlistKind::CallerPolicy,
            payload: serde_json::json!({
                "cmd": "git", "parent": "agent", "argv": ["status"],
            }),
        };
        assert!(!allowlist.is_approved(&key), "AllowOnce must not persist");
    }

    /// (d) gate returns AllowAlways → request proceeds AND key persists.
    #[tokio::test]
    async fn caller_policy_gate_allow_always_persists_key() {
        let cmd = ResolvedCommand {
            name: "git".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),
            intercepts: vec![],
            sandbox: Some(default_sandbox()),
            caller_policy: CallerPolicy {
                agent_allowed: false,
                allowed_parents: None,
                parent_sandbox: std::collections::HashMap::new(),
                deny_agent_strict: false,
            },
        };
        let req = ShimRequest {
            command: "git".to_string(),
            args: vec!["status".to_string()],
            session_token: String::new(),
            env: std::collections::HashMap::new(),
            pid: 0,
        };
        let gate = MockApprovalGate::allow_always();
        let allowlist = TestAllowlistStore::new();
        let gate_for_apply: Arc<dyn ApprovalGate + Send + Sync> = gate.clone();
        let (_resp, action) = apply_capture_with_allowlist(
            req,
            &[cmd],
            make_broker(),
            &ctx(),
            gate_for_apply,
            allowlist.clone().into(),
        )
        .await;
        assert_eq!(action, "passthrough");
        let key = AllowlistKey {
            kind: AllowlistKind::CallerPolicy,
            payload: serde_json::json!({
                "cmd": "git", "parent": "agent", "argv": ["status"],
            }),
        };
        assert!(allowlist.is_approved(&key), "AllowAlways must persist key");
    }

    /// (e) Second invocation with the same key auto-bypasses the gate.
    #[tokio::test]
    async fn caller_policy_gate_skipped_when_allowlist_has_key() {
        let cmd = ResolvedCommand {
            name: "git".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),
            intercepts: vec![],
            sandbox: Some(default_sandbox()),
            caller_policy: CallerPolicy {
                agent_allowed: false,
                allowed_parents: None,
                parent_sandbox: std::collections::HashMap::new(),
                deny_agent_strict: false,
            },
        };
        let req = || ShimRequest {
            command: "git".to_string(),
            args: vec!["status".to_string()],
            session_token: String::new(),
            env: std::collections::HashMap::new(),
            pid: 0,
        };
        let gate = MockApprovalGate::allow_always();
        let allowlist = TestAllowlistStore::new();
        let gate_for_apply: Arc<dyn ApprovalGate + Send + Sync> = gate.clone();
        // First call records the key.
        let _ = apply_capture_with_allowlist(
            req(),
            std::slice::from_ref(&cmd),
            make_broker(),
            &ctx(),
            gate_for_apply,
            allowlist.clone().into(),
        )
        .await;
        assert_eq!(gate.call_count(), 1);
        // Second call: the gate must NOT be consulted (allowlist hit).
        let gate_for_apply2: Arc<dyn ApprovalGate + Send + Sync> = gate.clone();
        let (_resp, action) = apply_capture_with_allowlist(
            req(),
            &[cmd],
            make_broker(),
            &ctx(),
            gate_for_apply2,
            allowlist.clone().into(),
        )
        .await;
        assert_eq!(action, "passthrough");
        assert_eq!(gate.call_count(), 1, "second call must not re-consult gate");
    }

    /// (f) allowed_parents mismatch: parent not in allowed_parents → gate
    /// consulted; AllowAlways stores key under the actual parent name.
    #[tokio::test]
    async fn caller_policy_gate_handles_allowed_parents_mismatch() {
        let cmd = ResolvedCommand {
            name: "git".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),
            intercepts: vec![],
            sandbox: Some(default_sandbox()),
            caller_policy: CallerPolicy {
                agent_allowed: true,
                allowed_parents: Some(vec!["gh".to_string()]),
                parent_sandbox: std::collections::HashMap::new(),
                deny_agent_strict: false,
            },
        };
        // Caller is "kubectl" — not in allowed_parents.
        let broker = make_broker();
        let nonce = broker.issue(Zeroizing::new("kubectl".to_string()));
        let mut env = std::collections::HashMap::new();
        env.insert("NONO_SANDBOX_CONTEXT".to_string(), nonce);
        let req = ShimRequest {
            command: "git".to_string(),
            args: vec!["status".to_string()],
            session_token: String::new(),
            env,
            pid: 0,
        };
        let gate = MockApprovalGate::allow_always();
        let allowlist = TestAllowlistStore::new();
        let gate_for_apply: Arc<dyn ApprovalGate + Send + Sync> = gate.clone();
        let _ = apply_capture_with_allowlist(
            req,
            &[cmd],
            Arc::clone(&broker),
            &ctx(),
            gate_for_apply,
            allowlist.clone().into(),
        )
        .await;
        assert_eq!(gate.call_count(), 1);
        let key = AllowlistKey {
            kind: AllowlistKind::CallerPolicy,
            payload: serde_json::json!({
                "cmd": "git", "parent": "kubectl", "argv": ["status"],
            }),
        };
        assert!(allowlist.is_approved(&key));
    }
}
