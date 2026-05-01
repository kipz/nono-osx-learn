//! Command mediation: policy-driven command interception and response injection.
//!
//! The mediation layer sits between the sandboxed AI agent and real tool binaries.
//! Instead of running a command directly, the sandbox's PATH resolves to a shim
//! that forwards the invocation over a Unix socket to this server running in the
//! unsandboxed parent.
//!
//! This layer can intercept any command invocation and either return a configured
//! static response or capture the output of the real binary and return a nonce
//! (phantom token pattern). On passthrough, nonce-bearing env vars are promoted
//! to their real values before exec-ing the real binary.
//!
//! All policy (which commands to intercept, what to do, which env vars to block)
//! lives in the profile's `mediation` section.

pub mod admin;
pub mod allowlist;
pub mod approval;
pub mod approve_ipc;
pub mod broker;
pub mod control;
pub mod policy;
pub mod server;
pub mod session;

use std::sync::{Arc, OnceLock};

use serde::{Deserialize, Serialize};

/// Top-level mediation configuration from a profile's `mediation` section.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct MediationConfig {
    /// Commands to mediate (intercept or pass through).
    #[serde(default)]
    pub commands: Vec<CommandEntry>,
    /// Environment variable policy for the sandboxed child.
    #[serde(default)]
    pub env: EnvPolicy,
}

impl MediationConfig {
    /// Returns true if there is any mediation configuration to apply.
    pub fn is_active(&self) -> bool {
        !self.commands.is_empty() || !self.env.block.is_empty()
    }
}

/// Per-command mediation entry.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CommandEntry {
    /// The command name to mediate (resolved via `which` at session start).
    pub name: String,
    /// Optional absolute path to the real binary, overriding `which` resolution.
    /// Useful when the system `which` resolves to a wrapper that should not be exec'd.
    #[serde(default)]
    pub binary_path: Option<String>,
    /// Arg-prefix intercept rules. Checked in order; first match wins.
    #[serde(default)]
    pub intercept: Vec<InterceptRule>,
    /// Optional sandbox profile applied when exec-ing the real binary.
    #[serde(default)]
    pub sandbox: Option<CommandSandbox>,
    /// Restrict who is allowed to invoke this command. Default: any caller
    /// (agent or any mediated parent) — backward compatible.
    #[serde(default)]
    pub caller_policy: CallerPolicy,
}

/// Caller-policy gate for a mediated command.
///
/// Evaluated before any intercept or per-command sandbox logic. A request
/// from the agent (no `NONO_SANDBOX_CONTEXT`) is gated by `agent_allowed`;
/// a request from a mediated parent is gated by `allowed_parents`.
///
/// Defaults preserve pre-existing behaviour: `agent_allowed: true` and
/// `allowed_parents: None` (any mediated parent).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CallerPolicy {
    /// If false, reject invocations originating from the primary (agent)
    /// sandbox. Default: true.
    #[serde(default = "default_true")]
    pub agent_allowed: bool,
    /// Restrict which mediated parents may invoke this command.
    ///
    /// - `None` (field absent in JSON): any mediated parent allowed.
    /// - `Some(vec![])`: no mediated parent allowed (only the agent, if
    ///   `agent_allowed`).
    /// - `Some(vec!["git"])`: only the listed parents allowed.
    #[serde(default)]
    pub allowed_parents: Option<Vec<String>>,
    /// Per-parent sandbox override. When the resolved parent name is a key
    /// in this map, exec_passthrough uses the keyed CommandSandbox instead
    /// of the command's default sandbox. Parents not listed (and the agent
    /// caller) use the default sandbox. Defaults to empty map.
    #[serde(default)]
    pub parent_sandbox: std::collections::HashMap<String, CommandSandbox>,
    /// When true, agent_allowed:false rejections hard-deny without consulting
    /// the approval gate. Used for security-critical commands where AllowAlways
    /// would re-open known regressions (e.g. ssh's role in §3a core.sshCommand
    /// exfil through git's sandbox).
    #[serde(default)]
    pub deny_agent_strict: bool,
}

impl Default for CallerPolicy {
    fn default() -> Self {
        Self {
            agent_allowed: true,
            allowed_parents: None,
            parent_sandbox: std::collections::HashMap::new(),
            deny_agent_strict: false,
        }
    }
}

fn default_true() -> bool {
    true
}

/// An intercept rule: if `args_prefix` matches the invocation's positional args,
/// perform the configured action without (or with) calling the real binary.
///
/// A rule may use exactly one matcher: either `args_prefix` (loose, prefix-only)
/// or `argv_shape` (strict, flag-aware). Specifying both is a configuration
/// error and is rejected during resolve.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InterceptRule {
    /// The leading positional args that must match (flags are ignored during matching).
    /// E.g. `["auth", "github", "token"]` matches `ddtool --debug auth github token`.
    #[serde(default)]
    pub args_prefix: Vec<String>,
    /// Strict, flag-aware matcher. When present, the invocation's first positional
    /// must equal `subcommand`, every declared flag must appear exactly once with
    /// the declared value (or as a boolean flag), and (per `extras`) no extra
    /// positionals or unknown flags may appear. Mutually exclusive with `args_prefix`.
    #[serde(default)]
    pub argv_shape: Option<ArgvShape>,
    /// If true, the user must authenticate via a native macOS biometric/password dialog
    /// before the action is executed. Requires `nono-approve` to be installed alongside nono.
    /// Defaults to false.
    #[serde(default)]
    pub admin: bool,
    /// What to do when this rule matches.
    pub action: InterceptAction,
}

/// Strict, flag-aware matcher for an intercept rule.
///
/// Matches when:
/// 1. The first positional argument equals `subcommand`.
/// 2. Every entry in `flags` appears exactly once in the invocation, with the
///    declared value (for `Required`/`ValueOnly`) or simply present (for `Boolean`).
/// 3. No additional positional or flag arguments appear, unless `extras` is `Allow`.
///
/// On mismatch, behaviour is controlled by `on_mismatch`: `Deny` (default) skips
/// this rule and lets matching fall through to the next rule (or default policy);
/// `Approve` triggers the approval dialog instead of denying outright.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ArgvShape {
    /// The required first positional argument (e.g. `"find-generic-password"`).
    pub subcommand: String,
    /// Declared flags. Each must appear exactly once in the invocation.
    #[serde(default)]
    pub flags: std::collections::BTreeMap<String, FlagSpec>,
    /// Whether to allow extra positional or flag arguments beyond those declared.
    /// Default: `Deny`.
    #[serde(default)]
    pub extras: ExtrasPolicy,
    /// What to do when the strict shape does not match. Default: `Deny`
    /// (fall through to the next rule).
    #[serde(default)]
    pub on_mismatch: OnMismatchPolicy,
}

/// Specification for a single declared flag in an `ArgvShape`.
///
/// Two JSON forms are accepted:
/// - Tagged form: `{ "type": "boolean" }` or `{ "type": "required", "value": "..." }`.
/// - Value-only sugar: `{ "value": "..." }` — equivalent to a `Required` flag.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum FlagSpec {
    /// Tagged form, discriminated by a `type` field.
    Tagged(FlagSpecTagged),
    /// Sugar: a flag that requires the given value.
    ValueOnly { value: String },
}

/// Tagged variants of `FlagSpec`, discriminated by `type`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FlagSpecTagged {
    /// A boolean flag: present in the invocation, no value attached.
    Boolean,
    /// A flag that must be present with the given value.
    Required { value: String },
}

impl FlagSpec {
    /// Returns the required value for this flag, or `None` if it's a boolean flag.
    pub fn as_required_value(&self) -> Option<&str> {
        match self {
            FlagSpec::ValueOnly { value } => Some(value.as_str()),
            FlagSpec::Tagged(FlagSpecTagged::Required { value }) => Some(value.as_str()),
            FlagSpec::Tagged(FlagSpecTagged::Boolean) => None,
        }
    }

    /// Returns true if this flag is a boolean (no value) flag.
    pub fn is_boolean(&self) -> bool {
        matches!(self, FlagSpec::Tagged(FlagSpecTagged::Boolean))
    }
}

/// Policy for extra positional/flag arguments beyond those declared in `ArgvShape`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtrasPolicy {
    /// Reject the invocation if any extras are present. Default.
    #[default]
    Deny,
    /// Allow extras to pass through.
    Allow,
}

/// Policy for what to do when an `ArgvShape` does not match the invocation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OnMismatchPolicy {
    /// Treat as a non-match; fall through to the next rule. Default.
    #[default]
    Deny,
    /// Trigger an approval prompt instead of denying outright.
    Approve,
}

/// The action to take when an intercept rule fires.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InterceptAction {
    /// Return a static response without calling the real binary.
    Respond {
        #[serde(default)]
        stdout: String,
        #[serde(default)]
        exit_code: i32,
    },
    /// Capture a credential and return a nonce to the sandbox.
    ///
    /// If `script` is set, runs `sh -c "<script>"` and captures its stdout.
    /// If `script` is absent, runs the real binary with the original args.
    /// The captured stdout (trimmed) is stored in the broker; the nonce is returned.
    Capture {
        /// Optional shell script to run instead of the real binary.
        /// Runs via `sh -c` in the unsandboxed parent. Stdout is the credential.
        #[serde(default)]
        script: Option<String>,
    },
    /// Run the real binary and return its actual output (no nonce wrapping).
    ///
    /// Useful with `admin: true` to gate sensitive-but-non-secret commands
    /// behind an approval step while still showing the real output.
    /// No per-command sandbox is applied — the binary needs unrestricted
    /// access to system resources (e.g. macOS Keychain via securityd).
    /// Protection comes from the profile author's choice of which commands
    /// and subcommands receive `approve` actions.
    /// If `script` is set, runs `sh -c "<script>"` instead of the real binary.
    Approve {
        /// Optional shell script to run instead of the real binary.
        #[serde(default)]
        script: Option<String>,
    },
}

/// Sandbox profile applied when exec-ing the real binary for a passthrough command.
///
/// Default (when absent): no sandbox applied — existing behavior.
/// Operators opt in per command. Applied via `pre_exec` in `exec_passthrough`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CommandSandbox {
    /// Network policy for the exec'd command. Default: allow all (no restriction).
    #[serde(default)]
    pub network: NetworkConfig,
    /// Directories the command may read.
    #[serde(default)]
    pub fs_read: Vec<String>,
    /// Individual files the command may read.
    #[serde(default)]
    pub fs_read_file: Vec<String>,
    /// Directories the command may write.
    #[serde(default)]
    pub fs_write: Vec<String>,
    /// Individual files the command may write.
    #[serde(default)]
    pub fs_write_file: Vec<String>,
    /// Commands allowed to execute directly (real binary, not shim) inside this
    /// per-command sandbox. Their output stays within the sandbox.
    #[serde(default)]
    pub allow_commands: Vec<String>,
    /// If true, grant read access to macOS Keychain database files
    /// (`login.keychain-db`, `metadata.keychain-db`). This causes the Seatbelt
    /// profile to skip its default mach-lookup denies for security daemons
    /// (SecurityServer, securityd, keychaind, secd), allowing the command to
    /// retrieve credentials from the system keychain.
    ///
    /// Use this for commands that authenticate via macOS Keychain (e.g. `gh`,
    /// which stores its GitHub token there). The token flows through the command
    /// internally — it does not appear in stdout visible to the agent.
    ///
    /// Default: false. macOS only; ignored on other platforms.
    #[serde(default)]
    pub keychain_access: bool,
}

/// Simple network config for per-command sandbox profiles.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct NetworkConfig {
    /// If true, block all outbound network. Default: false (allow all).
    #[serde(default)]
    pub block: bool,
    /// If non-empty, start a per-command proxy restricting outbound
    /// connections to these hosts. Mutually exclusive with `block`.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
}

/// Session context stamped onto every audit event.
///
/// Constructed once in `execution_runtime` before the sandbox is applied and
/// threaded through to the mediation server. `sandboxed_pid` is filled in via the
/// latch after the sandboxed agent process is forked.
#[derive(Clone)]
pub struct SessionAuditInfo {
    pub session_id: String,
    pub session_name: Option<String>,
    /// PID of the nono process itself (the unsandboxed supervisor).
    pub nono_pid: u32,
    /// Filled in once the sandboxed agent is forked; reads as `None` before that.
    pub sandboxed_pid: Arc<OnceLock<u32>>,
}

/// Audit event for command logging.
///
/// Process hierarchy per log entry:
///   `nono_pid`    — the nono sandbox process (unsandboxed supervisor)
///   `sandboxed_pid` — the sandboxed child process (e.g. claude, codex), direct child of nono
///   `command_pid`   — the shim process that executed the logged command
///                     (e.g. the process running "echo" or "git"), child of the sandboxed process
///
/// The session/process fields use `#[serde(default)]` so that older shim-
/// originated datagrams (which do not include them) still deserialize cleanly;
/// the server stamps the session/nono/sandboxed fields after deserialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// The command name (basename of argv[0]).
    pub command: String,
    /// Positional arguments passed to the command.
    pub args: Vec<String>,
    /// Unix timestamp (seconds since epoch).
    pub ts: u64,
    /// Process exit code. Always present.
    pub exit_code: i32,
    /// Which intercept action fired (respond/capture/approve/passthrough/admin_passthrough).
    /// Only set for mediated commands; absent for audit-mode commands.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_type: Option<String>,
    /// Session ID from the nono session registry (`~/.nono/sessions/{id}.json`).
    #[serde(default)]
    pub session_id: String,
    /// Human-readable session name (from `--name` or auto-generated).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_name: Option<String>,
    /// PID of the nono process (the unsandboxed supervisor).
    #[serde(default)]
    pub nono_pid: u32,
    /// PID of the sandboxed child process (e.g. claude, codex). `None` until after fork.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandboxed_pid: Option<u32>,
    /// PID of the shim process that ran this specific command (e.g. the process
    /// that executed "echo" or "git"). Child of the agent process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_pid: Option<u32>,
}

/// Environment variable policy for the sandboxed child process.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct EnvPolicy {
    /// Env var names to strip from the child environment (credential leakage prevention).
    #[serde(default)]
    pub block: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_config_allowed_hosts_deserializes() {
        let json = r#"{
            "allowed_hosts": ["github.com", "*.github.com", "api.github.com"]
        }"#;
        let config: NetworkConfig = serde_json::from_str(json).expect("deserialize");
        assert!(!config.block);
        assert_eq!(
            config.allowed_hosts,
            vec!["github.com", "*.github.com", "api.github.com"]
        );
    }

    #[test]
    fn test_network_config_block_and_allowed_hosts_coexist() {
        let json = r#"{"block": true, "allowed_hosts": ["github.com"]}"#;
        let config: NetworkConfig = serde_json::from_str(json).expect("deserialize");
        assert!(config.block);
        assert_eq!(config.allowed_hosts, vec!["github.com"]);
    }

    #[test]
    fn test_network_config_default_has_empty_allowed_hosts() {
        let config = NetworkConfig::default();
        assert!(!config.block);
        assert!(config.allowed_hosts.is_empty());
    }

    #[test]
    fn test_command_sandbox_allow_commands_deserializes() {
        let json = r#"{
            "allow_commands": ["ddtool", "kubectl"],
            "network": { "block": true }
        }"#;
        let sb: CommandSandbox = serde_json::from_str(json).expect("deserialize");
        assert_eq!(sb.allow_commands, vec!["ddtool", "kubectl"]);
        assert!(sb.network.block);
    }

    #[test]
    fn test_command_sandbox_allow_commands_defaults_empty() {
        let json = r#"{ "network": { "block": false } }"#;
        let sb: CommandSandbox = serde_json::from_str(json).expect("deserialize");
        assert!(sb.allow_commands.is_empty());
    }

    #[test]
    fn test_command_sandbox_default_has_empty_allow_commands() {
        let sb = CommandSandbox::default();
        assert!(sb.allow_commands.is_empty());
    }

    #[test]
    fn test_command_sandbox_fs_file_fields_deserialize() {
        let json = r#"{
            "fs_read": ["~/.config/gh"],
            "fs_read_file": ["~/.gitconfig", "~/.vault-token"],
            "fs_write": ["~/.config/ddtool"],
            "fs_write_file": ["~/.vault-token"]
        }"#;
        let sb: CommandSandbox = serde_json::from_str(json).expect("deserialize");
        assert_eq!(sb.fs_read, vec!["~/.config/gh"]);
        assert_eq!(sb.fs_read_file, vec!["~/.gitconfig", "~/.vault-token"]);
        assert_eq!(sb.fs_write, vec!["~/.config/ddtool"]);
        assert_eq!(sb.fs_write_file, vec!["~/.vault-token"]);
    }

    #[test]
    fn test_command_sandbox_fs_file_fields_default_empty() {
        let json = r#"{ "fs_read": ["~/.ssh"] }"#;
        let sb: CommandSandbox = serde_json::from_str(json).expect("deserialize");
        assert_eq!(sb.fs_read, vec!["~/.ssh"]);
        assert!(sb.fs_read_file.is_empty());
        assert!(sb.fs_write.is_empty());
        assert!(sb.fs_write_file.is_empty());
    }

    #[test]
    fn test_command_sandbox_keychain_access_deserializes() {
        let json = r#"{
            "keychain_access": true,
            "network": { "allowed_hosts": ["github.com"] }
        }"#;
        let sb: CommandSandbox = serde_json::from_str(json).expect("deserialize");
        assert!(sb.keychain_access);
    }

    #[test]
    fn test_command_sandbox_keychain_access_defaults_false() {
        let json = r#"{ "network": { "block": false } }"#;
        let sb: CommandSandbox = serde_json::from_str(json).expect("deserialize");
        assert!(!sb.keychain_access);
    }

    #[test]
    fn test_command_sandbox_default_has_keychain_access_false() {
        let sb = CommandSandbox::default();
        assert!(!sb.keychain_access);
    }

    #[test]
    fn test_caller_policy_defaults_are_backward_compatible() {
        let policy = CallerPolicy::default();
        assert!(
            policy.agent_allowed,
            "default must allow agent invocations to preserve existing behaviour"
        );
        assert!(
            policy.allowed_parents.is_none(),
            "default must accept any mediated parent (None means unrestricted)"
        );
    }

    #[test]
    fn test_caller_policy_omitted_in_json_uses_default() {
        let json = r#"{ "name": "git" }"#;
        let entry: CommandEntry = serde_json::from_str(json).expect("deserialize");
        assert!(entry.caller_policy.agent_allowed);
        assert!(entry.caller_policy.allowed_parents.is_none());
    }

    #[test]
    fn test_caller_policy_distinguishes_null_vs_empty_allowed_parents() {
        // Field absent: any parent allowed.
        let p1: CallerPolicy = serde_json::from_str(r#"{ "agent_allowed": true }"#).unwrap();
        assert!(p1.allowed_parents.is_none());

        // Empty array: no mediated parent allowed.
        let p2: CallerPolicy = serde_json::from_str(r#"{ "allowed_parents": [] }"#).unwrap();
        assert_eq!(p2.allowed_parents.as_deref(), Some(&[][..]));

        // Listed: only the named parents allowed.
        let p3: CallerPolicy = serde_json::from_str(r#"{ "allowed_parents": ["git"] }"#).unwrap();
        assert_eq!(
            p3.allowed_parents.as_deref(),
            Some(&["git".to_string()][..])
        );
    }

    #[test]
    fn test_caller_policy_agent_allowed_can_be_false() {
        let json = r#"{ "agent_allowed": false, "allowed_parents": ["git"] }"#;
        let policy: CallerPolicy = serde_json::from_str(json).expect("deserialize");
        assert!(!policy.agent_allowed);
        assert_eq!(
            policy.allowed_parents.as_deref(),
            Some(&["git".to_string()][..])
        );
    }

    #[test]
    fn test_argv_shape_deserializes_with_required_flag() {
        let json = r#"{
            "subcommand": "find-generic-password",
            "flags": {
                "-a": { "value": "kipz" },
                "-s": { "value": "Claude Code-credentials" }
            }
        }"#;
        let shape: ArgvShape = serde_json::from_str(json).expect("deserialize");
        assert_eq!(shape.subcommand, "find-generic-password");
        assert_eq!(shape.flags.len(), 2);
        match shape.flags.get("-a").unwrap() {
            FlagSpec::ValueOnly { value } => assert_eq!(value, "kipz"),
            _ => panic!("expected ValueOnly"),
        }
        // Default extras policy is Deny.
        assert!(matches!(shape.extras, ExtrasPolicy::Deny));
    }

    #[test]
    fn test_argv_shape_deserializes_with_boolean_flag() {
        let json = r#"{
            "subcommand": "find-generic-password",
            "flags": {
                "-w": { "type": "boolean" }
            }
        }"#;
        let shape: ArgvShape = serde_json::from_str(json).expect("deserialize");
        match shape.flags.get("-w").unwrap() {
            FlagSpec::Tagged(FlagSpecTagged::Boolean) => {}
            _ => panic!("expected Tagged(Boolean)"),
        }
    }

    #[test]
    fn test_argv_shape_extras_allow_explicit() {
        let json = r#"{
            "subcommand": "find-generic-password",
            "flags": {},
            "extras": "allow"
        }"#;
        let shape: ArgvShape = serde_json::from_str(json).expect("deserialize");
        assert!(matches!(shape.extras, ExtrasPolicy::Allow));
    }

    #[test]
    fn test_argv_shape_on_mismatch_default_is_deny() {
        // Field absent → OnMismatchPolicy::Deny.
        let json = r#"{
            "subcommand": "find-generic-password",
            "flags": {}
        }"#;
        let shape: ArgvShape = serde_json::from_str(json).expect("deserialize");
        assert!(matches!(shape.on_mismatch, OnMismatchPolicy::Deny));
    }

    #[test]
    fn test_argv_shape_on_mismatch_approve_explicit() {
        let json = r#"{
            "subcommand": "find-generic-password",
            "flags": {},
            "on_mismatch": "approve"
        }"#;
        let shape: ArgvShape = serde_json::from_str(json).expect("deserialize");
        assert!(matches!(shape.on_mismatch, OnMismatchPolicy::Approve));
    }

    #[test]
    fn test_intercept_rule_rejects_both_args_prefix_and_argv_shape() {
        let json = r#"{
            "args_prefix": ["foo"],
            "argv_shape": {
                "subcommand": "foo",
                "flags": {}
            },
            "action": { "type": "respond", "stdout": "" }
        }"#;
        let res: std::result::Result<InterceptRule, _> = serde_json::from_str(json);
        // Schema-level deserialize succeeds; the validation is performed during
        // resolve. So just verify the struct holds both fields and resolution
        // (Task 4) will reject.
        let rule = res.expect("schema-level deserialize must succeed");
        assert!(!rule.args_prefix.is_empty() && rule.argv_shape.is_some());
    }

    #[test]
    fn test_caller_policy_parent_sandbox_deserializes() {
        let json = r#"{
            "agent_allowed": true,
            "allowed_parents": ["gh", "git"],
            "parent_sandbox": {
                "gh": {
                    "fs_read": ["."],
                    "network": { "block": true }
                }
            }
        }"#;
        let p: CallerPolicy = serde_json::from_str(json).expect("deserialize");
        assert!(p.agent_allowed);
        assert_eq!(p.parent_sandbox.len(), 1);
        let gh_sb = p.parent_sandbox.get("gh").expect("gh entry present");
        assert_eq!(gh_sb.fs_read, vec!["."]);
        assert!(gh_sb.network.block);
    }

    #[test]
    fn test_caller_policy_parent_sandbox_default_empty() {
        let p: CallerPolicy = serde_json::from_str(r#"{}"#).expect("deserialize");
        assert!(p.parent_sandbox.is_empty(), "default must be empty map");
    }

    #[test]
    fn test_caller_policy_default_has_empty_parent_sandbox() {
        let p = CallerPolicy::default();
        assert!(p.parent_sandbox.is_empty());
    }

    #[test]
    fn test_caller_policy_deny_agent_strict_defaults_false() {
        let p: CallerPolicy = serde_json::from_str(r#"{}"#).expect("deserialize");
        assert!(!p.deny_agent_strict);
        let p2 = CallerPolicy::default();
        assert!(!p2.deny_agent_strict);
        let p3: CallerPolicy = serde_json::from_str(r#"{"deny_agent_strict": true}"#)
            .expect("deserialize");
        assert!(p3.deny_agent_strict);
    }
}
