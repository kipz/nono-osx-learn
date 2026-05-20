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
pub mod approval;
pub mod broker;
pub mod control;
pub mod matcher;
pub mod merge;
pub mod policy;
pub mod promote;
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
    /// Required default. Dispatched when no intercept rule matches the
    /// invocation's argv. The legacy implicit fall-through is gone:
    /// profiles must spell out what to do for unmatched calls.
    pub default: DefaultEntry,
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

/// Default action for a command. Dispatched when no intercept matches.
/// Grants reference this entry as `<command>.default`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DefaultEntry {
    /// Always "default". Skipped on serialise; defaulted on deserialise.
    #[serde(default = "default_id_value", skip_serializing)]
    pub id: String,

    /// Required action.
    pub action: InterceptAction,

    /// Optional fallback sandbox. Intercepts that omit their own `sandbox`
    /// inherit this when running.
    #[serde(default)]
    pub sandbox: Option<CommandSandbox>,

    /// Optional per-default scoping of nonce promotion. Same semantics as
    /// `InterceptRule::promote_in` — declares which argv slots and env vars
    /// may receive promoted credentials when this default action dispatches.
    /// Intercepts do NOT inherit this from the default; each rule's
    /// `promote_in` is independent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promote_in: Option<PromoteFilter>,
}

fn default_id_value() -> String {
    "default".to_string()
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
}

impl Default for CallerPolicy {
    fn default() -> Self {
        Self {
            agent_allowed: true,
            allowed_parents: None,
        }
    }
}

fn default_true() -> bool {
    true
}

/// Boolean predicate tree against an invocation's argv.
///
/// Profiles author intercept matchers as a recursive JSON shape: combinators
/// (`all` / `any` / `not`) compose leaves (`any_arg_matches`, `nth_arg_matches`,
/// `all_args_match`). The matcher is evaluated only against the argv passed to
/// the mediated command — it does not see env, cwd, or stdin. Regex leaves
/// use the `regex` crate (linear-time, no catastrophic backtracking; inline
/// flags `(?i)`, `(?m)` etc. supported).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum ArgsMatcher {
    /// Conjunction. Empty list = vacuously true (matches anything).
    All {
        all: Vec<ArgsMatcher>,
    },
    /// Disjunction. Empty list = vacuously false.
    Any {
        any: Vec<ArgsMatcher>,
    },
    /// Logical NOT.
    Not {
        not: Box<ArgsMatcher>,
    },
    /// At least one argv element matches `any_arg_matches` as a regex.
    AnyArgMatches {
        any_arg_matches: String,
    },
    /// Every argv element matches `all_args_match` (or argv is empty).
    AllArgsMatch {
        all_args_match: String,
    },
    /// argv element at `index` (0-based, counts flags) matches `regex`.
    NthArgMatches {
        nth_arg_matches: usize,
        regex: String,
    },
}

/// An intercept rule. Fires when its matcher accepts the invocation's argv.
///
/// Authors specify the matcher via the required `match` field as a predicate
/// tree (see `ArgsMatcher`). An empty `all: []` matcher matches everything.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InterceptRule {
    /// Optional identifier within the command's intercept list. Used by
    /// `Capture.grant_to` references in the form `<command>.<id>`. The id
    /// `"default"` is reserved for the command's default entry; setting it
    /// on an intercept is a profile-load error.
    #[serde(default)]
    pub id: Option<String>,

    /// Predicate-tree matcher against argv. Required: profile load fails if
    /// a rule omits `match`.
    #[serde(rename = "match")]
    pub matcher: ArgsMatcher,

    /// Require user authentication before the action runs.
    #[serde(default)]
    pub admin: bool,

    /// What to do on match.
    pub action: InterceptAction,

    /// Tri-state per-invocation sandbox binding. See `SandboxBinding` for
    /// JSON encoding (absent vs `null` vs object). When set on a `Run` rule,
    /// an `Explicit` binding replaces the command-level sandbox for that
    /// single invocation; an `ExplicitlyUnsandboxed` binding disables any
    /// per-command sandbox; `InheritFromDefault` (absent) falls back to
    /// `cmd.default.sandbox`. `Capture` ignores this field — it runs the
    /// real binary in the broker parent (unsandboxed) so credential helpers
    /// can reach the Keychain, OAuth flows, etc. `Respond` ignores it too
    /// (no exec happens).
    #[serde(default)]
    pub sandbox: SandboxBinding,

    /// Optional per-intercept scoping of nonce promotion. See `PromoteFilter`
    /// for semantics: when absent, argv promotion is suppressed entirely and
    /// env promotion falls back to the built-in safe-shape allowlist; when
    /// present, the contained predicates declare which argv slots and env
    /// vars are admissible for promotion at this redemption site.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promote_in: Option<PromoteFilter>,
}

/// Per-intercept scoping of nonce promotion.
///
/// Each sub-predicate is independently optional. Defaults are secure:
/// `args == None` ⇒ no argv slot promotes (the redemption site must declare
/// which positional slots may receive a credential). `env == None` ⇒ the
/// built-in safe-shape env name allowlist (`PROMOTE_ENV_DEFAULT_NAMES` in
/// `mediation::promote`) decides. To widen env promotion explicitly, set a
/// custom `EnvPredicate` that unions the default regex with whatever extra
/// names the rule needs.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PromoteFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<ArgPredicate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<EnvPredicate>,
}

/// Argv-slot predicate for `PromoteFilter`.
///
/// Evaluated per-arg (not per-argv): each leaf answers "may *this* slot
/// receive promotion?". Combinators mirror `ArgsMatcher`. Empty `any_of: []`
/// never promotes (defensive lock); empty `all_of: []` always promotes
/// (vacuous).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum ArgPredicate {
    /// Conjunction. Empty list = vacuously true.
    AllOf { all_of: Vec<ArgPredicate> },
    /// Disjunction. Empty list = vacuously false.
    AnyOf { any_of: Vec<ArgPredicate> },
    /// Logical NOT.
    Not { not: Box<ArgPredicate> },
    /// argv[i] matches `self_matches` as a regex. Handles attached
    /// `-Hnono_<hex>` and `--header=Authorization: Bearer nono_<hex>` forms.
    SelfMatches { self_matches: String },
    /// argv[i-1] matches `preceded_by_arg` as a regex. argv[0] always misses
    /// (no left neighbour). Handles separate-arg `["-H", "Authorization:
    /// Bearer nono_<hex>"]` form.
    PrecededByArg { preceded_by_arg: String },
    /// argv[i] is exactly at position `at_index` (0-based).
    AtIndex { at_index: usize },
}

/// Env-var predicate for `PromoteFilter`.
///
/// Env values are stored in a `HashMap<String, String>` with no positional
/// context; the predicates accordingly key off var name and (optionally) value
/// rather than position. Combinators mirror `ArgPredicate`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum EnvPredicate {
    /// Conjunction. Empty list = vacuously true.
    AllOf { all_of: Vec<EnvPredicate> },
    /// Disjunction. Empty list = vacuously false.
    AnyOf { any_of: Vec<EnvPredicate> },
    /// Logical NOT.
    Not { not: Box<EnvPredicate> },
    /// The env var's name matches `name_matches` as a regex.
    NameMatches { name_matches: String },
    /// The env var's value matches `value_matches` as a regex. Belt-and-
    /// braces; rarely needed alongside `name_matches`.
    ValueMatches { value_matches: String },
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
        stderr: String,
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

        /// Consumers authorised to redeem nonces minted by this capture.
        /// Each entry is `<command>.<intercept-id>` (or `<command>.default`
        /// for the command's default action). Empty list = never redeemable
        /// (defensive captures whose nonces have no legitimate consumer).
        /// Required: profile load fails if the field is missing.
        grant_to: Vec<String>,
    },
    /// Run the real binary, stream stdio directly. Optionally substitute via
    /// `script` (`sh -c "<script>"`). The effective sandbox is the matched
    /// rule's `sandbox` field if set, falling back to `cmd.default.sandbox`
    /// (A.5 wires this fallback chain more precisely), then `cmd.sandbox`,
    /// then no sandbox.
    Run {
        /// Optional shell-script substitution. When set, runs `sh -c "<script>"`
        /// instead of the real binary. Same semantics as `Capture.script`.
        #[serde(default)]
        script: Option<String>,
    },
}

/// Tri-state sandbox binding on an intercept rule.
///
/// - JSON field absent → `InheritFromDefault` — at exec time, falls back
///   to `cmd.default.sandbox` if set, then the legacy command-level
///   `cmd.sandbox`, then no sandbox.
/// - JSON `"sandbox": null` → `ExplicitlyUnsandboxed` — opts out of
///   inheritance entirely; the rule runs without any per-command sandbox.
/// - JSON `"sandbox": { ... }` → `Explicit(CommandSandbox)` — use this
///   exact sandbox for the matched call.
#[derive(Debug, Clone, Default)]
pub enum SandboxBinding {
    #[default]
    InheritFromDefault,
    ExplicitlyUnsandboxed,
    Explicit(CommandSandbox),
}

impl<'de> Deserialize<'de> for SandboxBinding {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        // serde calls this only when the field IS present (because of
        // #[serde(default)] on the field itself returning InheritFromDefault
        // when absent). So None here means "null"; Some means "object".
        let v: Option<CommandSandbox> = Option::deserialize(de)?;
        Ok(match v {
            None => SandboxBinding::ExplicitlyUnsandboxed,
            Some(sb) => SandboxBinding::Explicit(sb),
        })
    }
}

impl serde::Serialize for SandboxBinding {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            SandboxBinding::InheritFromDefault => s.serialize_none(),
            SandboxBinding::ExplicitlyUnsandboxed => s.serialize_none(),
            SandboxBinding::Explicit(sb) => sb.serialize(s),
        }
    }
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
        let json = r#"{
            "name": "git",
            "default": { "action": { "type": "run" } }
        }"#;
        let entry: CommandEntry = serde_json::from_str(json).expect("deserialize");
        assert!(entry.caller_policy.agent_allowed);
        assert!(entry.caller_policy.allowed_parents.is_none());
    }

    #[test]
    fn test_caller_policy_distinguishes_null_vs_empty_allowed_parents() {
        // Field absent: any parent allowed.
        let p1: CallerPolicy =
            serde_json::from_str(r#"{ "agent_allowed": true }"#).expect("deserialize p1");
        assert!(p1.allowed_parents.is_none());

        // Empty array: no mediated parent allowed.
        let p2: CallerPolicy =
            serde_json::from_str(r#"{ "allowed_parents": [] }"#).expect("deserialize p2");
        assert_eq!(p2.allowed_parents.as_deref(), Some(&[][..]));

        // Listed: only the named parents allowed.
        let p3: CallerPolicy =
            serde_json::from_str(r#"{ "allowed_parents": ["git"] }"#).expect("deserialize p3");
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
    fn args_matcher_round_trip_each_variant() {
        use serde_json::json;

        let cases: &[(&str, serde_json::Value)] = &[
            ("any_arg_matches", json!({ "any_arg_matches": "^foo" })),
            ("all_args_match", json!({ "all_args_match": "^-" })),
            (
                "nth_arg_matches",
                json!({ "nth_arg_matches": 2, "regex": "^https://" }),
            ),
            (
                "not",
                json!({ "not": { "any_arg_matches": "--insecure" } }),
            ),
            (
                "all",
                json!({
                    "all": [
                        { "any_arg_matches": "^https://gitlab\\.ddbuild\\.io" },
                        { "not": { "any_arg_matches": "^-k$" } },
                    ]
                }),
            ),
            (
                "any",
                json!({
                    "any": [
                        { "any_arg_matches": "^a$" },
                        { "any_arg_matches": "^b$" },
                    ]
                }),
            ),
        ];

        for (label, value) in cases {
            let m: ArgsMatcher = serde_json::from_value(value.clone())
                .unwrap_or_else(|e| panic!("{}: deserialize failed: {}", label, e));
            let back = serde_json::to_value(&m)
                .unwrap_or_else(|e| panic!("{}: serialize failed: {}", label, e));
            assert_eq!(back, *value, "{}: round-trip mismatch", label);
        }
    }

    #[test]
    fn args_matcher_rejects_unknown_keys() {
        let bad = serde_json::json!({ "any_arg_matches": "x", "garbage": true });
        let r: Result<ArgsMatcher, _> = serde_json::from_value(bad);
        assert!(r.is_err(), "deny_unknown_fields should reject extras");
    }

    #[test]
    fn args_matcher_rejects_ambiguous_shapes() {
        // An untagged enum will pick the first variant that matches. Verify the
        // serde layout doesn't silently accept two variants in one object.
        let ambiguous = serde_json::json!({
            "all": [],
            "any_arg_matches": "x"
        });
        let r: Result<ArgsMatcher, _> = serde_json::from_value(ambiguous);
        assert!(r.is_err(), "object with two variant keys must not parse");
    }

    #[test]
    fn intercept_rule_round_trips_id_field() {
        use serde_json::json;
        let v = json!({
            "id": "my-rule",
            "match": { "any_arg_matches": "x" },
            "action": { "type": "respond", "stdout": "hi", "exit_code": 0 }
        });
        let r: InterceptRule = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(r.id.as_deref(), Some("my-rule"));
        let back = serde_json::to_value(&r).unwrap();
        assert_eq!(back["id"], "my-rule");
    }

    #[test]
    fn intercept_rule_id_optional() {
        use serde_json::json;
        let v = json!({
            "match": { "any_arg_matches": "x" },
            "action": { "type": "respond", "stdout": "hi", "exit_code": 0 }
        });
        let r: InterceptRule = serde_json::from_value(v).unwrap();
        assert_eq!(r.id, None);
    }

    #[test]
    fn command_entry_round_trips_default_entry() {
        use serde_json::json;
        let v = json!({
            "name": "gh",
            "default": {
                "action": { "type": "respond", "stdout": "", "exit_code": 0 },
                "sandbox": { "network": { "allowed_hosts": ["github.com"] } }
            }
        });
        let c: CommandEntry = serde_json::from_value(v).unwrap();
        assert_eq!(c.default.id, "default");
        assert!(c.default.sandbox.is_some());
    }

    #[test]
    fn command_entry_rejects_missing_default() {
        use serde_json::json;
        let v = json!({ "name": "no-default" });
        let r: Result<CommandEntry, _> = serde_json::from_value(v);
        assert!(
            r.is_err(),
            "command entry without 'default' must fail to deserialize"
        );
    }

    #[test]
    fn default_entry_id_defaults_to_default() {
        use serde_json::json;
        let v = json!({ "action": { "type": "respond", "stdout": "x", "exit_code": 0 } });
        let d: DefaultEntry = serde_json::from_value(v).unwrap();
        assert_eq!(d.id, "default");
    }

    #[test]
    fn default_entry_id_field_is_not_serialised() {
        let d = DefaultEntry {
            id: "default".to_string(),
            action: InterceptAction::Respond {
                stdout: "ok".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
            sandbox: None,
            promote_in: None,
        };
        let v = serde_json::to_value(&d).unwrap();
        assert!(v.get("id").is_none(), "id should be skipped on serialise");
    }

    // ------------------------------------------------------------------
    // PromoteFilter / ArgPredicate / EnvPredicate (input shape only)
    // ------------------------------------------------------------------

    #[test]
    fn arg_predicate_round_trips_each_variant() {
        use serde_json::json;
        let cases: &[(&str, serde_json::Value)] = &[
            ("self_matches", json!({ "self_matches": "^-H" })),
            (
                "preceded_by_arg",
                json!({ "preceded_by_arg": "^(-H|--header)$" }),
            ),
            ("at_index", json!({ "at_index": 3 })),
            (
                "not",
                json!({ "not": { "self_matches": "^--data" } }),
            ),
            (
                "any_of",
                json!({
                    "any_of": [
                        { "self_matches": "^-H" },
                        { "preceded_by_arg": "^-H$" }
                    ]
                }),
            ),
            (
                "all_of",
                json!({
                    "all_of": [
                        { "self_matches": "^Authorization:" },
                        { "preceded_by_arg": "^-H$" }
                    ]
                }),
            ),
        ];
        for (label, value) in cases {
            let p: ArgPredicate = serde_json::from_value(value.clone())
                .unwrap_or_else(|e| panic!("{}: deserialize failed: {}", label, e));
            let back = serde_json::to_value(&p)
                .unwrap_or_else(|e| panic!("{}: serialize failed: {}", label, e));
            assert_eq!(back, *value, "{}: round-trip mismatch", label);
        }
    }

    #[test]
    fn arg_predicate_rejects_unknown_keys() {
        let bad = serde_json::json!({ "self_matches": "x", "garbage": true });
        let r: Result<ArgPredicate, _> = serde_json::from_value(bad);
        assert!(r.is_err(), "deny_unknown_fields should reject extras");
    }

    #[test]
    fn arg_predicate_rejects_typo() {
        // Intentional misspelling: the user-facing field is `preceded_by_arg`.
        let bad = serde_json::json!({ "prededed_by_arg": "^-H$" });
        let r: Result<ArgPredicate, _> = serde_json::from_value(bad);
        assert!(r.is_err(), "typo'd field name must not deserialise");
    }

    #[test]
    fn env_predicate_round_trips_each_variant() {
        use serde_json::json;
        let cases: &[(&str, serde_json::Value)] = &[
            ("name_matches", json!({ "name_matches": "(?i)^auth" })),
            ("value_matches", json!({ "value_matches": "^Bearer " })),
            (
                "not",
                json!({ "not": { "name_matches": "^DD_API_KEY$" } }),
            ),
            (
                "any_of",
                json!({
                    "any_of": [
                        { "name_matches": "^AUTHORIZATION$" },
                        { "name_matches": ".+_TOKEN$" }
                    ]
                }),
            ),
            (
                "all_of",
                json!({
                    "all_of": [
                        { "name_matches": "^AUTH_HEADER$" },
                        { "value_matches": "^Bearer " }
                    ]
                }),
            ),
        ];
        for (label, value) in cases {
            let p: EnvPredicate = serde_json::from_value(value.clone())
                .unwrap_or_else(|e| panic!("{}: deserialize failed: {}", label, e));
            let back = serde_json::to_value(&p)
                .unwrap_or_else(|e| panic!("{}: serialize failed: {}", label, e));
            assert_eq!(back, *value, "{}: round-trip mismatch", label);
        }
    }

    #[test]
    fn env_predicate_rejects_unknown_keys() {
        let bad = serde_json::json!({ "name_matches": "x", "matches": "y" });
        let r: Result<EnvPredicate, _> = serde_json::from_value(bad);
        assert!(r.is_err(), "deny_unknown_fields should reject extras");
    }

    #[test]
    fn promote_filter_round_trips_with_both_subfields() {
        use serde_json::json;
        let v = json!({
            "args": {
                "any_of": [
                    { "preceded_by_arg": "^(-H|--header)$" },
                    { "self_matches":    "^(-H|--header=)" }
                ]
            },
            "env": {
                "name_matches": "^AUTH_HEADER$"
            }
        });
        let p: PromoteFilter = serde_json::from_value(v.clone()).expect("deserialize");
        assert!(p.args.is_some());
        assert!(p.env.is_some());
        let back = serde_json::to_value(&p).expect("serialize");
        assert_eq!(back, v);
    }

    #[test]
    fn promote_filter_subfields_independently_optional() {
        // args only
        let p: PromoteFilter = serde_json::from_value(serde_json::json!({
            "args": { "self_matches": "^-H" }
        }))
        .expect("deserialize args-only");
        assert!(p.args.is_some());
        assert!(p.env.is_none());

        // env only
        let p: PromoteFilter = serde_json::from_value(serde_json::json!({
            "env": { "name_matches": "^X$" }
        }))
        .expect("deserialize env-only");
        assert!(p.args.is_none());
        assert!(p.env.is_some());

        // neither (empty object). Valid: the field on InterceptRule itself is
        // Option<PromoteFilter>, but if specified `{}` it parses to a
        // filter whose both subfields are None.
        let p: PromoteFilter =
            serde_json::from_value(serde_json::json!({})).expect("deserialize empty");
        assert!(p.args.is_none());
        assert!(p.env.is_none());
    }

    #[test]
    fn intercept_rule_round_trips_promote_in_field() {
        use serde_json::json;
        let v = json!({
            "id": "gitlab",
            "match": { "any_arg_matches": "^https://gitlab" },
            "action": { "type": "run" },
            "promote_in": {
                "args": {
                    "any_of": [
                        { "preceded_by_arg": "^(-H|--header)$" },
                        { "self_matches":    "^(-H|--header=)" }
                    ]
                }
            }
        });
        let r: InterceptRule = serde_json::from_value(v.clone()).expect("deserialize");
        assert!(
            r.promote_in.is_some(),
            "promote_in should round-trip when present"
        );
        let back = serde_json::to_value(&r).expect("serialize");
        assert_eq!(back["promote_in"], v["promote_in"]);
    }

    #[test]
    fn intercept_rule_promote_in_is_optional() {
        use serde_json::json;
        let v = json!({
            "match": { "any_arg_matches": "x" },
            "action": { "type": "run" }
        });
        let r: InterceptRule = serde_json::from_value(v).expect("deserialize");
        assert!(r.promote_in.is_none());
    }

    #[test]
    fn default_entry_round_trips_promote_in_field() {
        use serde_json::json;
        let v = json!({
            "action": { "type": "run" },
            "promote_in": {
                "env": { "name_matches": "(?i)^authorization$" }
            }
        });
        let d: DefaultEntry = serde_json::from_value(v.clone()).expect("deserialize");
        assert!(d.promote_in.is_some());
        let back = serde_json::to_value(&d).expect("serialize");
        assert_eq!(back["promote_in"], v["promote_in"]);
    }
}
