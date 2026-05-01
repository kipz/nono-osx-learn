//! Environment sanitization boundary for sandboxed execution.
//!
//! Threat model:
//! - Untrusted parent/shell environments may inject execution behavior via
//!   linker, shell, or interpreter environment variables.
//! - All sandbox execution strategies must share one allow/deny implementation
//!   to avoid drift in security behavior across code paths.

/// Returns true if an environment variable is unsafe to inherit into a sandboxed child.
///
/// Covers linker injection (LD_PRELOAD, DYLD_INSERT_LIBRARIES), shell startup
/// injection (BASH_ENV, PROMPT_COMMAND, IFS), and interpreter code/module injection
/// (NODE_OPTIONS, PYTHONPATH, PERL5OPT, RUBYOPT, JAVA_TOOL_OPTIONS, etc.).
pub(crate) fn is_dangerous_env_var(key: &str) -> bool {
    // Linker injection
    key.starts_with("LD_")
        || key.starts_with("DYLD_")
        // Shell injection
        || key == "BASH_ENV"
        || key == "ENV"
        || key == "CDPATH"
        || key == "GLOBIGNORE"
        || key.starts_with("BASH_FUNC_")
        || key == "PROMPT_COMMAND"
        || key == "IFS"
        // Python injection
        || key == "PYTHONSTARTUP"
        || key == "PYTHONPATH"
        // Node.js injection
        || key == "NODE_OPTIONS"
        || key == "NODE_PATH"
        // Perl injection
        || key == "PERL5OPT"
        || key == "PERL5LIB"
        // Ruby injection
        || key == "RUBYOPT"
        || key == "RUBYLIB"
        || key == "GEM_PATH"
        || key == "GEM_HOME"
        // JVM injection
        || key == "JAVA_TOOL_OPTIONS"
        || key == "_JAVA_OPTIONS"
        // .NET injection
        || key == "DOTNET_STARTUP_HOOKS"
        // Go injection
        || key == "GOFLAGS"
        // 1Password secrets and session tokens — meta-secrets used by
        // the parent to authenticate `op` CLI, must never leak to sandboxed child
        || key == "OP_SERVICE_ACCOUNT_TOKEN"
        || key == "OP_CONNECT_TOKEN"
        || key == "OP_CONNECT_HOST"
        || key.starts_with("OP_SESSION_")
        // NONO_GATE_* test-only knobs (e.g. NONO_GATE_FORCE_DENY) force the
        // approval gate into known verdicts. They must never leak into a
        // sandboxed child — otherwise the sandboxed agent could set
        // NONO_GATE_FORCE_DENY=0 in its own env and bypass the gate when nono
        // spawns mediated commands. Filter as a prefix so future NONO_GATE_*
        // vars are covered without code changes. The wider NONO_ prefix is
        // intentionally NOT filtered: nono itself sets NONO_SESSION_TOKEN,
        // NONO_MEDIATION_SOCKET, NONO_BROKER_SOCKET, NONO_CALLER, etc. for
        // sandboxed children, and those must pass through.
        || key.starts_with("NONO_GATE_")
}

/// Returns true if an environment variable matches the allow-list.
///
/// Supports exact names (`"PATH"`) and prefix patterns ending with `*`
/// (`"AWS_*"` matches `AWS_REGION`, `AWS_SECRET_ACCESS_KEY`, etc.).
/// A bare `"*"` matches everything. The `*` wildcard is only valid as a
/// trailing suffix — patterns like `"A*B"` or `"*X"` are rejected.
pub(crate) fn is_env_var_allowed(key: &str, allowed_env_vars: &[String]) -> bool {
    for pattern in allowed_env_vars {
        if let Some(prefix) = pattern.strip_suffix('*') {
            if prefix.contains('*') {
                continue;
            }
            if key.starts_with(prefix) {
                return true;
            }
        } else if !pattern.contains('*') && key == *pattern {
            return true;
        }
    }
    false
}

/// Validates that all allow-list patterns use `*` only as a trailing suffix.
/// Returns an error message describing the first invalid pattern, or None if valid.
pub(crate) fn validate_allow_vars_pattern(allow_vars: &[String]) -> Option<String> {
    for pattern in allow_vars {
        if pattern.contains('*') && !pattern.ends_with('*') {
            return Some(format!(
                "Invalid allow_vars pattern '{}': '*' is only valid as a trailing suffix",
                pattern
            ));
        }
        if pattern.starts_with('*') && pattern.len() > 1 {
            return Some(format!(
                "Invalid allow_vars pattern '{}': use a bare '*' to match all variables, or a specific prefix like 'AWS_*'",
                pattern
            ));
        }
    }
    None
}

/// Decide whether an inherited env var should be dropped for sandbox execution.
pub(super) fn should_skip_env_var(
    key: &str,
    config_env_vars: &[(&str, &str)],
    blocked_extra: &[&str],
) -> bool {
    config_env_vars.iter().any(|(ek, _)| *ek == key)
        || blocked_extra.contains(&key)
        || is_dangerous_env_var(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================================
    // 1Password env var blocklist — security-critical regression tests
    //
    // These vars are credential or session leaks that must NEVER reach a
    // sandboxed child process. If a future refactor accidentally removes one,
    // these tests will catch it.
    // ============================================================================

    #[test]
    fn test_blocks_op_service_account_token() {
        assert!(is_dangerous_env_var("OP_SERVICE_ACCOUNT_TOKEN"));
    }

    #[test]
    fn test_blocks_op_connect_token() {
        assert!(is_dangerous_env_var("OP_CONNECT_TOKEN"));
    }

    #[test]
    fn test_blocks_op_connect_host() {
        assert!(is_dangerous_env_var("OP_CONNECT_HOST"));
    }

    #[test]
    fn test_blocks_op_session_prefix() {
        // OP_SESSION_* vars carry per-account bearer tokens
        assert!(is_dangerous_env_var("OP_SESSION_my_team"));
        assert!(is_dangerous_env_var("OP_SESSION_personal"));
        assert!(is_dangerous_env_var("OP_SESSION_"));
    }

    #[test]
    fn test_allows_unrelated_env_vars() {
        // Env vars that happen to start with "OP" but aren't 1Password
        assert!(!is_dangerous_env_var("OPENAI_API_KEY"));
        assert!(!is_dangerous_env_var("OPERATOR_TOKEN"));
        assert!(!is_dangerous_env_var("OPTIONS"));
        assert!(!is_dangerous_env_var("HOME"));
        assert!(!is_dangerous_env_var("PATH"));
    }

    // ============================================================================
    // Existing categories — spot-check that the broader blocklist still works
    // ============================================================================

    #[test]
    fn test_blocks_linker_injection() {
        assert!(is_dangerous_env_var("LD_PRELOAD"));
        assert!(is_dangerous_env_var("DYLD_INSERT_LIBRARIES"));
    }

    #[test]
    fn test_blocks_interpreter_injection() {
        assert!(is_dangerous_env_var("NODE_OPTIONS"));
        assert!(is_dangerous_env_var("PYTHONPATH"));
        assert!(is_dangerous_env_var("RUBYOPT"));
    }

    // ============================================================================
    // NONO_GATE_* test-knob blocklist — security-critical regression tests.
    //
    // NONO_GATE_FORCE_DENY (and similar) force the approval gate into known
    // verdicts in tests. They must never reach a sandboxed agent — otherwise
    // the agent could set NONO_GATE_FORCE_DENY=0 in its own env and bypass
    // the gate when nono spawns mediated commands. The wider NONO_ prefix
    // is intentionally NOT filtered: nono itself sets NONO_SESSION_TOKEN,
    // NONO_MEDIATION_SOCKET, NONO_BROKER_SOCKET, and NONO_CALLER for
    // sandboxed children.
    // ============================================================================

    #[test]
    fn test_blocks_nono_gate_force_deny() {
        assert!(is_dangerous_env_var("NONO_GATE_FORCE_DENY"));
    }

    #[test]
    fn test_blocks_nono_gate_prefix() {
        // Any future NONO_GATE_* knob must be filtered.
        assert!(is_dangerous_env_var("NONO_GATE_FORCE_ALLOW"));
        assert!(is_dangerous_env_var("NONO_GATE_"));
        assert!(is_dangerous_env_var("NONO_GATE_ANY_NEW_KNOB"));
    }

    #[test]
    fn test_does_not_block_other_nono_vars() {
        // Vars set BY nono FOR sandboxed children must pass through.
        assert!(!is_dangerous_env_var("NONO_SESSION_TOKEN"));
        assert!(!is_dangerous_env_var("NONO_MEDIATION_SOCKET"));
        assert!(!is_dangerous_env_var("NONO_BROKER_SOCKET"));
        assert!(!is_dangerous_env_var("NONO_CALLER"));
        assert!(!is_dangerous_env_var("NONO_SANDBOX_CONTEXT"));
        assert!(!is_dangerous_env_var("NONO_CAP_FILE"));
        // Plausibly named vars that should not collide with the gate prefix.
        assert!(!is_dangerous_env_var("NONO_GATE")); // no trailing underscore
        assert!(!is_dangerous_env_var("NONO"));
    }

    // ============================================================================
    // Environment variable allow-list — is_env_var_allowed
    // ============================================================================

    #[test]
    fn test_env_var_allowed_exact_match() {
        let allowed: Vec<String> = vec!["PATH".into(), "HOME".into()];
        assert!(is_env_var_allowed("PATH", &allowed));
        assert!(is_env_var_allowed("HOME", &allowed));
    }

    #[test]
    fn test_env_var_allowed_exact_no_match() {
        let allowed: Vec<String> = vec!["PATH".into(), "HOME".into()];
        assert!(!is_env_var_allowed("SECRET", &allowed));
    }

    #[test]
    fn test_env_var_allowed_prefix_match() {
        let allowed: Vec<String> = vec!["AWS_*".into()];
        assert!(is_env_var_allowed("AWS_REGION", &allowed));
        assert!(is_env_var_allowed("AWS_SECRET_ACCESS_KEY", &allowed));
    }

    #[test]
    fn test_env_var_allowed_prefix_no_match() {
        let allowed: Vec<String> = vec!["AWS_*".into()];
        assert!(!is_env_var_allowed("GCP_REGION", &allowed));
    }

    #[test]
    fn test_env_var_allowed_empty_list() {
        let allowed: Vec<String> = vec![];
        assert!(!is_env_var_allowed("PATH", &allowed));
    }

    #[test]
    fn test_env_var_allowed_bare_star() {
        let allowed: Vec<String> = vec!["*".into()];
        assert!(is_env_var_allowed("ANYTHING", &allowed));
        assert!(is_env_var_allowed("PATH", &allowed));
    }

    #[test]
    fn test_env_var_allowed_prefix_does_not_match_partial() {
        let allowed: Vec<String> = vec!["AWS_*".into()];
        assert!(!is_env_var_allowed("AWS", &allowed));
    }

    #[test]
    fn test_env_var_allowed_prefix_matches_empty_suffix() {
        let allowed: Vec<String> = vec!["AWS_*".into()];
        assert!(is_env_var_allowed("AWS_", &allowed));
    }

    #[test]
    fn test_env_var_allowed_mixed_patterns() {
        let allowed: Vec<String> = vec!["PATH".into(), "AWS_*".into()];
        assert!(is_env_var_allowed("PATH", &allowed));
        assert!(is_env_var_allowed("AWS_REGION", &allowed));
        assert!(!is_env_var_allowed("HOME", &allowed));
    }

    #[test]
    fn test_env_var_allowed_mid_star_ignored() {
        let allowed: Vec<String> = vec!["A*B".into()];
        assert!(!is_env_var_allowed("AXB", &allowed));
        assert!(!is_env_var_allowed("A*B", &allowed));
    }

    // ============================================================================
    // Pattern validation — validate_allow_vars_pattern
    // ============================================================================

    #[test]
    fn test_validate_valid_patterns() {
        let patterns: Vec<String> = vec!["PATH".into(), "AWS_*".into(), "*".into()];
        assert!(validate_allow_vars_pattern(&patterns).is_none());
    }

    #[test]
    fn test_validate_rejects_mid_star() {
        let patterns: Vec<String> = vec!["A*B".into()];
        let err = validate_allow_vars_pattern(&patterns);
        assert!(err.is_some());
        assert!(err.as_ref().is_some_and(|e| e.contains("A*B")));
    }

    #[test]
    fn test_validate_rejects_leading_star_with_suffix() {
        let patterns: Vec<String> = vec!["*X".into()];
        let err = validate_allow_vars_pattern(&patterns);
        assert!(err.is_some());
        assert!(err.as_ref().is_some_and(|e| e.contains("*X")));
    }

    #[test]
    fn test_validate_accepts_bare_star() {
        let patterns: Vec<String> = vec!["*".into()];
        assert!(validate_allow_vars_pattern(&patterns).is_none());
    }

    #[test]
    fn test_validate_exact_name_no_star() {
        let patterns: Vec<String> = vec!["PATH".into()];
        assert!(validate_allow_vars_pattern(&patterns).is_none());
    }
}
