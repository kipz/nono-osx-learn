//! Approval gate abstraction for admin-gated intercept rules.
//!
//! The `ApprovalGate` trait abstracts the mechanism used to obtain human
//! approval before executing a command guarded by `admin: true`.
//!
//! `NativeApprovalGate` spawns `nono-approve` (a separate binary that presents
//! a native macOS TouchID/password dialog). The gate is synchronous; callers
//! must wrap it in `tokio::task::spawn_blocking` when called from async code.
//!
//! `CliApprovalGate` is the terminal fallback: it prompts the user via
//! `/dev/tty` (overridable by `NONO_APPROVAL_TTY` for tests) and supports
//! both a 2-button (`y`/`n`) and a 3-button (`a`/`r`/`d`) form. Until
//! `nono-approve` grows native support for "Allow always",
//! `NativeApprovalGate::approve_with_save_option` delegates to
//! `CliApprovalGate` so the persistent allowlist is reachable today.
//!
//! `AlwaysAllow` and `AlwaysDeny` are test doubles.

use std::io::{BufRead, BufReader, Write};

use tracing::warn;

/// Verdict for a 3-way approval prompt.
///
/// `AllowOnce` permits this single invocation but does not persist;
/// `AllowAlways` permits and is recorded in the per-user allowlist;
/// `Deny` rejects the invocation. Anything except `AllowAlways` MUST NOT
/// touch the allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalVerdict {
    AllowOnce,
    AllowAlways,
    Deny,
}

/// Synchronous gate that decides whether a command invocation is approved.
///
/// Implementations must be `Send + Sync` so they can be shared across tokio tasks.
pub trait ApprovalGate: Send + Sync {
    /// Returns `true` if the invocation is approved, `false` if denied.
    ///
    /// This method may block (e.g. waiting for user interaction). Callers from
    /// async contexts must use `tokio::task::spawn_blocking`.
    fn approve(&self, command: &str, args: &[String]) -> bool;

    /// 3-way approval: `AllowOnce` / `AllowAlways` / `Deny`.
    ///
    /// `reason` is a short human-readable string (e.g. an `argv_shape`
    /// mismatch summary) shown to the user.
    ///
    /// The default impl downcasts to `approve()` and returns
    /// `AllowOnce` on yes / `Deny` on no — gates that cannot offer a
    /// "remember" option will simply never persist. Production gates
    /// override this to expose the 3-button UX.
    fn approve_with_save_option(
        &self,
        command: &str,
        args: &[String],
        _reason: &str,
    ) -> ApprovalVerdict {
        if self.approve(command, args) {
            ApprovalVerdict::AllowOnce
        } else {
            ApprovalVerdict::Deny
        }
    }
}

/// Production gate: spawns `nono-approve` and interprets its exit code.
pub struct NativeApprovalGate;

impl ApprovalGate for NativeApprovalGate {
    fn approve(&self, command: &str, args: &[String]) -> bool {
        let binary = match find_approve_binary() {
            Some(p) => p,
            None => {
                warn!(
                    "nono-approve binary not found; denying command '{}'",
                    command
                );
                return false;
            }
        };

        let status = std::process::Command::new(&binary)
            .arg(command)
            .args(args)
            .status();

        match status {
            Ok(s) => s.success(),
            Err(e) => {
                warn!(
                    "nono-approve: failed to spawn '{}': {}; denying command '{}'",
                    binary.display(),
                    e,
                    command
                );
                false
            }
        }
    }

    /// Until `nono-approve` grows native 3-button support, fall back to the
    /// CLI prompt so the persistent-allowlist path is reachable today. The
    /// GUI 3-button dialog is a follow-up.
    fn approve_with_save_option(
        &self,
        command: &str,
        args: &[String],
        reason: &str,
    ) -> ApprovalVerdict {
        CliApprovalGate.approve_with_save_option(command, args, reason)
    }
}

/// Find the `nono-approve` binary.
///
/// Looks next to the running `nono` executable first, then falls back to PATH.
fn find_approve_binary() -> Option<std::path::PathBuf> {
    // 1. Look next to current exe
    if let Ok(exe) = std::env::current_exe() {
        let candidate = exe.with_file_name("nono-approve");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    // 2. Try PATH
    which::which("nono-approve").ok()
}

/// Terminal fallback gate: prompts via `/dev/tty` (or
/// `NONO_APPROVAL_TTY`).
///
/// Two prompt shapes:
/// - `approve()` shows `[y]es / [n]o:` (2 buttons).
/// - `approve_with_save_option()` shows
///   `[a]llow once / [r]emember / [d]eny:` (3 buttons).
///
/// The user types one character (case-insensitive) followed by newline.
/// Anything except the documented yes/allow choices is treated as a deny —
/// closing the tty (EOF) is therefore safe (denies).
pub struct CliApprovalGate;

impl CliApprovalGate {
    /// Read the path of the prompt tty. Defaults to `/dev/tty`; tests may
    /// override via `NONO_APPROVAL_TTY` to point at a fifo or pre-written
    /// file.
    fn tty_path() -> std::path::PathBuf {
        std::env::var_os("NONO_APPROVAL_TTY")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("/dev/tty"))
    }

    /// Print `prompt` to the tty, read a single line, lowercase-trim it,
    /// and return the first character (or empty string on EOF / error).
    ///
    /// We open the tty path twice: once for write (append mode, so a regular
    /// file used in tests preserves any pre-written input at offset 0) and
    /// once for read. For `/dev/tty` both go to the controlling terminal;
    /// for a test fifo both ends sit on the named pipe; for a regular test
    /// file the read sees the pre-written input, the write goes to the end.
    fn prompt(command: &str, args: &[String], reason: &str, choices: &str) -> String {
        let path = Self::tty_path();
        let writer = std::fs::OpenOptions::new()
            .append(true)
            .create(false)
            .open(&path);
        let mut writer = match writer {
            Ok(f) => f,
            Err(e) => {
                warn!(
                    "approval: failed to open tty {} for write: {}; denying",
                    path.display(),
                    e
                );
                return String::new();
            }
        };
        let _ = writeln!(writer);
        let _ = writeln!(writer, "  Approval required for: {}", command);
        let _ = writeln!(writer, "  Argv: {}", args.join(" "));
        if !reason.is_empty() {
            let _ = writeln!(writer, "  Reason: {}", reason);
        }
        let _ = write!(writer, "  {}: ", choices);
        let _ = writer.flush();

        let read_handle = match std::fs::OpenOptions::new().read(true).open(&path) {
            Ok(f) => f,
            Err(e) => {
                warn!(
                    "approval: failed to open tty {} for read: {}; denying",
                    path.display(),
                    e
                );
                return String::new();
            }
        };
        let mut reader = BufReader::new(read_handle);
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => String::new(),
            Ok(_) => line.trim().to_lowercase(),
            Err(e) => {
                warn!("approval: tty read error: {}; denying", e);
                String::new()
            }
        }
    }
}

impl ApprovalGate for CliApprovalGate {
    fn approve(&self, command: &str, args: &[String]) -> bool {
        let resp = Self::prompt(command, args, "", "[y]es / [n]o");
        matches!(resp.chars().next(), Some('y'))
    }

    fn approve_with_save_option(
        &self,
        command: &str,
        args: &[String],
        reason: &str,
    ) -> ApprovalVerdict {
        let resp = Self::prompt(
            command,
            args,
            reason,
            "[a]llow once / [r]emember / [d]eny",
        );
        match resp.chars().next() {
            Some('a') => ApprovalVerdict::AllowOnce,
            Some('r') => ApprovalVerdict::AllowAlways,
            _ => ApprovalVerdict::Deny,
        }
    }
}

/// Test double: always approves.
#[cfg(test)]
pub struct AlwaysAllow;

#[cfg(test)]
impl ApprovalGate for AlwaysAllow {
    fn approve(&self, _command: &str, _args: &[String]) -> bool {
        true
    }
}

/// Test double: always returns `AllowOnce` from the 3-way prompt.
#[cfg(test)]
pub struct AlwaysAllowOnce;

#[cfg(test)]
impl ApprovalGate for AlwaysAllowOnce {
    fn approve(&self, _command: &str, _args: &[String]) -> bool {
        true
    }
    fn approve_with_save_option(
        &self,
        _command: &str,
        _args: &[String],
        _reason: &str,
    ) -> ApprovalVerdict {
        ApprovalVerdict::AllowOnce
    }
}

/// Test double: always returns `AllowAlways` from the 3-way prompt.
#[cfg(test)]
pub struct AlwaysAllowAlways;

#[cfg(test)]
impl ApprovalGate for AlwaysAllowAlways {
    fn approve(&self, _command: &str, _args: &[String]) -> bool {
        true
    }
    fn approve_with_save_option(
        &self,
        _command: &str,
        _args: &[String],
        _reason: &str,
    ) -> ApprovalVerdict {
        ApprovalVerdict::AllowAlways
    }
}

/// Test double: always denies.
#[cfg(test)]
pub struct AlwaysDeny;

#[cfg(test)]
impl ApprovalGate for AlwaysDeny {
    fn approve(&self, _command: &str, _args: &[String]) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::{EnvVarGuard, ENV_LOCK};
    use tempfile::tempdir;

    /// Pre-write `input` to a regular file in `dir` and return the path.
    ///
    /// `CliApprovalGate::prompt` opens the path twice — once with
    /// `append(true)` (writes go to the end) and once read-only (reads
    /// start at byte 0). With a pre-written file, the read sees the input
    /// while the write harmlessly grows the tail. This avoids the fifo
    /// timing fragility (writer thread vs. reader open ordering).
    fn input_file(dir: &std::path::Path, name: &str, input: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, input).unwrap();
        path
    }

    #[test]
    fn cli_approval_allow_once() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempdir().unwrap();
        let p = input_file(dir.path(), "tty.input", "a\n");
        let _env = EnvVarGuard::set_all(&[("NONO_APPROVAL_TTY", p.to_str().unwrap())]);
        let v = CliApprovalGate.approve_with_save_option(
            "security",
            &["find-generic-password".to_string()],
            "test",
        );
        assert_eq!(v, ApprovalVerdict::AllowOnce);
    }

    #[test]
    fn cli_approval_allow_always() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempdir().unwrap();
        let p = input_file(dir.path(), "tty.input", "r\n");
        let _env = EnvVarGuard::set_all(&[("NONO_APPROVAL_TTY", p.to_str().unwrap())]);
        let v = CliApprovalGate.approve_with_save_option(
            "security",
            &["find-generic-password".to_string()],
            "test",
        );
        assert_eq!(v, ApprovalVerdict::AllowAlways);
    }

    #[test]
    fn cli_approval_deny() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempdir().unwrap();
        let p = input_file(dir.path(), "tty.input", "d\n");
        let _env = EnvVarGuard::set_all(&[("NONO_APPROVAL_TTY", p.to_str().unwrap())]);
        let v = CliApprovalGate.approve_with_save_option(
            "security",
            &["find-generic-password".to_string()],
            "test",
        );
        assert_eq!(v, ApprovalVerdict::Deny);
    }

    #[test]
    fn cli_approval_eof_denies() {
        // Empty file: read_line returns Ok(0) immediately.
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempdir().unwrap();
        let p = input_file(dir.path(), "empty.input", "");
        let _env = EnvVarGuard::set_all(&[("NONO_APPROVAL_TTY", p.to_str().unwrap())]);
        let v = CliApprovalGate.approve_with_save_option(
            "security",
            &["find-generic-password".to_string()],
            "test",
        );
        assert_eq!(v, ApprovalVerdict::Deny);
    }
}
