//! BPF-LSM filesystem deny-within-allow — end-to-end integration tests.
//!
//! Each test spawns a real `nono run` session against a profile that:
//!   - Opts into parent-of-protected via `allow_parent_of_protected: true`,
//!   - Grants the parent dir (so the agent can read non-protected children),
//!   - Lists a path inside the parent under `policy.add_deny_access`.
//!
//! The expectation is that BPF-LSM kernel hooks return `-EACCES` for any
//! file_open / inode_unlink / inode_rmdir / inode_rename / inode_create /
//! inode_mkdir / inode_symlink / inode_link / inode_setattr that targets a
//! path inside a protected subtree, while non-protected children of the
//! parent remain freely accessible. This is the Linux equivalent of macOS
//! Seatbelt's `(deny file-write* ...)` rules.
//!
//! Two protection sources are exercised:
//!   1. nono's own state root (`~/.nono`) — populated automatically by the
//!      BPF userspace loader.
//!   2. profile `policy.add_deny_access` paths — populated alongside (1).
//!
//! All tests skip cleanly when the cargo-built `nono` binary lacks the
//! `cap_bpf,cap_sys_admin,cap_dac_override+ep` file caps. Run via
//! `make test-integration`.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

// -------------------------------------------------------------------------
// Skip helpers (mirrors bpf_lsm_integration.rs)
// -------------------------------------------------------------------------

fn nono_binary() -> PathBuf {
    ensure_nono_shim_built();
    PathBuf::from(env!("CARGO_BIN_EXE_nono"))
}

fn binary_has_mediation_caps() -> bool {
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(|| {
        let nono = nono_binary();
        let Ok(out) = Command::new("getcap").arg(&nono).output() else {
            return false;
        };
        let listing = String::from_utf8_lossy(&out.stdout);
        listing.contains("cap_bpf")
            && listing.contains("cap_sys_admin")
            && listing.contains("cap_dac_override")
    })
}

macro_rules! skip_unless_mediation_capable {
    () => {
        if !binary_has_mediation_caps() {
            eprintln!(
                "skipping: {} lacks BPF-LSM caps. Run via `make test-integration`.",
                nono_binary().display(),
            );
            return;
        }
    };
}

fn ensure_nono_shim_built() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let nono_exe = PathBuf::from(env!("CARGO_BIN_EXE_nono"));
        let target_dir = nono_exe.parent().expect("nono exe has parent");
        let shim = target_dir.join("nono-shim");
        if shim.is_file() {
            return;
        }
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace = manifest
            .parent()
            .and_then(Path::parent)
            .unwrap_or(&manifest);
        let status = Command::new("cargo")
            .arg("build")
            .arg("-p")
            .arg("nono-shim")
            .arg("--bin")
            .arg("nono-shim")
            .current_dir(workspace)
            .status()
            .expect("spawn cargo to build nono-shim");
        assert!(status.success(), "cargo build -p nono-shim failed");
        assert!(shim.is_file(), "nono-shim missing at {}", shim.display());
    });
}

// -------------------------------------------------------------------------
// Harness
// -------------------------------------------------------------------------

/// One per-test fixture. Layout:
///
/// ```text
/// $TMP/
///   home/                       ← $HOME inside the session
///     .nono/                    ← session audit dir; protected by default
///     workdir/                  ← --workdir; granted in profile
///       allowed.txt             ← non-protected file under granted parent
///     protected/                ← listed in profile.policy.add_deny_access
///       secret.txt              ← protected file (pre-existing)
///   profile.json
/// ```
///
/// The session profile grants `home` (parent of `.nono` and `protected`)
/// with `allow_parent_of_protected: true`, and lists `home/protected` in
/// `policy.add_deny_access`. Pre-flight admission relies on Phase 2.4
/// dropping the `target_os = "macos"` gate on Linux; runtime enforcement
/// relies on Phase 2.3 populating the BPF protected_roots map; wiring
/// between them is Phase 2.5.
struct ProtectedHarness {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    workdir: PathBuf,
    protected_dir: PathBuf,
    profile: PathBuf,
}

impl ProtectedHarness {
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let home = tmp.path().join("home");
        let workdir = home.join("workdir");
        let protected_dir = home.join("protected");
        let nono_dir = home.join(".nono"); // session audit dir
        std::fs::create_dir_all(&workdir).expect("create workdir");
        std::fs::create_dir_all(&protected_dir).expect("create protected");
        std::fs::create_dir_all(&nono_dir).expect("create nono dir");

        // Pre-existing files used by individual tests.
        std::fs::write(workdir.join("allowed.txt"), b"OK")
            .expect("create workdir/allowed.txt");
        std::fs::write(protected_dir.join("secret.txt"), b"SECRET")
            .expect("create protected/secret.txt");
        std::fs::write(nono_dir.join("state.db"), b"NONO_STATE")
            .expect("create .nono/state.db");

        let profile = tmp.path().join("profile.json");
        std::fs::write(&profile, profile_json(&home, &protected_dir))
            .expect("write profile");

        Self {
            _tmp: tmp,
            home,
            workdir,
            protected_dir,
            profile,
        }
    }

    fn run_nono(&self, args: &[&str]) -> NonoOutput {
        let nono = nono_binary();
        let mut cmd = Command::new(&nono);
        cmd.arg("run")
            .arg("--silent")
            .arg("--profile")
            .arg(&self.profile)
            .arg("--workdir")
            .arg(&self.workdir)
            .arg("--");
        for a in args {
            cmd.arg(a);
        }
        cmd.env_clear();
        cmd.env("HOME", &self.home);
        cmd.env(
            "PATH",
            std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into()),
        );
        cmd.env("TERM", "dumb");
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        let out = cmd.output().expect("spawn nono");
        NonoOutput {
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            exit_code: out.status.code().unwrap_or(-1),
        }
    }

    fn read_audit_events(&self) -> Vec<serde_json::Value> {
        let path = self.home.join(".nono").join("sessions").join("audit.jsonl");
        let Ok(content) = std::fs::read_to_string(&path) else {
            return Vec::new();
        };
        content
            .lines()
            .filter(|l| !l.is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    /// Poll for an audit event with the given `reason` field for up to ~1s.
    fn wait_for_audit_reason(&self, reason: &str) -> Option<serde_json::Value> {
        for _ in 0..20 {
            for event in self.read_audit_events() {
                if event.get("reason").and_then(|r| r.as_str()) == Some(reason) {
                    return Some(event);
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        None
    }
}

struct NonoOutput {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

impl NonoOutput {
    fn combined(&self) -> String {
        format!(
            "exit={} stdout={:?} stderr={:?}",
            self.exit_code, self.stdout, self.stderr
        )
    }
}

fn profile_json(home: &Path, protected: &Path) -> String {
    let home_s = home.display().to_string().replace('\\', "\\\\");
    let prot_s = protected.display().to_string().replace('\\', "\\\\");
    // Grant home (parent of both .nono and protected) with the opt-in;
    // also grant /usr,/bin,/lib for the spawned shell + coreutils.
    //
    // No `exclude_groups` needed: the default deny groups (which are
    // marked required and can't be excluded) get routed through the
    // BPF-LSM `protected_roots` map alongside `add_deny_access`. The
    // `validate_deny_overlaps` pre-flight check is no-op when BPF-LSM
    // is available, so a broad `home` grant overlapping group denies
    // is legitimate — the kernel enforces.
    format!(
        r#"{{
  "meta": {{ "name": "bpf-lsm-protected-subtree", "version": "1.0" }},
  "allow_parent_of_protected": true,
  "policy": {{
    "add_deny_access": ["{prot_s}"]
  }},
  "filesystem": {{
    "allow": ["{home_s}", "/usr", "/bin", "/lib", "/lib64", "/etc"]
  }},
  "network": {{ "block": false }},
  "workdir": {{ "access": "readwrite" }}
}}"#
    )
}

// =========================================================================
// Tests — file_open coverage
// =========================================================================

#[test]
fn read_protected_file_denied() {
    skip_unless_mediation_capable!();
    let h = ProtectedHarness::new();
    let secret = h.protected_dir.join("secret.txt").display().to_string();
    let out = h.run_nono(&["cat", &secret]);
    assert!(
        !out.stdout.contains("SECRET"),
        "protected file content leaked; {}",
        out.combined()
    );
    assert!(
        out.exit_code != 0,
        "cat of protected file should fail; {}",
        out.combined()
    );
    assert!(
        h.wait_for_audit_reason("protected_open_deny").is_some(),
        "expected protected_open_deny audit event"
    );
}

#[test]
fn write_protected_file_denied() {
    skip_unless_mediation_capable!();
    let h = ProtectedHarness::new();
    let target = h.protected_dir.join("secret.txt").display().to_string();
    let out = h.run_nono(&["sh", "-c", &format!("echo HACKED > {target}")]);
    let body = std::fs::read_to_string(&target).unwrap_or_default();
    assert_eq!(
        body, "SECRET",
        "protected file was overwritten despite deny; got {body:?}; {}",
        out.combined()
    );
    assert!(out.exit_code != 0, "{}", out.combined());
}

#[test]
fn mmap_protected_file_denied() {
    skip_unless_mediation_capable!();
    let h = ProtectedHarness::new();
    // python's mmap goes through the open() path, which file_open hooks.
    let secret = h.protected_dir.join("secret.txt").display().to_string();
    let script = format!(
        "import mmap, os, sys; \
         fd = os.open('{secret}', os.O_RDONLY); \
         mmap.mmap(fd, 0, prot=mmap.PROT_READ); \
         print('LEAK')"
    );
    let out = h.run_nono(&["python3", "-c", &script]);
    assert!(
        !out.stdout.contains("LEAK"),
        "mmap of protected file succeeded; {}",
        out.combined()
    );
    assert!(out.exit_code != 0, "{}", out.combined());
}

// =========================================================================
// Tests — inode_unlink / inode_rmdir / inode_rename / inode_create
// =========================================================================

#[test]
fn unlink_protected_child_denied() {
    skip_unless_mediation_capable!();
    let h = ProtectedHarness::new();
    // Use python3 so we hit the kernel unlink syscall directly. `rm`
    // is in nono's `dangerous_commands` startup-blocked list and would
    // never reach the BPF hook.
    //
    // Note on layered enforcement: Landlock's default access set for a
    // filesystem.allow grant does NOT include `REMOVE_FILE`, so the
    // unlink is denied at the Landlock layer BEFORE BPF-LSM's
    // inode_unlink hook fires. This test therefore only asserts that
    // the deny happens (file unchanged + non-zero exit); the BPF
    // audit-event side is exercised by the other write-deny tests
    // (file_open + inode_create + inode_rename) where Landlock grants
    // the access and BPF-LSM is the one returning EACCES.
    let target = h.protected_dir.join("secret.txt").display().to_string();
    let script = format!(
        "import os, sys; \
         try: os.unlink('{target}')\n\
         except OSError as e: sys.exit(13)\n\
         else: sys.exit(0)"
    );
    let out = h.run_nono(&["python3", "-c", &script]);
    assert!(
        h.protected_dir.join("secret.txt").exists(),
        "protected file removed despite deny; {}",
        out.combined()
    );
    assert!(out.exit_code != 0, "{}", out.combined());
}

#[test]
fn rmdir_inside_protected_denied() {
    skip_unless_mediation_capable!();
    let h = ProtectedHarness::new();
    let dir = h.protected_dir.join("subdir");
    std::fs::create_dir(&dir).expect("create subdir");
    let target = dir.display().to_string();
    let out = h.run_nono(&["rmdir", &target]);
    assert!(
        dir.exists(),
        "protected subdir was rmdir'd despite deny; {}",
        out.combined()
    );
    assert!(out.exit_code != 0, "{}", out.combined());
}

#[test]
fn rename_into_protected_denied() {
    skip_unless_mediation_capable!();
    let h = ProtectedHarness::new();
    let src = h.workdir.join("allowed.txt").display().to_string();
    let dst = h
        .protected_dir
        .join("smuggled.txt")
        .display()
        .to_string();
    let out = h.run_nono(&["mv", &src, &dst]);
    assert!(
        h.workdir.join("allowed.txt").exists(),
        "source moved despite deny; {}",
        out.combined()
    );
    assert!(
        !h.protected_dir.join("smuggled.txt").exists(),
        "target appeared in protected dir; {}",
        out.combined()
    );
    assert!(out.exit_code != 0, "{}", out.combined());
}

#[test]
fn rename_out_of_protected_denied() {
    skip_unless_mediation_capable!();
    let h = ProtectedHarness::new();
    let src = h.protected_dir.join("secret.txt").display().to_string();
    let dst = h.workdir.join("exfil.txt").display().to_string();
    let out = h.run_nono(&["mv", &src, &dst]);
    assert!(
        !h.workdir.join("exfil.txt").exists(),
        "secret file moved out of protected dir; {}",
        out.combined()
    );
    assert!(out.exit_code != 0, "{}", out.combined());
}

#[test]
fn create_in_protected_denied() {
    skip_unless_mediation_capable!();
    let h = ProtectedHarness::new();
    let target = h
        .protected_dir
        .join("new_file.txt")
        .display()
        .to_string();
    let out = h.run_nono(&["sh", "-c", &format!("echo data > {target}")]);
    assert!(
        !h.protected_dir.join("new_file.txt").exists(),
        "new file created in protected dir; {}",
        out.combined()
    );
    assert!(out.exit_code != 0, "{}", out.combined());
}

// =========================================================================
// Tests — bind-mount handling
// =========================================================================

/// When `~/.nono/sessions/` is bind-mounted from outside the protected
/// subtree (shadowfax's deployment shape), the dentry parent walk would
/// reach the bind-mount source's tree, not the agent's `~/.nono`. The
/// userspace loader compensates by enumerating bind-mount sources mounted
/// under each protected root and inserting their `(dev, ino)` into the
/// protected_roots map. This test sets up that scenario and verifies the
/// access is still denied.
#[test]
fn read_via_bind_mount_denied() {
    skip_unless_mediation_capable!();
    // Bind mounts require CAP_SYS_ADMIN; the binary already needs it for
    // the broker. Setting up the bind mount itself happens inside this
    // test process and needs the same cap on the test runner.
    if !test_process_has_cap_sys_admin() {
        eprintln!("skipping read_via_bind_mount_denied: needs CAP_SYS_ADMIN on the test process");
        return;
    }
    let h = ProtectedHarness::new();
    let bind_src = h._tmp.path().join("bind_src");
    std::fs::create_dir_all(&bind_src).expect("create bind source");
    std::fs::write(bind_src.join("via_bind.txt"), b"BIND_LEAK")
        .expect("create bind file");

    // Bind-mount over a subdir of the protected root.
    let bind_target = h.protected_dir.join("bound");
    std::fs::create_dir_all(&bind_target).expect("create bind target");
    let status = Command::new("mount")
        .arg("--bind")
        .arg(&bind_src)
        .arg(&bind_target)
        .status()
        .expect("spawn mount");
    assert!(status.success(), "bind mount failed");

    // Read a file inside the bind-mount through the protected path.
    let target = bind_target.join("via_bind.txt").display().to_string();
    let out = h.run_nono(&["cat", &target]);

    // Cleanup.
    let _ = Command::new("umount").arg(&bind_target).status();

    assert!(
        !out.stdout.contains("BIND_LEAK"),
        "bind-mount leak: protected file content reached agent; {}",
        out.combined()
    );
    assert!(out.exit_code != 0, "{}", out.combined());
}

fn test_process_has_cap_sys_admin() -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("CapEff:\t") {
            let bits = u64::from_str_radix(rest.trim(), 16).unwrap_or(0);
            // CAP_SYS_ADMIN = 21
            return (bits >> 21) & 1 == 1;
        }
    }
    false
}

// =========================================================================
// Tests — regression / negative cases
// =========================================================================

#[test]
fn unrelated_path_in_session_unaffected() {
    skip_unless_mediation_capable!();
    let h = ProtectedHarness::new();
    let allowed = h.workdir.join("allowed.txt").display().to_string();
    let out = h.run_nono(&["cat", &allowed]);
    assert!(
        out.stdout.contains("OK"),
        "non-protected file read unexpectedly failed; {}",
        out.combined()
    );
    assert_eq!(out.exit_code, 0, "{}", out.combined());
}

#[test]
fn nono_state_root_denied_inside_session() {
    skip_unless_mediation_capable!();
    let h = ProtectedHarness::new();
    // ~/.nono/state.db must be denied even though it's inside the granted
    // home parent. This is the WRK-2585 root cause case: parent grant +
    // BPF-LSM enforces ~/.nono.
    let state = h.home.join(".nono/state.db").display().to_string();
    let out = h.run_nono(&["cat", &state]);
    assert!(
        !out.stdout.contains("NONO_STATE"),
        ".nono/state.db leaked; {}",
        out.combined()
    );
    assert!(out.exit_code != 0, "{}", out.combined());
}

#[test]
fn session_starts_with_parent_grant_and_opt_in() {
    skip_unless_mediation_capable!();
    let h = ProtectedHarness::new();
    // Smoke: just running `true` should succeed end-to-end with a profile
    // that grants $HOME (parent of $HOME/.nono) and opts into
    // allow_parent_of_protected. Currently red on Linux because the
    // pre-flight rejects the parent grant; Phase 2.4 lifts the gate.
    let out = h.run_nono(&["true"]);
    assert_eq!(
        out.exit_code, 0,
        "session should start cleanly with allow_parent_of_protected; {}",
        out.combined()
    );
}
