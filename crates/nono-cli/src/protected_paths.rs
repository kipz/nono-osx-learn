//! Protection for nono's own state paths.
//!
//! These checks enforce a hard fail if initial sandbox capabilities overlap
//! with internal CLI state roots (currently `~/.nono`).

use nono::{CapabilitySet, NonoError, Result};
use std::path::{Path, PathBuf};

/// Resolved internal state roots that must not be accessible by the sandboxed child.
///
/// This is intentionally modeled as a list so configured/custom roots can be
/// added later without changing call sites.
pub struct ProtectedRoots {
    roots: Vec<PathBuf>,
}

impl ProtectedRoots {
    /// Build protected roots from current defaults.
    ///
    /// Today this protects the full `~/.nono` subtree.
    pub fn from_defaults() -> Result<Self> {
        let home = dirs::home_dir().ok_or(NonoError::HomeNotFound)?;
        let state_root = resolve_path(&home.join(".nono"));
        Ok(Self {
            roots: vec![state_root],
        })
    }

    /// Return a slice of protected root paths.
    pub fn as_paths(&self) -> &[PathBuf] {
        &self.roots
    }
}

/// Validate that no filesystem capability overlaps any protected root.
///
/// Overlap rules:
/// - Any file capability inside a protected root is rejected.
/// - Any directory capability inside a protected root is rejected.
/// - Any directory capability that is a parent of a protected root is rejected
///   (e.g. granting `~` would cover `~/.nono`).
pub fn validate_caps_against_protected_roots(
    caps: &CapabilitySet,
    protected_roots: &[PathBuf],
    allow_parent_of_protected: bool,
) -> Result<()> {
    for cap in caps.fs_capabilities() {
        validate_requested_path_against_protected_roots(
            &cap.resolved,
            cap.is_file,
            &cap.source.to_string(),
            protected_roots,
            allow_parent_of_protected,
        )?;
    }

    Ok(())
}

/// Validate an intended grant path before capability construction.
///
/// This catches protected-root overlaps even when requested paths don't exist
/// yet and are later skipped during capability creation.
///
/// `parent_of_protected` is admitted on both platforms when
/// `allow_parent_of_protected` is true. The OS sandbox layer enforces the
/// subtree at runtime: Seatbelt deny rules emitted via
/// [`emit_protected_root_deny_rules`] on macOS, BPF-LSM `protected_roots`
/// hooks (populated from [`bpf_lsm_protected_roots_for_session`]) on Linux.
/// Without the opt-in the grant is rejected so a profile cannot
/// accidentally expose nono's state directory.
pub fn validate_requested_path_against_protected_roots(
    path: &Path,
    is_file: bool,
    source: &str,
    protected_roots: &[PathBuf],
    allow_parent_of_protected: bool,
) -> Result<()> {
    let requested_path = resolve_path(path);
    let resolved_roots: Vec<PathBuf> = protected_roots.iter().map(|p| resolve_path(p)).collect();

    for protected_root in &resolved_roots {
        let inside_protected = requested_path.starts_with(protected_root);
        let parent_of_protected = !is_file && protected_root.starts_with(&requested_path);

        // inside_protected is always a hard error on all platforms
        if inside_protected {
            return Err(NonoError::SandboxInit(format!(
                "Refusing to grant '{}' (source: {}) because it overlaps protected nono state root '{}'.",
                requested_path.display(),
                source,
                protected_root.display(),
            )));
        }

        // parent_of_protected: with the opt-in, both platforms admit the
        // grant and rely on the OS sandbox layer to enforce the protected
        // subtree at runtime — Seatbelt deny rules on macOS, BPF-LSM hooks
        // on Linux (`protected_roots` map + dentry walker). Without the
        // opt-in we still hard-reject so a profile cannot accidentally
        // expose nono's state.
        if parent_of_protected && !allow_parent_of_protected {
            return Err(NonoError::SandboxInit(format!(
                "Refusing to grant '{}' (source: {}) because it overlaps protected nono state root '{}'.",
                requested_path.display(),
                source,
                protected_root.display(),
            )));
        }
    }

    Ok(())
}

/// Return the protected root overlapped by a requested path, if any.
///
/// Only `inside_protected` is flagged on either platform, because by the
/// time this runtime check runs the OS sandbox layer (Seatbelt deny rules
/// on macOS, BPF-LSM `protected_roots` on Linux) is already enforcing the
/// subtree. Parent grants are admitted at pre-flight by
/// [`validate_requested_path_against_protected_roots`] only when the
/// profile opted in via `allow_parent_of_protected`; if it did not, the
/// pre-flight already rejected and we never get here.
///
/// Unlike [`validate_requested_path_against_protected_roots`], this function
/// does **not** take an `allow_parent_of_protected` flag — at runtime there
/// is no parent-grant case to gate.
#[must_use]
pub fn overlapping_protected_root(
    path: &Path,
    is_file: bool,
    protected_roots: &[PathBuf],
) -> Option<PathBuf> {
    let requested_path = resolve_path(path);
    let resolved_roots: Vec<PathBuf> = protected_roots.iter().map(|p| resolve_path(p)).collect();

    let _ = is_file; // is_file no longer informs the runtime decision.

    for protected_root in &resolved_roots {
        let inside_protected = requested_path.starts_with(protected_root);
        if inside_protected {
            return Some(protected_root.clone());
        }
    }

    None
}

/// Emit Seatbelt deny rules for all protected roots.
///
/// On macOS, this adds `(deny file-read-data ...)` and `(deny file-write* ...)`
/// platform rules for each protected root, preventing the sandboxed child from
/// accessing `~/.nono` even when a parent directory is granted.
///
/// On non-macOS, this is a no-op — Landlock does not support deny-within-allow,
/// so the pre-flight validation rejects parent grants instead.
pub(crate) fn emit_protected_root_deny_rules(
    protected_roots: &[PathBuf],
    caps: &mut CapabilitySet,
) -> Result<()> {
    if !cfg!(target_os = "macos") {
        return Ok(());
    }

    for root in protected_roots {
        let resolved = resolve_path(root);
        emit_deny_rules_for_path(&resolved, caps)?;

        // Also emit for the canonical path if it differs (important on macOS
        // where paths like /var resolve to /private/var).
        if let Ok(canonical) = resolved.canonicalize() {
            if canonical != resolved {
                emit_deny_rules_for_path(&canonical, caps)?;
            }
        }
    }

    Ok(())
}

/// Emit Seatbelt deny rules for a single path.
#[cfg(target_os = "macos")]
fn emit_deny_rules_for_path(path: &Path, caps: &mut CapabilitySet) -> Result<()> {
    let escaped = crate::policy::escape_seatbelt_path(crate::policy::path_to_utf8(path)?)?;
    let filter = format!("subpath \"{}\"", escaped);
    caps.add_platform_rule(format!("(allow file-read-metadata ({}))", filter))?;
    caps.add_platform_rule(format!("(deny file-read-data ({}))", filter))?;
    caps.add_platform_rule(format!("(deny file-write* ({}))", filter))?;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn emit_deny_rules_for_path(_path: &Path, _caps: &mut CapabilitySet) -> Result<()> {
    Ok(())
}

/// Compute the set of protected-root paths to load into the BPF-LSM
/// `protected_roots` map for a session. Linux-only at runtime — on macOS
/// returns empty because Seatbelt deny rules emitted via
/// [`emit_protected_root_deny_rules`] and `add_deny_access_rules` cover
/// the same ground.
///
/// Inputs (all merged into a single deduped list):
///   - `state_roots`: the protected state-root set (today: `~/.nono`) as
///     produced by `ProtectedRoots::from_defaults`.
///   - `add_deny_access`: the profile's `policy.add_deny_access` entries
///     (raw strings, possibly containing `$VAR` placeholders that have
///     already been expanded by the profile loader).
///   - `policy_group_denies`: deny paths inherited from policy groups
///     (`deny_credentials`, `deny_keychains_*`, etc.) as resolved by
///     `policy::resolve_deny_paths_for_groups`. These are required-by-
///     default safety denies; on macOS Seatbelt enforces them via the
///     same `add_deny_access_rules` machinery, on Linux pre-BPF-LSM the
///     `validate_deny_overlaps` check rejected any session whose allow
///     set covered them. Routing them through BPF-LSM lets a profile
///     legitimately grant a broad parent (e.g. `$HOME`) without losing
///     these baseline denies.
///
/// Output: the union of all three sets, each path resolved via
/// [`resolve_path`] (canonicalize where possible, fall back to the
/// longest existing ancestor). Duplicates are removed. Bind-mount sources
/// mounted at-or-under any returned path are NOT enumerated here — that
/// lives in `nono::sandbox::bpf_lsm`, where `/proc/self/mountinfo` is
/// scanned just before BPF map population.
///
/// Paths that fail to resolve at all (no canonical form, no extant
/// ancestor) are still included, so a not-yet-created path the agent
/// might later mkdir into still gets denied (the kernel walker matches
/// by `(dev, ino)`, which only exists once the path does — but inserting
/// the resolved path is harmless).
#[must_use]
pub fn bpf_lsm_protected_roots_for_session(
    state_roots: &[PathBuf],
    add_deny_access: &[String],
    policy_group_denies: &[PathBuf],
) -> Vec<PathBuf> {
    if cfg!(target_os = "macos") {
        return Vec::new();
    }

    let mut out: Vec<PathBuf> =
        Vec::with_capacity(state_roots.len() + add_deny_access.len() + policy_group_denies.len());
    let mut push_unique = |path: PathBuf| {
        let resolved = resolve_path(&path);
        if !out.iter().any(|p| p == &resolved) {
            out.push(resolved);
        }
    };

    for root in state_roots {
        push_unique(root.clone());
    }
    for entry in add_deny_access {
        // `add_deny_access` entries arrive as raw strings from the
        // profile JSON; placeholders like `$HOME/...` and `~/...`
        // are NOT expanded by the profile loader (the existing
        // `add_deny_access_rules` path expands them per-call). Use
        // the same `expand_path` helper here so the BPF map is
        // populated with concrete paths the kernel can stat.
        match crate::policy::expand_path(entry) {
            Ok(p) => push_unique(p),
            Err(_) => push_unique(PathBuf::from(entry)),
        }
    }
    for path in policy_group_denies {
        push_unique(path.clone());
    }
    out
}

/// Resolve path by canonicalizing the full path, or canonicalizing the longest
/// existing ancestor and appending remaining components.
fn resolve_path(path: &Path) -> PathBuf {
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }

    let mut remaining = Vec::new();
    let mut current = path.to_path_buf();
    loop {
        if let Ok(canonical) = current.canonicalize() {
            let mut result = canonical;
            for component in remaining.iter().rev() {
                result = result.join(component);
            }
            return result;
        }

        match current.file_name() {
            Some(name) => {
                remaining.push(name.to_os_string());
                if !current.pop() {
                    break;
                }
            }
            None => break,
        }
    }

    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nono::{AccessMode, CapabilitySet, FsCapability};
    use tempfile::TempDir;

    #[test]
    fn parent_directory_capability_blocked_without_opt_in() {
        let tmp = TempDir::new().expect("tmpdir");
        let parent = tmp.path().to_path_buf();
        let protected = parent.join(".nono");

        let mut caps = CapabilitySet::new();
        let cap = FsCapability::new_dir(&parent, AccessMode::ReadWrite).expect("dir cap");
        caps.add_fs(cap);

        // Without opt-in, parent grant is always rejected
        let err =
            validate_caps_against_protected_roots(&caps, &[protected], false).expect_err("blocked");
        assert!(
            err.to_string()
                .contains("overlaps protected nono state root"),
            "unexpected error: {err}",
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parent_directory_capability_allowed_with_opt_in_on_macos() {
        let tmp = TempDir::new().expect("tmpdir");
        let parent = tmp.path().to_path_buf();
        let protected = parent.join(".nono");

        let mut caps = CapabilitySet::new();
        let cap = FsCapability::new_dir(&parent, AccessMode::ReadWrite).expect("dir cap");
        caps.add_fs(cap);

        // With opt-in on macOS, parent grant is allowed (Seatbelt deny rules protect the root)
        validate_caps_against_protected_roots(&caps, &[protected], true)
            .expect("allowed on macOS with opt-in");
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn parent_directory_capability_allowed_with_opt_in_on_linux() {
        let tmp = TempDir::new().expect("tmpdir");
        let parent = tmp.path().to_path_buf();
        let protected = parent.join(".nono");

        let mut caps = CapabilitySet::new();
        let cap = FsCapability::new_dir(&parent, AccessMode::ReadWrite).expect("dir cap");
        caps.add_fs(cap);

        // With opt-in on Linux, parent grant is allowed because BPF-LSM
        // enforces a deny over `~/.nono` at runtime (matching macOS Seatbelt
        // behavior). Pre-flight admits the parent grant; the kernel hooks
        // emit -EACCES when the agent actually reaches into the subtree.
        validate_caps_against_protected_roots(&caps, &[protected], true)
            .expect("allowed on Linux with opt-in (BPF-LSM enforces)");
    }

    #[test]
    fn inside_protected_root_always_blocked() {
        let tmp = TempDir::new().expect("tmpdir");
        let protected = tmp.path().join(".nono");
        std::fs::create_dir_all(&protected).expect("mkdir");
        let inside = protected.join("state.db");
        std::fs::write(&inside, b"").expect("create file");

        // File inside protected root — blocked on all platforms
        let err = validate_requested_path_against_protected_roots(
            &inside,
            true,
            "test",
            std::slice::from_ref(&protected),
            false,
        )
        .expect_err("blocked");
        assert!(
            err.to_string()
                .contains("overlaps protected nono state root"),
            "unexpected error: {err}",
        );

        // Directory inside protected root — blocked on all platforms
        let subdir = protected.join("rollbacks");
        std::fs::create_dir_all(&subdir).expect("mkdir");
        let err = validate_requested_path_against_protected_roots(
            &subdir,
            false,
            "test",
            std::slice::from_ref(&protected),
            false,
        )
        .expect_err("blocked");
        assert!(
            err.to_string()
                .contains("overlaps protected nono state root"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn blocks_child_directory_capability() {
        let tmp = TempDir::new().expect("tmpdir");
        let protected = tmp.path().join(".nono");
        let child = protected.join("rollbacks");
        std::fs::create_dir_all(&child).expect("mkdir");

        let mut caps = CapabilitySet::new();
        let cap = FsCapability::new_dir(&child, AccessMode::ReadWrite).expect("dir cap");
        caps.add_fs(cap);

        validate_caps_against_protected_roots(&caps, &[protected], false).expect_err("blocked");
    }

    #[test]
    fn allows_unrelated_capability() {
        let tmp = TempDir::new().expect("tmpdir");
        let protected = tmp.path().join(".nono");
        let workspace = tmp.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("mkdir");

        let mut caps = CapabilitySet::new();
        let cap = FsCapability::new_dir(&workspace, AccessMode::ReadWrite).expect("dir cap");
        caps.add_fs(cap);

        validate_caps_against_protected_roots(&caps, &[protected], false).expect("allowed");
    }

    #[test]
    fn requested_path_blocks_nonexistent_child_under_protected_root() {
        let tmp = TempDir::new().expect("tmpdir");
        let protected = tmp.path().join(".nono");
        std::fs::create_dir_all(&protected).expect("mkdir");
        let child = protected.join("rollbacks").join("future-session");

        let err = validate_requested_path_against_protected_roots(
            &child,
            false,
            "CLI",
            &[protected],
            false,
        )
        .expect_err("blocked");
        assert!(
            err.to_string()
                .contains("overlaps protected nono state root"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn overlapping_protected_root_reports_match() {
        let tmp = TempDir::new().expect("tmpdir");
        let protected = tmp.path().join(".nono");
        std::fs::create_dir_all(&protected).expect("mkdir");
        let child = protected.join("rollbacks");

        // inside_protected is always reported
        let overlap = overlapping_protected_root(&child, false, std::slice::from_ref(&protected));
        let expected = std::fs::canonicalize(&protected).unwrap_or(protected);

        assert_eq!(overlap, Some(expected));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn overlapping_protected_root_parent_not_flagged_on_macos() {
        let tmp = TempDir::new().expect("tmpdir");
        let parent = tmp.path().to_path_buf();
        let protected = parent.join(".nono");

        let overlap = overlapping_protected_root(&parent, false, std::slice::from_ref(&protected));
        // macOS: parent-of-protected is not flagged (Seatbelt deny rules handle it)
        assert_eq!(overlap, None, "parent should not be flagged on macOS");
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn overlapping_protected_root_parent_not_flagged_on_linux() {
        let tmp = TempDir::new().expect("tmpdir");
        let parent = tmp.path().to_path_buf();
        let protected = parent.join(".nono");

        let overlap = overlapping_protected_root(&parent, false, std::slice::from_ref(&protected));
        // Linux: parent-of-protected is NOT flagged at runtime once BPF-LSM
        // is the primary enforcer (matching macOS, where Seatbelt deny rules
        // already protect the root). The pre-flight validator separately
        // gates parent grants on the profile's `allow_parent_of_protected`.
        assert_eq!(
            overlap, None,
            "parent should not be flagged on Linux (BPF-LSM enforces)"
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn bpf_lsm_protected_roots_includes_state_root_and_add_deny_access() {
        // Smoke-tests the merger that feeds the BPF protected_roots map.
        // Inputs: state root paths (~/.nono and friends) plus the profile's
        // `policy.add_deny_access` entries. Output: the union, expanded.
        let tmp = TempDir::new().expect("tmpdir");
        let state_root = tmp.path().join(".nono");
        std::fs::create_dir_all(&state_root).expect("mkdir");
        let secret_dir = tmp.path().join("secret");
        std::fs::create_dir_all(&secret_dir).expect("mkdir");

        let group_dir = tmp.path().join("group_deny");
        std::fs::create_dir_all(&group_dir).expect("mkdir");

        let state_roots = vec![state_root.clone()];
        let add_deny_access = vec![secret_dir.to_string_lossy().into_owned()];
        let policy_group_denies = vec![group_dir.clone()];

        let merged = bpf_lsm_protected_roots_for_session(
            &state_roots,
            &add_deny_access,
            &policy_group_denies,
        );

        let merged_strs: Vec<String> = merged
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert!(
            merged_strs.iter().any(|p| p.ends_with("/.nono")),
            "expected state root in merged set, got: {:?}",
            merged_strs
        );
        assert!(
            merged_strs.iter().any(|p| p.ends_with("/secret")),
            "expected add_deny_access path in merged set, got: {:?}",
            merged_strs
        );
        assert!(
            merged_strs.iter().any(|p| p.ends_with("/group_deny")),
            "expected policy-group deny path in merged set, got: {:?}",
            merged_strs
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn emit_protected_root_deny_rules_adds_platform_rules() {
        let tmp = TempDir::new().expect("tmpdir");
        let protected = tmp.path().join(".nono");
        std::fs::create_dir_all(&protected).expect("mkdir");

        let mut caps = CapabilitySet::new();
        emit_protected_root_deny_rules(&[protected], &mut caps).expect("emit rules");

        let rules = caps.platform_rules();
        assert!(!rules.is_empty(), "should have platform rules");
        let joined = rules.join("\n");
        assert!(
            joined.contains("deny file-read-data"),
            "should deny reads: {joined}"
        );
        assert!(
            joined.contains("deny file-write*"),
            "should deny writes: {joined}"
        );
        assert!(
            joined.contains("allow file-read-metadata"),
            "should allow metadata: {joined}"
        );
    }
}
