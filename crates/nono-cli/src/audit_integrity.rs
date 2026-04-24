use nono::supervisor::{AuditEntry, UrlOpenRequest};
use nono::undo::{AuditIntegritySummary, ContentHash, NetworkAuditEvent};
use nono::{NonoError, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::marker::PhantomData;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const HASH_ALGORITHM: &str = "sha256";

/// Configuration for a chain-hashed, Merkle-rooted NDJSON audit stream.
///
/// Each stream has its own filename and three domain-separation labels so
/// records from different streams cannot be spliced into one another — a
/// leaf produced with the `nono.audit.event.alpha` tag will not hash to
/// the same value as one produced with a different tag, and neither will
/// combine into a chain or Merkle node from another scheme.
pub(crate) struct RecorderConfig {
    pub(crate) filename: &'static str,
    pub(crate) event_domain: &'static [u8],
    pub(crate) chain_domain: &'static [u8],
    pub(crate) merkle_domain: &'static [u8],
    pub(crate) merkle_scheme_label: &'static str,
}

pub(crate) const AUDIT_EVENTS_CONFIG: RecorderConfig = RecorderConfig {
    filename: "audit-events.ndjson",
    event_domain: b"nono.audit.event.alpha\n",
    chain_domain: b"nono.audit.chain.alpha\n",
    merkle_domain: b"nono.audit.merkle.alpha\n",
    merkle_scheme_label: "alpha",
};

/// Configuration for the mediation (per-command) audit stream.
///
/// Distinct domain-separation labels from `AUDIT_EVENTS_CONFIG` prevent
/// cross-stream replay: a leaf record produced in this stream cannot be
/// spliced into `audit-events.ndjson`, and vice versa, because the hashes
/// won't match under the other stream's domain tag.
pub(crate) const MEDIATION_EVENTS_CONFIG: RecorderConfig = RecorderConfig {
    filename: "audit.jsonl",
    event_domain: b"nono.mediation.event.alpha\n",
    chain_domain: b"nono.mediation.chain.alpha\n",
    merkle_domain: b"nono.mediation.merkle.alpha\n",
    merkle_scheme_label: "alpha",
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum AuditEventPayload {
    SessionStarted {
        started: String,
        command: Vec<String>,
    },
    SessionEnded {
        ended: String,
        exit_code: i32,
    },
    CapabilityDecision {
        entry: AuditEntry,
    },
    UrlOpen {
        request: UrlOpenRequest,
        success: bool,
        error: Option<String>,
    },
    Network {
        event: NetworkAuditEvent,
    },
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct AuditEventRecord<P> {
    pub(crate) sequence: u64,
    pub(crate) prev_chain: Option<ContentHash>,
    pub(crate) leaf_hash: ContentHash,
    pub(crate) chain_hash: ContentHash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) event_json: Option<String>,
    pub(crate) event: P,
}

#[derive(Serialize)]
pub(crate) struct AuditVerificationResult {
    pub(crate) hash_algorithm: String,
    pub(crate) merkle_scheme: String,
    pub(crate) event_count: u64,
    pub(crate) computed_chain_head: Option<ContentHash>,
    pub(crate) computed_merkle_root: Option<ContentHash>,
    pub(crate) stored_event_count: Option<u64>,
    pub(crate) stored_chain_head: Option<ContentHash>,
    pub(crate) stored_merkle_root: Option<ContentHash>,
    pub(crate) event_count_matches: bool,
    pub(crate) records_verified: bool,
}

pub(crate) struct AuditRecorder<P: Serialize> {
    config: &'static RecorderConfig,
    file: File,
    next_sequence: u64,
    previous_chain: Option<ContentHash>,
    leaf_hashes: Vec<ContentHash>,
    _payload: PhantomData<P>,
}

impl<P: Serialize> AuditRecorder<P> {
    pub(crate) fn new(session_dir: PathBuf, config: &'static RecorderConfig) -> Result<Self> {
        let path = session_dir.join(config.filename);
        // 0o600: audit streams hold command args, approval decisions, URLs, and
        // capability metadata — sensitive on multi-user hosts. Set the mode at
        // creation time rather than relying on umask (usually 0o022 → 0o644).
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| {
                NonoError::Snapshot(format!(
                    "Failed to open audit event log {}: {e}",
                    path.display()
                ))
            })?;
        Ok(Self {
            config,
            file,
            next_sequence: 0,
            previous_chain: None,
            leaf_hashes: Vec::new(),
            _payload: PhantomData,
        })
    }

    pub(crate) fn event_count(&self) -> u64 {
        self.leaf_hashes.len() as u64
    }

    pub(crate) fn finalize(&self) -> Option<AuditIntegritySummary> {
        let chain_head = self.previous_chain?;
        let merkle_root = merkle_root(&self.leaf_hashes, self.config.merkle_domain);
        Some(AuditIntegritySummary {
            hash_algorithm: HASH_ALGORITHM.to_string(),
            event_count: self.event_count(),
            chain_head,
            merkle_root,
        })
    }

    pub(crate) fn append_event(&mut self, event: P) -> Result<()> {
        let event_bytes = serde_json::to_vec(&event)
            .map_err(|e| NonoError::Snapshot(format!("Failed to serialize audit event: {e}")))?;
        let leaf_hash = hash_event(&event_bytes, self.config.event_domain);
        let chain_hash = hash_chain(
            self.previous_chain.as_ref(),
            &leaf_hash,
            self.config.chain_domain,
        );
        let record = AuditEventRecord {
            sequence: self.next_sequence,
            prev_chain: self.previous_chain,
            leaf_hash,
            chain_hash,
            event_json: Some(String::from_utf8(event_bytes.clone()).map_err(|e| {
                NonoError::Snapshot(format!(
                    "Failed to encode canonical audit event JSON as UTF-8: {e}"
                ))
            })?),
            event,
        };
        let line = serde_json::to_vec(&record)
            .map_err(|e| NonoError::Snapshot(format!("Failed to serialize audit record: {e}")))?;
        self.file
            .write_all(&line)
            .and_then(|_| self.file.write_all(b"\n"))
            .and_then(|_| self.file.flush())
            .map_err(|e| NonoError::Snapshot(format!("Failed to append audit record: {e}")))?;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.previous_chain = Some(chain_hash);
        self.leaf_hashes.push(leaf_hash);
        Ok(())
    }
}

impl AuditRecorder<AuditEventPayload> {
    pub(crate) fn record_session_started(
        &mut self,
        started: String,
        command: Vec<String>,
    ) -> Result<()> {
        self.append_event(AuditEventPayload::SessionStarted { started, command })
    }

    pub(crate) fn record_session_ended(&mut self, ended: String, exit_code: i32) -> Result<()> {
        self.append_event(AuditEventPayload::SessionEnded { ended, exit_code })
    }

    pub(crate) fn record_capability_decision(&mut self, entry: AuditEntry) -> Result<()> {
        self.append_event(AuditEventPayload::CapabilityDecision { entry })
    }

    pub(crate) fn record_open_url(
        &mut self,
        request: UrlOpenRequest,
        success: bool,
        error: Option<String>,
    ) -> Result<()> {
        self.append_event(AuditEventPayload::UrlOpen {
            request,
            success,
            error,
        })
    }

    pub(crate) fn record_network_event(&mut self, event: NetworkAuditEvent) -> Result<()> {
        self.append_event(AuditEventPayload::Network { event })
    }
}

fn hash_event(event_bytes: &[u8], domain: &[u8]) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(event_bytes);
    ContentHash::from_bytes(hasher.finalize().into())
}

fn hash_chain(
    previous: Option<&ContentHash>,
    leaf_hash: &ContentHash,
    domain: &[u8],
) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    if let Some(prev) = previous {
        hasher.update(prev.as_bytes());
    } else {
        hasher.update([0u8; 32]);
    }
    hasher.update(leaf_hash.as_bytes());
    ContentHash::from_bytes(hasher.finalize().into())
}

/// Compute a Merkle root over `leaves`, domain-separated by `domain`.
///
/// Deviations from RFC 6962 and why they're safe here:
///
/// 1. **Empty tree:** returns `H(domain)` rather than `SHA256("")`. The latter is
///    a well-known constant (`e3b0c442…b855`) that would collide across every
///    stream and violate the cross-stream domain-separation invariant stated on
///    `RecorderConfig`.
///
/// 2. **Unpaired-node promotion:** an odd node at a given level is promoted
///    upward unchanged rather than paired with itself and re-hashed (the
///    CVE-2012-2459 duplication attack on Bitcoin's Merkle tree). Safe here
///    because the audit log is append-only and every leaf carries a unique
///    `sequence` field baked into its hashed JSON — duplicating a leaf would
///    require two records with the same sequence number, which verification
///    rejects in `verify_audit_log` before the Merkle check ever runs.
///
/// 3. **No leaf/internal prefix byte:** RFC 6962 prefixes leaves with `0x00`
///    and internal nodes with `0x01` to rule out leaf-as-internal confusion.
///    Safe here because leaves are hashed under `event_domain`
///    (`nono.audit.event.alpha\n` / `nono.mediation.event.alpha\n`) while
///    internal nodes are hashed under `merkle_domain`
///    (`nono.audit.merkle.alpha\n` / `nono.mediation.merkle.alpha\n`). A crafted
///    event whose bytes equal `L || R` still hashes to
///    `H(event_domain || bytes)`, which cannot collide with
///    `H(merkle_domain || L || R)` under SHA-256. See the
///    `merkle_leaf_and_internal_hashes_are_disjoint` test.
fn merkle_root(leaves: &[ContentHash], domain: &[u8]) -> ContentHash {
    if leaves.is_empty() {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        return ContentHash::from_bytes(hasher.finalize().into());
    }

    let mut level: Vec<[u8; 32]> = leaves.iter().map(|leaf| *leaf.as_bytes()).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            if pair.len() == 1 {
                next.push(left);
                continue;
            }

            let right = pair[1];
            let mut hasher = Sha256::new();
            hasher.update(domain);
            hasher.update(left);
            hasher.update(right);
            next.push(hasher.finalize().into());
        }
        level = next;
    }
    ContentHash::from_bytes(level[0])
}

pub(crate) fn verify_audit_log<P>(
    session_dir: &Path,
    stored: Option<&AuditIntegritySummary>,
    config: &'static RecorderConfig,
) -> Result<AuditVerificationResult>
where
    P: Serialize + DeserializeOwned,
{
    let path = session_dir.join(config.filename);
    let file = File::open(&path).map_err(|e| {
        NonoError::Snapshot(format!(
            "Failed to open audit event log {}: {e}",
            path.display()
        ))
    })?;

    let reader = BufReader::new(file);
    let mut previous_chain: Option<ContentHash> = None;
    let mut leaf_hashes = Vec::new();
    let mut computed_chain_head: Option<ContentHash> = None;
    let mut missing_canonical_event_json = false;

    for (index, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to read audit event log {}: {e}",
                path.display()
            ))
        })?;
        if line.trim().is_empty() {
            continue;
        }

        let record: AuditEventRecord<P> = serde_json::from_str(&line).map_err(|e| {
            NonoError::Snapshot(format!(
                "Failed to parse audit event record {} line {}: {e}",
                path.display(),
                index.saturating_add(1)
            ))
        })?;

        let expected_sequence = leaf_hashes.len() as u64;
        if record.sequence != expected_sequence {
            return Err(NonoError::Snapshot(format!(
                "Audit event record sequence mismatch at line {}: expected {}, got {}",
                index.saturating_add(1),
                expected_sequence,
                record.sequence
            )));
        }

        if record.prev_chain != previous_chain {
            return Err(NonoError::Snapshot(format!(
                "Audit event record prev_chain mismatch at line {}",
                index.saturating_add(1)
            )));
        }

        let event_bytes = if let Some(raw) = record.event_json.as_ref() {
            let reparsed: P = serde_json::from_str(raw).map_err(|e| {
                NonoError::Snapshot(format!(
                    "Failed to parse canonical audit event JSON at line {}: {e}",
                    index.saturating_add(1)
                ))
            })?;
            let reparsed_value = serde_json::to_value(&reparsed).map_err(|e| {
                NonoError::Snapshot(format!(
                    "Failed to normalize canonical audit event JSON at line {}: {e}",
                    index.saturating_add(1)
                ))
            })?;
            let record_value = serde_json::to_value(&record.event).map_err(|e| {
                NonoError::Snapshot(format!(
                    "Failed to normalize audit event payload at line {}: {e}",
                    index.saturating_add(1)
                ))
            })?;
            if reparsed_value != record_value {
                return Err(NonoError::Snapshot(format!(
                    "Audit event JSON mismatch at line {}",
                    index.saturating_add(1)
                )));
            }
            raw.as_bytes().to_vec()
        } else {
            missing_canonical_event_json = true;
            serde_json::to_vec(&record.event).map_err(|e| {
                NonoError::Snapshot(format!(
                    "Failed to serialize audit event for verification at line {}: {e}",
                    index.saturating_add(1)
                ))
            })?
        };
        let leaf_hash = hash_event(&event_bytes, config.event_domain);
        if record.leaf_hash != leaf_hash {
            return Err(NonoError::Snapshot(format!(
                "Audit event leaf hash mismatch at line {}",
                index.saturating_add(1)
            )));
        }

        let chain_hash = hash_chain(previous_chain.as_ref(), &leaf_hash, config.chain_domain);
        if record.chain_hash != chain_hash {
            return Err(NonoError::Snapshot(format!(
                "Audit event chain hash mismatch at line {}",
                index.saturating_add(1)
            )));
        }

        previous_chain = Some(chain_hash);
        computed_chain_head = Some(chain_hash);
        leaf_hashes.push(leaf_hash);
    }

    let computed_merkle_root = if leaf_hashes.is_empty() {
        None
    } else {
        Some(merkle_root(&leaf_hashes, config.merkle_domain))
    };

    if stored.is_some() && !leaf_hashes.is_empty() && missing_canonical_event_json {
        return Err(NonoError::Snapshot(format!(
            "{} audit log is missing canonical event_json bytes",
            config.merkle_scheme_label
        )));
    }

    let stored_event_count = stored.map(|s| s.event_count);
    let stored_chain_head = stored.map(|s| s.chain_head);
    let stored_merkle_root = stored.map(|s| s.merkle_root);
    let event_count = leaf_hashes.len() as u64;
    let event_count_matches = stored_event_count
        .map(|count| count == event_count)
        .unwrap_or(true);

    if let Some(stored_head) = stored_chain_head {
        if Some(stored_head) != computed_chain_head {
            return Err(NonoError::Snapshot(format!(
                "{} audit log chain head mismatch",
                config.merkle_scheme_label
            )));
        }
    }

    if let Some(stored_root) = stored_merkle_root {
        if Some(stored_root) != computed_merkle_root {
            return Err(NonoError::Snapshot(format!(
                "{} audit log Merkle root mismatch",
                config.merkle_scheme_label
            )));
        }
    }

    Ok(AuditVerificationResult {
        hash_algorithm: HASH_ALGORITHM.to_string(),
        merkle_scheme: config.merkle_scheme_label.to_string(),
        event_count,
        computed_chain_head,
        computed_merkle_root,
        stored_event_count,
        stored_chain_head,
        stored_merkle_root,
        event_count_matches,
        records_verified: true,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nono::supervisor::{ApprovalDecision, AuditEntry, CapabilityRequest, UrlOpenRequest};
    use nono::undo::{NetworkAuditDecision, NetworkAuditEvent, NetworkAuditMode};
    use nono::AccessMode;
    use std::path::PathBuf;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn recorder_produces_integrity_summary() {
        let dir = tempfile::tempdir().unwrap();
        let mut recorder: AuditRecorder<AuditEventPayload> =
            AuditRecorder::new(dir.path().to_path_buf(), &AUDIT_EVENTS_CONFIG).unwrap();
        recorder
            .record_session_started("2026-04-21T00:00:00Z".to_string(), vec!["pwd".to_string()])
            .unwrap();
        recorder
            .record_session_ended("2026-04-21T00:00:01Z".to_string(), 0)
            .unwrap();

        let summary = recorder.finalize().unwrap();
        assert_eq!(summary.event_count, 2);
        assert_eq!(summary.hash_algorithm, HASH_ALGORITHM);
    }

    #[test]
    fn recorder_tracks_event_count_without_needing_integrity_output() {
        let dir = tempfile::tempdir().unwrap();
        let mut recorder: AuditRecorder<AuditEventPayload> =
            AuditRecorder::new(dir.path().to_path_buf(), &AUDIT_EVENTS_CONFIG).unwrap();
        recorder
            .record_session_started("2026-04-21T00:00:00Z".to_string(), vec!["pwd".to_string()])
            .unwrap();

        assert_eq!(recorder.event_count(), 1);
    }

    #[test]
    fn verifier_round_trips_all_current_audit_event_payload_variants() {
        let dir = tempfile::tempdir().unwrap();
        let mut recorder: AuditRecorder<AuditEventPayload> =
            AuditRecorder::new(dir.path().to_path_buf(), &AUDIT_EVENTS_CONFIG).unwrap();
        recorder
            .record_session_started(
                "2026-04-21T00:00:00Z".to_string(),
                vec!["claude".to_string(), "--debug".to_string()],
            )
            .unwrap();
        recorder
            .record_capability_decision(AuditEntry {
                timestamp: UNIX_EPOCH + Duration::from_secs(5),
                request: CapabilityRequest {
                    request_id: "req-1".to_string(),
                    path: PathBuf::from("/tmp/example"),
                    access: AccessMode::ReadWrite,
                    reason: Some("need scratch space".to_string()),
                    child_pid: 42,
                    session_id: "sess-1".to_string(),
                },
                decision: ApprovalDecision::Denied {
                    reason: "outside policy".to_string(),
                },
                backend: "terminal".to_string(),
                duration_ms: 12,
            })
            .unwrap();
        recorder
            .record_open_url(
                UrlOpenRequest {
                    request_id: "open-1".to_string(),
                    url: "https://example.com/callback".to_string(),
                    child_pid: 42,
                    session_id: "sess-1".to_string(),
                },
                false,
                Some("blocked".to_string()),
            )
            .unwrap();
        recorder
            .record_network_event(NetworkAuditEvent {
                timestamp_unix_ms: 123,
                mode: NetworkAuditMode::Reverse,
                decision: NetworkAuditDecision::Deny,
                target: "api.example.com".to_string(),
                port: Some(443),
                method: Some("POST".to_string()),
                path: Some("/v1/chat".to_string()),
                status: Some(403),
                reason: Some("policy".to_string()),
            })
            .unwrap();
        recorder
            .record_session_ended("2026-04-21T00:00:01Z".to_string(), 7)
            .unwrap();

        let summary = recorder.finalize().unwrap();
        let verified =
            verify_audit_log::<AuditEventPayload>(dir.path(), Some(&summary), &AUDIT_EVENTS_CONFIG)
                .unwrap();
        assert_eq!(verified.event_count, 5);
        assert_eq!(verified.merkle_scheme, "alpha");
        assert!(verified.records_verified);
    }

    #[test]
    fn verifier_rejects_alpha_records_missing_event_json() {
        let dir = tempfile::tempdir().unwrap();
        let mut recorder: AuditRecorder<AuditEventPayload> =
            AuditRecorder::new(dir.path().to_path_buf(), &AUDIT_EVENTS_CONFIG).unwrap();
        recorder
            .record_session_started("2026-04-21T00:00:00Z".to_string(), vec!["pwd".to_string()])
            .unwrap();
        recorder
            .record_session_ended("2026-04-21T00:00:01Z".to_string(), 0)
            .unwrap();

        let path = dir.path().join(AUDIT_EVENTS_CONFIG.filename);
        let contents = std::fs::read_to_string(&path).unwrap();
        let rewritten = contents
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let mut record: AuditEventRecord<AuditEventPayload> =
                    serde_json::from_str(line).unwrap();
                record.event_json = None;
                serde_json::to_string(&record).unwrap()
            })
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&path, format!("{rewritten}\n")).unwrap();

        let summary = recorder.finalize().unwrap();
        let err = match verify_audit_log::<AuditEventPayload>(
            dir.path(),
            Some(&summary),
            &AUDIT_EVENTS_CONFIG,
        ) {
            Ok(_) => panic!("alpha verification should reject records missing event_json"),
            Err(err) => err,
        };
        assert!(err
            .to_string()
            .contains("missing canonical event_json bytes"));
    }

    // ---------------------------------------------------------------------
    // Mediation stream tests (parameterized payload + distinct config).
    // ---------------------------------------------------------------------

    /// Minimal payload for exercising the generic recorder with a non-
    /// `AuditEventPayload` type. Mirrors the mediation `AuditEvent` shape.
    #[derive(Clone, Debug, Serialize, serde::Deserialize, PartialEq)]
    struct FakeMediationEvent {
        command: String,
        ts: u64,
        exit_code: i32,
    }

    #[test]
    fn mediation_recorder_chains_and_merkles() {
        // Append events under MEDIATION_EVENTS_CONFIG and verify that
        // finalize() produces a summary that matches a fresh verification
        // pass — proves chain + Merkle math is correct under the distinct
        // domain-separation labels.
        let dir = tempfile::tempdir().unwrap();
        let mut recorder: AuditRecorder<FakeMediationEvent> =
            AuditRecorder::new(dir.path().to_path_buf(), &MEDIATION_EVENTS_CONFIG).unwrap();
        for i in 0..5 {
            recorder
                .append_event(FakeMediationEvent {
                    command: format!("cmd-{i}"),
                    ts: 1_775_000_000 + i as u64,
                    exit_code: 0,
                })
                .unwrap();
        }
        let summary = recorder.finalize().unwrap();
        assert_eq!(summary.event_count, 5);

        let verified = verify_audit_log::<FakeMediationEvent>(
            dir.path(),
            Some(&summary),
            &MEDIATION_EVENTS_CONFIG,
        )
        .unwrap();
        assert!(verified.records_verified);
        assert!(verified.event_count_matches);
        assert_eq!(verified.computed_chain_head, Some(summary.chain_head));
        assert_eq!(verified.computed_merkle_root, Some(summary.merkle_root));
    }

    #[test]
    fn mediation_verify_fails_on_tampered_log() {
        // Append events, flip a single byte in the on-disk JSONL, then
        // re-verify and expect a failure. Proves the chain/Merkle check
        // actually catches tampering for the mediation stream.
        let dir = tempfile::tempdir().unwrap();
        let mut recorder: AuditRecorder<FakeMediationEvent> =
            AuditRecorder::new(dir.path().to_path_buf(), &MEDIATION_EVENTS_CONFIG).unwrap();
        for i in 0..3 {
            recorder
                .append_event(FakeMediationEvent {
                    command: format!("c{i}"),
                    ts: 100 + i as u64,
                    exit_code: 0,
                })
                .unwrap();
        }
        let summary = recorder.finalize().unwrap();

        // Tamper: flip one character in the command field of the first event.
        let log_path = dir.path().join(MEDIATION_EVENTS_CONFIG.filename);
        let contents = std::fs::read_to_string(&log_path).unwrap();
        let tampered = contents.replacen("\"command\":\"c0\"", "\"command\":\"X0\"", 1);
        assert_ne!(contents, tampered, "replacement must have changed bytes");
        std::fs::write(&log_path, tampered).unwrap();

        let result = verify_audit_log::<FakeMediationEvent>(
            dir.path(),
            Some(&summary),
            &MEDIATION_EVENTS_CONFIG,
        );
        assert!(
            result.is_err(),
            "tampered mediation log should fail verification"
        );
    }

    #[test]
    fn mediation_and_audit_configs_produce_different_chain_heads() {
        // Same event bytes under different domain-separation labels must
        // produce different leaf + chain hashes. Guards against cross-
        // stream replay.
        let dir_a = tempfile::tempdir().unwrap();
        let dir_m = tempfile::tempdir().unwrap();
        let event = FakeMediationEvent {
            command: "ls".to_string(),
            ts: 1,
            exit_code: 0,
        };

        let mut rec_a: AuditRecorder<FakeMediationEvent> =
            AuditRecorder::new(dir_a.path().to_path_buf(), &AUDIT_EVENTS_CONFIG).unwrap();
        rec_a.append_event(event.clone()).unwrap();
        let sum_a = rec_a.finalize().unwrap();

        let mut rec_m: AuditRecorder<FakeMediationEvent> =
            AuditRecorder::new(dir_m.path().to_path_buf(), &MEDIATION_EVENTS_CONFIG).unwrap();
        rec_m.append_event(event).unwrap();
        let sum_m = rec_m.finalize().unwrap();

        assert_ne!(
            sum_a.chain_head, sum_m.chain_head,
            "distinct domain labels must yield distinct chain heads"
        );
        assert_ne!(
            sum_a.merkle_root, sum_m.merkle_root,
            "distinct domain labels must yield distinct Merkle roots"
        );
    }

    #[test]
    fn mediation_recorder_under_concurrent_appenders() {
        // Pound on a shared `Arc<Mutex<AuditRecorder>>` from many threads,
        // matching the mediation server's two concurrent write paths
        // (stream handler + datagram receiver). Each thread appends N
        // events; after joining, the total event_count and chain must
        // reflect all appends with no lost/duplicated records.
        use std::sync::{Arc, Mutex};
        use std::thread;

        let dir = tempfile::tempdir().unwrap();
        let recorder: Arc<Mutex<AuditRecorder<FakeMediationEvent>>> = Arc::new(Mutex::new(
            AuditRecorder::new(dir.path().to_path_buf(), &MEDIATION_EVENTS_CONFIG).unwrap(),
        ));

        const THREADS: usize = 10;
        const PER_THREAD: usize = 20;
        let mut handles = Vec::with_capacity(THREADS);
        for t in 0..THREADS {
            let r = Arc::clone(&recorder);
            handles.push(thread::spawn(move || {
                for i in 0..PER_THREAD {
                    let ev = FakeMediationEvent {
                        command: format!("t{t}-i{i}"),
                        ts: (t * 1000 + i) as u64,
                        exit_code: 0,
                    };
                    // Critical section: lock → append → drop guard. Matches the
                    // discipline enforced in mediation::server::log_mediated_audit.
                    r.lock().unwrap().append_event(ev).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let expected_count = (THREADS * PER_THREAD) as u64;
        let guard = recorder.lock().unwrap();
        assert_eq!(guard.event_count(), expected_count);
        let summary = guard.finalize().unwrap();
        drop(guard);

        // Re-verify on disk — proves chain integrity held across all
        // concurrent appends.
        let verified = verify_audit_log::<FakeMediationEvent>(
            dir.path(),
            Some(&summary),
            &MEDIATION_EVENTS_CONFIG,
        )
        .unwrap();
        assert_eq!(verified.event_count, expected_count);
        assert!(verified.records_verified);
        assert!(verified.event_count_matches);
    }

    #[test]
    fn empty_merkle_root_is_domain_separated() {
        // The empty-tree case must respect the cross-stream domain-separation
        // invariant stated on `RecorderConfig`. Returning a constant like
        // `SHA256("")` would collide across every stream.
        let empty_audit = merkle_root(&[], AUDIT_EVENTS_CONFIG.merkle_domain);
        let empty_mediation = merkle_root(&[], MEDIATION_EVENTS_CONFIG.merkle_domain);
        assert_ne!(
            empty_audit, empty_mediation,
            "empty-tree Merkle roots must differ across streams"
        );
        assert_ne!(
            *empty_audit.as_bytes(),
            *ContentHash::from_bytes(Sha256::digest(b"").into()).as_bytes(),
            "empty-tree Merkle root must not be the well-known SHA-256 of the empty string"
        );
    }

    #[test]
    fn merkle_leaf_and_internal_hashes_are_disjoint() {
        // Rules out leaf-vs-internal-node confusion even without RFC 6962
        // prefix bytes. `hash_event(x, event_domain)` produces
        // `H(event_domain || x)`, while an internal node at this level
        // produces `H(merkle_domain || L || R)`. Because `event_domain` and
        // `merkle_domain` differ, SHA-256 cannot collide the two regardless
        // of the attacker-chosen payload `x`.
        for config in [&AUDIT_EVENTS_CONFIG, &MEDIATION_EVENTS_CONFIG] {
            for sample in [
                &b""[..],
                b"{}",
                // A synthetic "internal-node shape": 64 bytes of two concatenated
                // 32-byte hashes. If leaf/internal were confused, this is what
                // an attacker would craft.
                &[0xAAu8; 64][..],
                b"\x00\x01\x02\x03",
            ] {
                let leaf = hash_event(sample, config.event_domain);

                // Build an internal node whose children bytes happen to equal
                // `sample` padded/truncated to 64 bytes — matches the loop body
                // in `merkle_root`.
                let mut padded = [0u8; 64];
                let n = sample.len().min(64);
                padded[..n].copy_from_slice(&sample[..n]);
                let (left, right) = padded.split_at(32);
                let mut hasher = Sha256::new();
                hasher.update(config.merkle_domain);
                hasher.update(left);
                hasher.update(right);
                let internal = ContentHash::from_bytes(hasher.finalize().into());

                assert_ne!(
                    leaf,
                    internal,
                    "leaf and internal-node hashes must not collide (config={}, sample_len={})",
                    config.merkle_scheme_label,
                    sample.len()
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn audit_log_file_mode_is_owner_only() {
        // Regression guard for the info-disclosure fix: both streams must
        // land on disk with mode 0o600 at creation time, matching the
        // mediation sockets' hygiene. Without the explicit `.mode(0o600)`,
        // the default umask of 0o022 would leave the file at 0o644.
        use std::os::unix::fs::PermissionsExt;

        for config in [&AUDIT_EVENTS_CONFIG, &MEDIATION_EVENTS_CONFIG] {
            let dir = tempfile::tempdir().unwrap();
            let mut recorder: AuditRecorder<FakeMediationEvent> =
                AuditRecorder::new(dir.path().to_path_buf(), config).unwrap();
            recorder
                .append_event(FakeMediationEvent {
                    command: "probe".to_string(),
                    ts: 1,
                    exit_code: 0,
                })
                .unwrap();

            let path = dir.path().join(config.filename);
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "{} must be created with mode 0o600 (got 0o{:o})",
                config.filename, mode
            );
        }
    }
}
