use std::collections::{BTreeMap, HashMap, HashSet};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use md5::Md5;
use serde::{Deserialize, Serialize};
use serde_json::de::from_slice;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

pub mod v0;
pub use v0::*;

pub const MANIFEST_V0_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../spec/skill-format/manifest.schema.json"
));
pub const MANIFEST_V1_DRAFT_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../spec/skill-format/manifest.v1.experimental.schema.json"
));
pub const SIGNATURES_V0_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../spec/skill-format/signatures.schema.json"
));
pub const PROVENANCE_V0_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../spec/skill-format/provenance.schema.json"
));
pub const POLICY_V0_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../spec/policy/policy.schema.json"
));
pub const RECEIPT_V0_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../spec/execution-receipt.schema.json"
));
pub const RECEIPT_V1_DRAFT_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../spec/execution-receipt.v1.experimental.schema.json"
));

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("invalid digest format: {0}")]
    InvalidDigestFormat(String),
    #[error("digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch { expected: String, actual: String },
    #[error("unsupported signature algorithm: {0}")]
    UnsupportedSignatureAlgorithm(String),
    #[error("missing public key for signer: {0}")]
    MissingPublicKey(String),
    #[error("signature set is empty")]
    EmptySignatureSet,
    #[error("base64 decode failed")]
    Base64Decode,
    #[error("invalid signature bytes")]
    SignatureBytes,
    #[error("signature verification failed for signer: {0}")]
    SignatureVerify(String),
    #[error("canonical JSON serialization failed")]
    CanonicalJson,
    #[error("invalid manifest JSON")]
    ManifestJson,
    #[error("unsupported manifest schema version: {0}")]
    UnsupportedManifestSchemaVersion(String),
    #[error("invalid manifest v1 draft JSON")]
    ManifestV1DraftJson,
    #[error("unsupported receipt schema version: {0}")]
    UnsupportedReceiptSchemaVersion(String),
    #[error("invalid receipt v1 draft JSON")]
    ReceiptV1DraftJson,
    #[error("invalid draft field: {0}")]
    InvalidDraftField(String),
    #[error("invalid signatures JSON")]
    SignaturesJson,
    #[error("invalid provenance JSON")]
    ProvenanceJson,
    #[error("invalid registry snapshot JSON")]
    SnapshotJson,
    #[error("invalid execution receipt JSON")]
    ReceiptJson,
    #[error("invalid policy document")]
    PolicyDocument,
    #[error("unsupported policy version: {0}")]
    UnsupportedPolicyVersion(u64),
    #[error("policy.trusted_signers must be non-empty")]
    EmptyTrustedSigners,
    #[error("no trusted signer declared in manifest.signers")]
    UntrustedManifestSigners,
    #[error("no trusted signer present in signatures.json")]
    UntrustedSignatureSet,
    #[error("signature signer is not declared in manifest.signers: {0}")]
    SignatureSignerNotDeclared(String),
    #[error("capability denied: {0}")]
    CapabilityDenied(String),
    #[error("policy constraint violation: {0}")]
    PolicyConstraint(String),
    #[error("invalid v0 skill manifest: {reason}")]
    InvalidV0SkillManifest { reason: String },
    #[error("invalid v0 pipeline: {reason}")]
    InvalidV0Pipeline { reason: String },
    #[error("missing required capability after policy intersection: {0}")]
    MissingRequiredCapabilityV0(String),
    #[error("v0 event chain violation: {reason}")]
    EventChainViolationV0 { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<String>,
    pub name: String,
    pub version: String,
    pub entrypoint: String,
    pub artifact: String,
    pub capabilities: Vec<Capability>,
    pub signers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestV1Draft {
    pub schema_version: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub version: String,
    pub entrypoint: EntryPointV1Draft,
    pub artifact: String,
    pub inputs_schema: JsonSchemaRefV1Draft,
    pub outputs_schema: JsonSchemaRefV1Draft,
    pub capabilities: Vec<Capability>,
    pub signers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compatibility: Option<CompatibilityV1Draft>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EntryPointV1Draft {
    Name(String),
    Descriptor(EntryPointDescriptorV1Draft),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryPointDescriptorV1Draft {
    pub kind: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonSchemaRefV1Draft {
    Inline(serde_json::Value),
    Uri(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityV1Draft {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_profiles: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_profiles: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEntry {
    pub signer: String,
    pub algorithm: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signatures {
    pub artifact: String,
    pub manifest_hash: String,
    pub signatures: Vec<SignatureEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub source: String,
    pub commit: String,
    pub build_system: String,
    pub build_recipe_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryEntry {
    pub sha256: String,
    pub md5: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrySnapshot {
    pub snapshot_hash: String,
    pub timestamp: u64,
    pub entries: BTreeMap<String, RegistryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReceipt {
    pub artifact: String,
    pub inputs_hash: String,
    pub outputs_hash: String,
    pub caps_used: Vec<String>,
    pub timestamp: u64,
    pub receipt_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReceiptV1Draft {
    pub schema_version: String,
    pub artifact: String,
    pub manifest_hash: String,
    pub policy_hash: String,
    pub bundle_hash: String,
    pub inputs_hash: String,
    pub outputs_hash: String,
    pub runtime_version_digest: String,
    pub result_digest: String,
    pub caps_requested: Vec<String>,
    pub caps_granted: Vec<String>,
    pub caps_used: Vec<String>,
    pub result: ExecutionResultV1Draft,
    pub runtime: RuntimeV1Draft,
    pub started_at: u64,
    pub finished_at: u64,
    pub timestamp_strategy: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestations: Option<Vec<AttestationV1Draft>>,
    pub receipt_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionResultV1Draft {
    pub status: String,
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeV1Draft {
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationV1Draft {
    pub r#type: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u64,
    pub trusted_signers: Vec<String>,
    pub capability_ceiling: CapabilityCeiling,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityCeiling {
    pub fs: Option<PolicyFs>,
    pub net: Option<Vec<String>>,
    pub kv: Option<PolicyKv>,
    pub queue: Option<PolicyQueue>,
    pub env: Option<Vec<String>>,
    pub exec: Option<bool>,
    pub time: Option<bool>,
    pub random: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFs {
    pub read: Option<Vec<String>>,
    pub write: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyKv {
    pub read: Option<Vec<String>>,
    pub write: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyQueue {
    pub publish: Option<Vec<String>>,
    pub consume: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
struct SnapshotHashPayload<'a> {
    timestamp: u64,
    entries: &'a BTreeMap<String, RegistryEntry>,
}

#[derive(Debug, Clone, Serialize)]
struct ReceiptHashPayload<'a> {
    artifact: &'a str,
    inputs_hash: &'a str,
    outputs_hash: &'a str,
    caps_used: &'a [String],
    timestamp: u64,
}

#[derive(Debug, Clone, Serialize)]
struct BundleHashPayload<'a> {
    artifact: &'a str,
    manifest_hash: &'a str,
    signatures_hash: &'a str,
}

#[derive(Debug, Clone, Serialize)]
struct ReceiptV1DraftHashPayload<'a> {
    schema_version: &'a str,
    artifact: &'a str,
    manifest_hash: &'a str,
    policy_hash: &'a str,
    bundle_hash: &'a str,
    inputs_hash: &'a str,
    outputs_hash: &'a str,
    runtime_version_digest: &'a str,
    result_digest: &'a str,
    caps_requested: &'a [String],
    caps_granted: &'a [String],
    caps_used: &'a [String],
    result: &'a ExecutionResultV1Draft,
    runtime: &'a RuntimeV1Draft,
    started_at: u64,
    finished_at: u64,
    timestamp_strategy: &'a str,
    attestations: Option<&'a [AttestationV1Draft]>,
}

#[derive(Debug, Clone, Serialize)]
struct ResultDigestPayload<'a> {
    status: &'a str,
    code: &'a str,
    outputs_hash: &'a str,
    caps_used: &'a [String],
}

pub fn sha256_prefixed(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{digest:x}")
}

pub fn md5_hex(bytes: &[u8]) -> String {
    let digest = Md5::digest(bytes);
    format!("{digest:x}")
}

pub fn parse_manifest_json(bytes: &[u8]) -> Result<Manifest, VerifyError> {
    let manifest: Manifest = from_slice(bytes).map_err(|_| VerifyError::ManifestJson)?;
    if let Some(version) = manifest.schema_version.as_deref() {
        if version != "1.0.0-draft" {
            return Err(VerifyError::UnsupportedManifestSchemaVersion(
                version.to_string(),
            ));
        }
    }
    validate_sha256_prefixed(&manifest.artifact)?;
    Ok(manifest)
}

pub fn parse_manifest_v1_draft_json(bytes: &[u8]) -> Result<ManifestV1Draft, VerifyError> {
    let manifest: ManifestV1Draft =
        from_slice(bytes).map_err(|_| VerifyError::ManifestV1DraftJson)?;
    if manifest.schema_version != "1.0.0-draft" {
        return Err(VerifyError::UnsupportedManifestSchemaVersion(
            manifest.schema_version.clone(),
        ));
    }
    if manifest.id.is_empty() {
        return Err(VerifyError::InvalidDraftField(
            "manifest.id must be non-empty".to_string(),
        ));
    }
    if manifest.version.is_empty() {
        return Err(VerifyError::InvalidDraftField(
            "manifest.version must be non-empty".to_string(),
        ));
    }
    validate_sha256_prefixed(&manifest.artifact)?;
    match &manifest.entrypoint {
        EntryPointV1Draft::Name(name) => {
            if name.is_empty() {
                return Err(VerifyError::InvalidDraftField(
                    "manifest.entrypoint must be non-empty".to_string(),
                ));
            }
        }
        EntryPointV1Draft::Descriptor(descriptor) => {
            if !(descriptor.kind == "wasi-command" || descriptor.kind == "wasi-reactor") {
                return Err(VerifyError::InvalidDraftField(
                    "manifest.entrypoint.kind must be wasi-command or wasi-reactor".to_string(),
                ));
            }
            if descriptor.path.is_empty() {
                return Err(VerifyError::InvalidDraftField(
                    "manifest.entrypoint.path must be non-empty".to_string(),
                ));
            }
        }
    }
    validate_json_schema_ref(&manifest.inputs_schema, "manifest.inputs_schema")?;
    validate_json_schema_ref(&manifest.outputs_schema, "manifest.outputs_schema")?;
    if manifest
        .capabilities
        .iter()
        .any(|cap| cap.kind.is_empty() || cap.value.is_empty())
    {
        return Err(VerifyError::InvalidDraftField(
            "manifest.capabilities items must have non-empty kind/value".to_string(),
        ));
    }
    if manifest.signers.iter().any(String::is_empty) {
        return Err(VerifyError::InvalidDraftField(
            "manifest.signers items must be non-empty".to_string(),
        ));
    }
    if let Some(compatibility) = &manifest.compatibility {
        if compatibility
            .runtime_profiles
            .as_ref()
            .is_some_and(|items| items.iter().any(String::is_empty))
        {
            return Err(VerifyError::InvalidDraftField(
                "manifest.compatibility.runtime_profiles items must be non-empty".to_string(),
            ));
        }
        if compatibility
            .adapter_profiles
            .as_ref()
            .is_some_and(|items| items.iter().any(String::is_empty))
        {
            return Err(VerifyError::InvalidDraftField(
                "manifest.compatibility.adapter_profiles items must be non-empty".to_string(),
            ));
        }
    }
    Ok(manifest)
}

pub fn parse_signatures_json(bytes: &[u8]) -> Result<Signatures, VerifyError> {
    let signatures: Signatures = from_slice(bytes).map_err(|_| VerifyError::SignaturesJson)?;
    validate_sha256_prefixed(&signatures.artifact)?;
    validate_sha256_prefixed(&signatures.manifest_hash)?;
    Ok(signatures)
}

pub fn compute_manifest_hash(manifest: &Manifest) -> Result<String, VerifyError> {
    let bytes = to_jcs_bytes(manifest)?;
    Ok(sha256_prefixed(&bytes))
}

pub fn parse_provenance_json(bytes: &[u8]) -> Result<Provenance, VerifyError> {
    let provenance: Provenance = from_slice(bytes).map_err(|_| VerifyError::ProvenanceJson)?;
    validate_sha256_prefixed(&provenance.build_recipe_hash)?;
    Ok(provenance)
}

pub fn parse_snapshot_json(bytes: &[u8]) -> Result<RegistrySnapshot, VerifyError> {
    let snapshot: RegistrySnapshot = from_slice(bytes).map_err(|_| VerifyError::SnapshotJson)?;
    validate_sha256_prefixed(&snapshot.snapshot_hash)?;
    for entry in snapshot.entries.values() {
        validate_sha256_prefixed(&entry.sha256)?;
        validate_md5_hex(&entry.md5)?;
    }
    Ok(snapshot)
}

pub fn parse_receipt_json(bytes: &[u8]) -> Result<ExecutionReceipt, VerifyError> {
    let receipt: ExecutionReceipt = from_slice(bytes).map_err(|_| VerifyError::ReceiptJson)?;
    validate_sha256_prefixed(&receipt.artifact)?;
    validate_sha256_prefixed(&receipt.inputs_hash)?;
    validate_sha256_prefixed(&receipt.outputs_hash)?;
    validate_sha256_prefixed(&receipt.receipt_hash)?;
    Ok(receipt)
}

pub fn parse_receipt_v1_draft_json(bytes: &[u8]) -> Result<ExecutionReceiptV1Draft, VerifyError> {
    let receipt: ExecutionReceiptV1Draft =
        from_slice(bytes).map_err(|_| VerifyError::ReceiptV1DraftJson)?;
    if receipt.schema_version != "1.0.0-draft" {
        return Err(VerifyError::UnsupportedReceiptSchemaVersion(
            receipt.schema_version.clone(),
        ));
    }
    for digest in [
        &receipt.artifact,
        &receipt.manifest_hash,
        &receipt.policy_hash,
        &receipt.bundle_hash,
        &receipt.inputs_hash,
        &receipt.outputs_hash,
        &receipt.runtime_version_digest,
        &receipt.result_digest,
        &receipt.receipt_hash,
    ] {
        validate_sha256_prefixed(digest)?;
    }
    if receipt
        .caps_requested
        .iter()
        .chain(receipt.caps_granted.iter())
        .chain(receipt.caps_used.iter())
        .any(String::is_empty)
    {
        return Err(VerifyError::InvalidDraftField(
            "receipt capability fields must not contain empty items".to_string(),
        ));
    }
    if !(receipt.result.status == "success" || receipt.result.status == "failure") {
        return Err(VerifyError::InvalidDraftField(
            "receipt.result.status must be success or failure".to_string(),
        ));
    }
    if receipt.result.code.is_empty() {
        return Err(VerifyError::InvalidDraftField(
            "receipt.result.code must be non-empty".to_string(),
        ));
    }
    if receipt.runtime.name.is_empty() || receipt.runtime.version.is_empty() {
        return Err(VerifyError::InvalidDraftField(
            "receipt.runtime.name/version must be non-empty".to_string(),
        ));
    }
    if receipt.finished_at < receipt.started_at {
        return Err(VerifyError::InvalidDraftField(
            "receipt.finished_at must be >= receipt.started_at".to_string(),
        ));
    }
    if receipt.timestamp_strategy != "local_untrusted_unix_seconds" {
        return Err(VerifyError::InvalidDraftField(
            "receipt.timestamp_strategy must be local_untrusted_unix_seconds".to_string(),
        ));
    }
    if receipt.attestations.as_ref().is_some_and(|items| {
        items
            .iter()
            .any(|item| item.r#type.is_empty() || item.value.is_empty())
    }) {
        return Err(VerifyError::InvalidDraftField(
            "receipt.attestations items must have non-empty type/value".to_string(),
        ));
    }
    Ok(receipt)
}

pub fn parse_policy_document(bytes: &[u8]) -> Result<Policy, VerifyError> {
    let policy: Policy = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(_) => serde_yaml::from_slice(bytes).map_err(|_| VerifyError::PolicyDocument)?,
    };
    if policy.version != 1 {
        return Err(VerifyError::UnsupportedPolicyVersion(policy.version));
    }
    if policy.trusted_signers.is_empty() {
        return Err(VerifyError::EmptyTrustedSigners);
    }
    validate_policy_constraints(&policy)?;
    Ok(policy)
}

pub fn verify_artifact_hash(skill_wasm: &[u8], expected_artifact: &str) -> Result<(), VerifyError> {
    validate_sha256_prefixed(expected_artifact)?;
    let actual = sha256_prefixed(skill_wasm);
    if actual != expected_artifact {
        return Err(VerifyError::DigestMismatch {
            expected: expected_artifact.to_string(),
            actual,
        });
    }
    Ok(())
}

pub fn verify_registry_entry_artifact(
    artifact_bytes: &[u8],
    entry: &RegistryEntry,
) -> Result<(), VerifyError> {
    validate_sha256_prefixed(&entry.sha256)?;
    validate_md5_hex(&entry.md5)?;

    let actual_md5 = md5_hex(artifact_bytes);
    if actual_md5 != entry.md5 {
        return Err(VerifyError::DigestMismatch {
            expected: entry.md5.clone(),
            actual: actual_md5,
        });
    }

    let actual_sha256 = sha256_prefixed(artifact_bytes);
    if actual_sha256 != entry.sha256 {
        return Err(VerifyError::DigestMismatch {
            expected: entry.sha256.clone(),
            actual: actual_sha256,
        });
    }

    Ok(())
}

pub fn verify_snapshot_hash(snapshot: &RegistrySnapshot) -> Result<(), VerifyError> {
    validate_sha256_prefixed(&snapshot.snapshot_hash)?;
    let payload = SnapshotHashPayload {
        timestamp: snapshot.timestamp,
        entries: &snapshot.entries,
    };
    let bytes = to_jcs_bytes(&payload)?;
    let actual = sha256_prefixed(&bytes);
    if actual != snapshot.snapshot_hash {
        return Err(VerifyError::DigestMismatch {
            expected: snapshot.snapshot_hash.clone(),
            actual,
        });
    }
    Ok(())
}

pub fn verify_receipt_hash(receipt: &ExecutionReceipt) -> Result<(), VerifyError> {
    validate_sha256_prefixed(&receipt.artifact)?;
    validate_sha256_prefixed(&receipt.inputs_hash)?;
    validate_sha256_prefixed(&receipt.outputs_hash)?;
    validate_sha256_prefixed(&receipt.receipt_hash)?;

    let actual = compute_receipt_hash(
        &receipt.artifact,
        &receipt.inputs_hash,
        &receipt.outputs_hash,
        &receipt.caps_used,
        receipt.timestamp,
    )?;
    if actual != receipt.receipt_hash {
        return Err(VerifyError::DigestMismatch {
            expected: receipt.receipt_hash.clone(),
            actual,
        });
    }
    Ok(())
}

pub fn verify_receipt_v1_draft_hash(receipt: &ExecutionReceiptV1Draft) -> Result<(), VerifyError> {
    validate_sha256_prefixed(&receipt.artifact)?;
    validate_sha256_prefixed(&receipt.manifest_hash)?;
    validate_sha256_prefixed(&receipt.policy_hash)?;
    validate_sha256_prefixed(&receipt.bundle_hash)?;
    validate_sha256_prefixed(&receipt.inputs_hash)?;
    validate_sha256_prefixed(&receipt.outputs_hash)?;
    validate_sha256_prefixed(&receipt.runtime_version_digest)?;
    validate_sha256_prefixed(&receipt.result_digest)?;
    validate_sha256_prefixed(&receipt.receipt_hash)?;

    let actual = compute_receipt_v1_draft_hash(receipt)?;
    if actual != receipt.receipt_hash {
        return Err(VerifyError::DigestMismatch {
            expected: receipt.receipt_hash.clone(),
            actual,
        });
    }
    Ok(())
}

pub fn compute_receipt_hash(
    artifact: &str,
    inputs_hash: &str,
    outputs_hash: &str,
    caps_used: &[String],
    timestamp: u64,
) -> Result<String, VerifyError> {
    let payload = ReceiptHashPayload {
        artifact,
        inputs_hash,
        outputs_hash,
        caps_used,
        timestamp,
    };
    let bytes = to_jcs_bytes(&payload)?;
    Ok(sha256_prefixed(&bytes))
}

pub fn compute_signatures_hash(signatures: &Signatures) -> Result<String, VerifyError> {
    let bytes = to_jcs_bytes(signatures)?;
    Ok(sha256_prefixed(&bytes))
}

pub fn compute_policy_hash(policy: &Policy) -> Result<String, VerifyError> {
    let bytes = to_jcs_bytes(policy)?;
    Ok(sha256_prefixed(&bytes))
}

pub fn compute_bundle_hash(
    artifact: &str,
    manifest_hash: &str,
    signatures: &Signatures,
) -> Result<String, VerifyError> {
    validate_sha256_prefixed(artifact)?;
    validate_sha256_prefixed(manifest_hash)?;
    let signatures_hash = compute_signatures_hash(signatures)?;
    let payload = BundleHashPayload {
        artifact,
        manifest_hash,
        signatures_hash: &signatures_hash,
    };
    let bytes = to_jcs_bytes(&payload)?;
    Ok(sha256_prefixed(&bytes))
}

pub fn compute_runtime_version_digest_v1(runtime: &RuntimeV1Draft) -> Result<String, VerifyError> {
    let bytes = to_jcs_bytes(runtime)?;
    Ok(sha256_prefixed(&bytes))
}

pub fn compute_result_digest_v1(
    result: &ExecutionResultV1Draft,
    outputs_hash: &str,
    caps_used: &[String],
) -> Result<String, VerifyError> {
    validate_sha256_prefixed(outputs_hash)?;
    let payload = ResultDigestPayload {
        status: &result.status,
        code: &result.code,
        outputs_hash,
        caps_used,
    };
    let bytes = to_jcs_bytes(&payload)?;
    Ok(sha256_prefixed(&bytes))
}

pub fn compute_receipt_v1_draft_hash(
    receipt: &ExecutionReceiptV1Draft,
) -> Result<String, VerifyError> {
    let payload = ReceiptV1DraftHashPayload {
        schema_version: &receipt.schema_version,
        artifact: &receipt.artifact,
        manifest_hash: &receipt.manifest_hash,
        policy_hash: &receipt.policy_hash,
        bundle_hash: &receipt.bundle_hash,
        inputs_hash: &receipt.inputs_hash,
        outputs_hash: &receipt.outputs_hash,
        runtime_version_digest: &receipt.runtime_version_digest,
        result_digest: &receipt.result_digest,
        caps_requested: &receipt.caps_requested,
        caps_granted: &receipt.caps_granted,
        caps_used: &receipt.caps_used,
        result: &receipt.result,
        runtime: &receipt.runtime,
        started_at: receipt.started_at,
        finished_at: receipt.finished_at,
        timestamp_strategy: &receipt.timestamp_strategy,
        attestations: receipt.attestations.as_deref(),
    };
    let bytes = to_jcs_bytes(&payload)?;
    Ok(sha256_prefixed(&bytes))
}

pub fn verify_signatures(
    signatures: &Signatures,
    public_keys: &HashMap<String, VerifyingKey>,
) -> Result<(), VerifyError> {
    validate_sha256_prefixed(&signatures.artifact)?;
    validate_sha256_prefixed(&signatures.manifest_hash)?;
    if signatures.signatures.is_empty() {
        return Err(VerifyError::EmptySignatureSet);
    }
    for entry in &signatures.signatures {
        if entry.algorithm != "ed25519" {
            return Err(VerifyError::UnsupportedSignatureAlgorithm(
                entry.algorithm.clone(),
            ));
        }
        let key = public_keys
            .get(&entry.signer)
            .ok_or_else(|| VerifyError::MissingPublicKey(entry.signer.clone()))?;
        let raw = STANDARD
            .decode(entry.signature.as_bytes())
            .map_err(|_| VerifyError::Base64Decode)?;
        let signature = Signature::from_slice(&raw).map_err(|_| VerifyError::SignatureBytes)?;
        key.verify(signatures.manifest_hash.as_bytes(), &signature)
            .map_err(|_| VerifyError::SignatureVerify(entry.signer.clone()))?;
    }
    Ok(())
}

pub fn verify_trusted_signers(
    manifest: &Manifest,
    signatures: &Signatures,
    policy: &Policy,
) -> Result<(), VerifyError> {
    let trusted = &policy.trusted_signers;
    let manifest_signers = manifest
        .signers
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let trusted_signers = trusted.iter().map(String::as_str).collect::<HashSet<_>>();

    if manifest_signers.is_disjoint(&trusted_signers) {
        return Err(VerifyError::UntrustedManifestSigners);
    }

    for entry in &signatures.signatures {
        if !manifest_signers.contains(entry.signer.as_str()) {
            return Err(VerifyError::SignatureSignerNotDeclared(
                entry.signer.clone(),
            ));
        }
    }

    if !signatures.signatures.iter().any(|entry| {
        manifest_signers.contains(entry.signer.as_str())
            && trusted_signers.contains(entry.signer.as_str())
    }) {
        return Err(VerifyError::UntrustedSignatureSet);
    }
    Ok(())
}

pub fn enforce_capability_ceiling(
    capabilities: &[Capability],
    policy: &Policy,
) -> Result<(), VerifyError> {
    for capability in capabilities {
        if !is_capability_allowed(capability, &policy.capability_ceiling) {
            return Err(VerifyError::CapabilityDenied(format!(
                "{}:{}",
                capability.kind, capability.value
            )));
        }
    }
    Ok(())
}

fn to_jcs_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, VerifyError> {
    serde_jcs::to_vec(value).map_err(|_| VerifyError::CanonicalJson)
}

fn validate_sha256_prefixed(value: &str) -> Result<(), VerifyError> {
    if value.len() != 71 || !value.starts_with("sha256:") {
        return Err(VerifyError::InvalidDigestFormat(value.to_string()));
    }
    if !value[7..]
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(VerifyError::InvalidDigestFormat(value.to_string()));
    }
    Ok(())
}

fn validate_md5_hex(value: &str) -> Result<(), VerifyError> {
    if value.len() != 32 {
        return Err(VerifyError::InvalidDigestFormat(value.to_string()));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(VerifyError::InvalidDigestFormat(value.to_string()));
    }
    Ok(())
}

fn validate_json_schema_ref(value: &JsonSchemaRefV1Draft, field: &str) -> Result<(), VerifyError> {
    match value {
        JsonSchemaRefV1Draft::Inline(json) => {
            if !json.is_object() {
                return Err(VerifyError::InvalidDraftField(format!(
                    "{field} inline schema must be a JSON object"
                )));
            }
        }
        JsonSchemaRefV1Draft::Uri(uri) => {
            Url::parse(uri).map_err(|_| {
                VerifyError::InvalidDraftField(format!("{field} URI must be absolute and valid"))
            })?;
        }
    }
    Ok(())
}

fn is_capability_allowed(capability: &Capability, ceiling: &CapabilityCeiling) -> bool {
    match capability.kind.as_str() {
        "fs.read" => {
            let Some(path) = normalize_abs_path(&capability.value) else {
                return false;
            };
            let Some(fs) = &ceiling.fs else {
                return false;
            };
            let Some(prefixes) = &fs.read else {
                return false;
            };
            prefixes.iter().any(|prefix| {
                normalize_abs_path(prefix)
                    .map(|normalized| path_within_prefix(&path, &normalized))
                    .unwrap_or(false)
            })
        }
        "fs.write" => {
            let Some(path) = normalize_abs_path(&capability.value) else {
                return false;
            };
            let Some(fs) = &ceiling.fs else {
                return false;
            };
            let Some(prefixes) = &fs.write else {
                return false;
            };
            prefixes.iter().any(|prefix| {
                normalize_abs_path(prefix)
                    .map(|normalized| path_within_prefix(&path, &normalized))
                    .unwrap_or(false)
            })
        }
        "net" | "net.http" => {
            let Ok(requested) = Url::parse(&capability.value) else {
                return false;
            };
            let Some(prefixes) = &ceiling.net else {
                return false;
            };
            prefixes.iter().any(|prefix| {
                Url::parse(prefix)
                    .ok()
                    .map(|allowed| net_uri_within_prefix(&requested, &allowed))
                    .unwrap_or(false)
            })
        }
        "env" => {
            if !is_valid_env_name(&capability.value) {
                return false;
            }
            let Some(allowed) = &ceiling.env else {
                return false;
            };
            allowed.iter().any(|name| name == &capability.value)
        }
        "exec" => capability.value == "true" && ceiling.exec.unwrap_or(false),
        "exec.safe" => !capability.value.is_empty() && ceiling.exec.unwrap_or(false),
        "time" => capability.value == "true" && ceiling.time.unwrap_or(false),
        "time.now" => !capability.value.is_empty() && ceiling.time.unwrap_or(false),
        "random.bytes" => !capability.value.is_empty() && ceiling.random.unwrap_or(false),
        "kv.read" => {
            let Some(kv) = &ceiling.kv else {
                return false;
            };
            let Some(allowed) = &kv.read else {
                return false;
            };
            allowed
                .iter()
                .any(|item| item == "*" || item == &capability.value)
        }
        "kv.write" => {
            let Some(kv) = &ceiling.kv else {
                return false;
            };
            let Some(allowed) = &kv.write else {
                return false;
            };
            allowed
                .iter()
                .any(|item| item == "*" || item == &capability.value)
        }
        "queue.publish" => {
            let Some(queue) = &ceiling.queue else {
                return false;
            };
            let Some(allowed) = &queue.publish else {
                return false;
            };
            allowed
                .iter()
                .any(|item| item == "*" || item == &capability.value)
        }
        "queue.consume" => {
            let Some(queue) = &ceiling.queue else {
                return false;
            };
            let Some(allowed) = &queue.consume else {
                return false;
            };
            allowed
                .iter()
                .any(|item| item == "*" || item == &capability.value)
        }
        _ => false,
    }
}

fn normalize_abs_path(path: &str) -> Option<String> {
    if !path.starts_with('/') {
        return None;
    }
    let mut normalized = Vec::new();
    for part in path.split('/') {
        if part.is_empty() {
            continue;
        }
        if part == "." || part == ".." {
            return None;
        }
        normalized.push(part);
    }
    if normalized.is_empty() {
        Some("/".to_string())
    } else {
        Some(format!("/{}", normalized.join("/")))
    }
}

fn path_within_prefix(path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return path.starts_with('/');
    }
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn normalize_uri_path(path: &str) -> Option<String> {
    let raw = if path.is_empty() { "/" } else { path };
    normalize_abs_path(raw)
}

fn net_uri_within_prefix(requested: &Url, allowed: &Url) -> bool {
    if !requested.has_authority() || !allowed.has_authority() {
        return false;
    }
    if requested.scheme() != allowed.scheme() {
        return false;
    }
    if requested.host_str() != allowed.host_str() {
        return false;
    }
    if requested.port_or_known_default() != allowed.port_or_known_default() {
        return false;
    }
    if requested.username() != allowed.username() || requested.password() != allowed.password() {
        return false;
    }
    if requested.fragment().is_some() || allowed.query().is_some() || allowed.fragment().is_some() {
        return false;
    }
    let Some(requested_path) = normalize_uri_path(requested.path()) else {
        return false;
    };
    let Some(allowed_path) = normalize_uri_path(allowed.path()) else {
        return false;
    };
    path_within_prefix(&requested_path, &allowed_path)
}

fn is_valid_env_name(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_uppercase()) {
        return false;
    }
    chars.all(|c| c == '_' || c.is_ascii_uppercase() || c.is_ascii_digit())
}

fn validate_policy_constraints(policy: &Policy) -> Result<(), VerifyError> {
    if has_duplicates(&policy.trusted_signers) {
        return Err(VerifyError::PolicyConstraint(
            "trusted_signers must be unique".to_string(),
        ));
    }
    let ceiling = &policy.capability_ceiling;
    if let Some(fs) = &ceiling.fs {
        if let Some(read) = &fs.read {
            if read.iter().any(|path| !path.starts_with('/')) {
                return Err(VerifyError::PolicyConstraint(
                    "capability_ceiling.fs.read items must start with '/'".to_string(),
                ));
            }
            if has_duplicates(read) {
                return Err(VerifyError::PolicyConstraint(
                    "capability_ceiling.fs.read items must be unique".to_string(),
                ));
            }
        }
        if let Some(write) = &fs.write {
            if write.iter().any(|path| !path.starts_with('/')) {
                return Err(VerifyError::PolicyConstraint(
                    "capability_ceiling.fs.write items must start with '/'".to_string(),
                ));
            }
            if has_duplicates(write) {
                return Err(VerifyError::PolicyConstraint(
                    "capability_ceiling.fs.write items must be unique".to_string(),
                ));
            }
        }
    }
    if let Some(net) = &ceiling.net {
        if net.iter().any(|uri| {
            let Ok(parsed) = Url::parse(uri) else {
                return true;
            };
            if !parsed.has_authority() || parsed.query().is_some() || parsed.fragment().is_some() {
                return true;
            }
            normalize_uri_path(parsed.path()).is_none()
        }) {
            return Err(VerifyError::PolicyConstraint(
                "capability_ceiling.net items must be absolute authority URIs without query/fragment and with normalized paths".to_string(),
            ));
        }
        if has_duplicates(net) {
            return Err(VerifyError::PolicyConstraint(
                "capability_ceiling.net items must be unique".to_string(),
            ));
        }
    }
    if let Some(env) = &ceiling.env {
        if env.iter().any(|name| !is_valid_env_name(name)) {
            return Err(VerifyError::PolicyConstraint(
                "capability_ceiling.env items must match ^[A-Z_][A-Z0-9_]*$".to_string(),
            ));
        }
        if has_duplicates(env) {
            return Err(VerifyError::PolicyConstraint(
                "capability_ceiling.env items must be unique".to_string(),
            ));
        }
    }
    if let Some(kv) = &ceiling.kv {
        if let Some(read) = &kv.read {
            if has_duplicates(read) {
                return Err(VerifyError::PolicyConstraint(
                    "capability_ceiling.kv.read items must be unique".to_string(),
                ));
            }
        }
        if let Some(write) = &kv.write {
            if has_duplicates(write) {
                return Err(VerifyError::PolicyConstraint(
                    "capability_ceiling.kv.write items must be unique".to_string(),
                ));
            }
        }
    }
    if let Some(queue) = &ceiling.queue {
        if let Some(publish) = &queue.publish {
            if has_duplicates(publish) {
                return Err(VerifyError::PolicyConstraint(
                    "capability_ceiling.queue.publish items must be unique".to_string(),
                ));
            }
        }
        if let Some(consume) = &queue.consume {
            if has_duplicates(consume) {
                return Err(VerifyError::PolicyConstraint(
                    "capability_ceiling.queue.consume items must be unique".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn has_duplicates(values: &[String]) -> bool {
    let mut seen = HashSet::with_capacity(values.len());
    for value in values {
        if !seen.insert(value) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    #[test]
    fn parses_manifest_json() {
        let raw = br#"{
            "schema_version":"1.0.0-draft",
            "name":"echo",
            "version":"1.0.0",
            "entrypoint":"run",
            "artifact":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "capabilities":[{"kind":"net","value":"https://example.com"}],
            "signers":["alice.dev"]
        }"#;
        let manifest = parse_manifest_json(raw).expect("manifest should parse");
        assert_eq!(manifest.name, "echo");
    }

    #[test]
    fn rejects_manifest_json_with_unknown_field() {
        let raw = br#"{
            "name":"echo",
            "version":"1.0.0",
            "entrypoint":"run",
            "artifact":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "capabilities":[],
            "signers":[],
            "unexpected":"x"
        }"#;
        assert!(matches!(
            parse_manifest_json(raw),
            Err(VerifyError::ManifestJson)
        ));
    }

    #[test]
    fn rejects_manifest_json_with_unsupported_schema_version() {
        let raw = br#"{
            "schema_version":"9.9.9",
            "name":"echo",
            "version":"1.0.0",
            "entrypoint":"run",
            "artifact":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "capabilities":[],
            "signers":[]
        }"#;
        assert!(matches!(
            parse_manifest_json(raw),
            Err(VerifyError::UnsupportedManifestSchemaVersion(_))
        ));
    }

    #[test]
    fn parses_signatures_json() {
        let raw = br#"{
            "artifact":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "manifest_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "signatures":[{"signer":"alice.dev","algorithm":"ed25519","signature":"AA=="}]
        }"#;
        let signatures = parse_signatures_json(raw).expect("signatures should parse");
        assert_eq!(signatures.signatures.len(), 1);
    }

    #[test]
    fn parses_provenance_json() {
        let raw = br#"{
            "source":"https://example.com/repo",
            "commit":"abc123",
            "build_system":"cargo",
            "build_recipe_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }"#;
        let provenance = parse_provenance_json(raw).expect("provenance should parse");
        assert_eq!(provenance.build_system, "cargo");
    }

    #[test]
    fn rejects_provenance_json_with_unknown_field() {
        let raw = br#"{
            "source":"https://example.com/repo",
            "commit":"abc123",
            "build_system":"cargo",
            "build_recipe_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "unexpected":"x"
        }"#;
        assert!(matches!(
            parse_provenance_json(raw),
            Err(VerifyError::ProvenanceJson)
        ));
    }

    #[test]
    fn parses_snapshot_json() {
        let raw = br#"{
            "snapshot_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "timestamp":1,
            "entries":{
                "echo@1.0.0":{
                    "sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "md5":"cccccccccccccccccccccccccccccccc"
                }
            }
        }"#;
        let snapshot = parse_snapshot_json(raw).expect("snapshot should parse");
        assert_eq!(snapshot.entries.len(), 1);
    }

    #[test]
    fn parses_receipt_json() {
        let raw = br#"{
            "artifact":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "inputs_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "outputs_hash":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "caps_used":["net:https://example.com"],
            "timestamp":1,
            "receipt_hash":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        }"#;
        let receipt = parse_receipt_json(raw).expect("receipt should parse");
        assert_eq!(receipt.caps_used.len(), 1);
    }

    #[test]
    fn verifies_artifact_hash() {
        let wasm = b"\0asm";
        let digest = sha256_prefixed(wasm);
        assert!(verify_artifact_hash(wasm, &digest).is_ok());
    }

    #[test]
    fn verifies_registry_entry_artifact_hashes() {
        let bytes = b"hello world";
        let entry = RegistryEntry {
            sha256: sha256_prefixed(bytes),
            md5: md5_hex(bytes),
        };
        assert!(verify_registry_entry_artifact(bytes, &entry).is_ok());
    }

    #[test]
    fn rejects_registry_entry_on_md5_mismatch() {
        let bytes = b"hello world";
        let entry = RegistryEntry {
            sha256: sha256_prefixed(bytes),
            md5: "00000000000000000000000000000000".to_string(),
        };
        assert!(matches!(
            verify_registry_entry_artifact(bytes, &entry),
            Err(VerifyError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn rejects_bad_artifact_hash() {
        let wasm = b"\0asm";
        let bad = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        assert!(matches!(
            verify_artifact_hash(wasm, bad),
            Err(VerifyError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn verifies_snapshot_hash_using_payload_without_snapshot_hash_field() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "echo@1.0.0".to_string(),
            RegistryEntry {
                sha256: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
                md5: "11111111111111111111111111111111".to_string(),
            },
        );

        let payload = SnapshotHashPayload {
            timestamp: 1234,
            entries: &entries,
        };
        let expected = sha256_prefixed(&to_jcs_bytes(&payload).unwrap());

        let snapshot = RegistrySnapshot {
            snapshot_hash: expected,
            timestamp: 1234,
            entries,
        };
        assert!(verify_snapshot_hash(&snapshot).is_ok());
    }

    #[test]
    fn verifies_receipt_hash_using_payload_without_receipt_hash_field() {
        let payload = ReceiptHashPayload {
            artifact: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            inputs_hash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            outputs_hash: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            caps_used: &["net:https://example.com".to_string()],
            timestamp: 42,
        };
        let expected = sha256_prefixed(&to_jcs_bytes(&payload).unwrap());
        let receipt = ExecutionReceipt {
            artifact: payload.artifact.to_string(),
            inputs_hash: payload.inputs_hash.to_string(),
            outputs_hash: payload.outputs_hash.to_string(),
            caps_used: payload.caps_used.to_vec(),
            timestamp: payload.timestamp,
            receipt_hash: expected,
        };
        assert!(verify_receipt_hash(&receipt).is_ok());
    }

    #[test]
    fn verifies_receipt_v1_draft_hash_with_security_digests() {
        let signatures = Signatures {
            artifact: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            manifest_hash:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            signatures: vec![SignatureEntry {
                signer: "alice.dev".to_string(),
                algorithm: "ed25519".to_string(),
                signature: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            }],
        };
        let policy = Policy {
            version: 1,
            trusted_signers: vec!["alice.dev".to_string()],
            capability_ceiling: CapabilityCeiling {
                fs: None,
                net: None,
                kv: None,
                queue: None,
                env: None,
                exec: Some(false),
                time: Some(false),
                random: Some(false),
            },
        };
        let runtime = RuntimeV1Draft {
            name: "provenact-cli".to_string(),
            version: "0.1.0".to_string(),
            profile: Some("wasmtime36-hostabi-v0".to_string()),
        };
        let result = ExecutionResultV1Draft {
            status: "success".to_string(),
            code: "ok".to_string(),
            message: None,
        };
        let caps_used = vec!["env:HOME".to_string()];
        let outputs_hash =
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string();
        let runtime_version_digest = compute_runtime_version_digest_v1(&runtime).unwrap();
        let result_digest = compute_result_digest_v1(&result, &outputs_hash, &caps_used).unwrap();
        let policy_hash = compute_policy_hash(&policy).unwrap();
        let bundle_hash =
            compute_bundle_hash(&signatures.artifact, &signatures.manifest_hash, &signatures)
                .unwrap();

        let mut receipt = ExecutionReceiptV1Draft {
            schema_version: "1.0.0-draft".to_string(),
            artifact: signatures.artifact.clone(),
            manifest_hash: signatures.manifest_hash.clone(),
            policy_hash,
            bundle_hash,
            inputs_hash: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                .to_string(),
            outputs_hash: outputs_hash.clone(),
            runtime_version_digest,
            result_digest,
            caps_requested: vec!["env:HOME".to_string()],
            caps_granted: vec!["env:HOME".to_string()],
            caps_used,
            result,
            runtime,
            started_at: 10,
            finished_at: 11,
            timestamp_strategy: "local_untrusted_unix_seconds".to_string(),
            attestations: None,
            receipt_hash: String::new(),
        };
        receipt.receipt_hash = compute_receipt_v1_draft_hash(&receipt).unwrap();
        assert!(verify_receipt_v1_draft_hash(&receipt).is_ok());
    }

    #[test]
    fn verifies_ed25519_signature_over_manifest_hash_string_bytes() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let artifact = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let manifest_hash =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let sig = signing_key.sign(manifest_hash.as_bytes());
        let signatures = Signatures {
            artifact: artifact.to_string(),
            manifest_hash: manifest_hash.to_string(),
            signatures: vec![SignatureEntry {
                signer: "alice.dev".to_string(),
                algorithm: "ed25519".to_string(),
                signature: STANDARD.encode(sig.to_bytes()),
            }],
        };
        let mut keys = HashMap::new();
        keys.insert("alice.dev".to_string(), verifying_key);

        assert!(verify_signatures(&signatures, &keys).is_ok());
    }

    #[test]
    fn rejects_empty_signature_set() {
        let signatures = Signatures {
            artifact: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            manifest_hash:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            signatures: Vec::new(),
        };
        let keys = HashMap::new();
        assert!(matches!(
            verify_signatures(&signatures, &keys),
            Err(VerifyError::EmptySignatureSet)
        ));
    }

    #[test]
    fn parses_policy_document_from_yaml() {
        let raw = br#"
version: 1
trusted_signers: ["alice.dev"]
capability_ceiling:
  env: ["HOME"]
  exec: false
  time: false
"#;
        let policy = parse_policy_document(raw).expect("policy should parse");
        assert_eq!(policy.version, 1);
        assert_eq!(policy.trusted_signers, vec!["alice.dev".to_string()]);
    }

    #[test]
    fn verifies_trusted_signer_intersection() {
        let manifest = Manifest {
            schema_version: None,
            name: "echo".to_string(),
            version: "1.0.0".to_string(),
            entrypoint: "run".to_string(),
            artifact: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            capabilities: vec![],
            signers: vec!["alice.dev".to_string()],
        };
        let signatures = Signatures {
            artifact: manifest.artifact.clone(),
            manifest_hash:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            signatures: vec![SignatureEntry {
                signer: "alice.dev".to_string(),
                algorithm: "ed25519".to_string(),
                signature: "AA==".to_string(),
            }],
        };
        let policy = Policy {
            version: 1,
            trusted_signers: vec!["alice.dev".to_string()],
            capability_ceiling: CapabilityCeiling {
                fs: None,
                net: None,
                kv: None,
                queue: None,
                env: None,
                exec: Some(false),
                time: Some(false),
                random: Some(false),
            },
        };
        assert!(verify_trusted_signers(&manifest, &signatures, &policy).is_ok());
    }

    #[test]
    fn rejects_signature_signer_not_declared_in_manifest() {
        let manifest = Manifest {
            schema_version: None,
            name: "echo".to_string(),
            version: "1.0.0".to_string(),
            entrypoint: "run".to_string(),
            artifact: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            capabilities: vec![],
            signers: vec!["alice.dev".to_string()],
        };
        let signatures = Signatures {
            artifact: manifest.artifact.clone(),
            manifest_hash:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            signatures: vec![SignatureEntry {
                signer: "mallory.dev".to_string(),
                algorithm: "ed25519".to_string(),
                signature: "AA==".to_string(),
            }],
        };
        let policy = Policy {
            version: 1,
            trusted_signers: vec!["alice.dev".to_string(), "mallory.dev".to_string()],
            capability_ceiling: CapabilityCeiling {
                fs: None,
                net: None,
                kv: None,
                queue: None,
                env: None,
                exec: Some(false),
                time: Some(false),
                random: Some(false),
            },
        };
        assert!(matches!(
            verify_trusted_signers(&manifest, &signatures, &policy),
            Err(VerifyError::SignatureSignerNotDeclared(_))
        ));
    }

    #[test]
    fn rejects_split_trust_between_manifest_and_signatures() {
        let manifest = Manifest {
            schema_version: None,
            name: "echo".to_string(),
            version: "1.0.0".to_string(),
            entrypoint: "run".to_string(),
            artifact: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            capabilities: vec![],
            signers: vec!["alice.dev".to_string(), "bob.dev".to_string()],
        };
        let signatures = Signatures {
            artifact: manifest.artifact.clone(),
            manifest_hash:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            signatures: vec![SignatureEntry {
                signer: "bob.dev".to_string(),
                algorithm: "ed25519".to_string(),
                signature: "AA==".to_string(),
            }],
        };
        let policy = Policy {
            version: 1,
            trusted_signers: vec!["alice.dev".to_string()],
            capability_ceiling: CapabilityCeiling {
                fs: None,
                net: None,
                kv: None,
                queue: None,
                env: None,
                exec: Some(false),
                time: Some(false),
                random: Some(false),
            },
        };
        assert!(matches!(
            verify_trusted_signers(&manifest, &signatures, &policy),
            Err(VerifyError::UntrustedSignatureSet)
        ));
    }

    #[test]
    fn denies_capability_outside_policy_ceiling() {
        let policy = Policy {
            version: 1,
            trusted_signers: vec!["alice.dev".to_string()],
            capability_ceiling: CapabilityCeiling {
                fs: None,
                net: Some(vec!["https://api.example.com".to_string()]),
                kv: None,
                queue: None,
                env: None,
                exec: Some(false),
                time: Some(false),
                random: Some(false),
            },
        };
        let requested = vec![Capability {
            kind: "net".to_string(),
            value: "https://evil.example.com/path".to_string(),
        }];
        assert!(matches!(
            enforce_capability_ceiling(&requested, &policy),
            Err(VerifyError::CapabilityDenied(_))
        ));
    }

    #[test]
    fn denies_net_capability_with_host_prefix_confusion() {
        let policy = Policy {
            version: 1,
            trusted_signers: vec!["alice.dev".to_string()],
            capability_ceiling: CapabilityCeiling {
                fs: None,
                net: Some(vec!["https://api.example.com".to_string()]),
                kv: None,
                queue: None,
                env: None,
                exec: Some(false),
                time: Some(false),
                random: Some(false),
            },
        };
        let requested = vec![Capability {
            kind: "net".to_string(),
            value: "https://api.example.com.evil.tld/v1".to_string(),
        }];
        assert!(matches!(
            enforce_capability_ceiling(&requested, &policy),
            Err(VerifyError::CapabilityDenied(_))
        ));
    }

    #[test]
    fn denies_policy_net_prefix_with_query_or_fragment() {
        let raw = br#"{
          "version": 1,
          "trusted_signers": ["alice.dev"],
          "capability_ceiling": {
            "net": ["https://api.example.com/v1?token=abc"]
          }
        }"#;
        assert!(matches!(
            parse_policy_document(raw),
            Err(VerifyError::PolicyConstraint(_))
        ));
    }
}
