use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::{sha256_prefixed, VerifyError};

pub const SKILL_MANIFEST_V0_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../spec/v0/skill-manifest.schema.json"
));

pub const PIPELINE_DAG_V0_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../spec/v0/pipeline-dag.schema.json"
));

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillManifestV0 {
    pub schema_version: String,
    pub skill_id: String,
    pub version: String,
    pub entrypoint: EntrypointV0,
    pub description: String,
    pub inputs: IoDescriptorV0,
    pub outputs: IoDescriptorV0,
    pub caps: Vec<CapabilityRequestV0>,
    pub limits: LimitsV0,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supply_chain: Option<SupplyChainV0>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntrypointV0 {
    pub wasm: String,
    pub wasi: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IoDescriptorV0 {
    pub content_type: String,
    pub json_schema: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRequestV0 {
    pub name: String,
    pub required: bool,
    pub constraints: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsV0 {
    pub cpu_ms: u64,
    pub mem_mb: u64,
    pub io_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainV0 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sbom: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signatures: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineDagV0 {
    pub schema_version: String,
    pub pipeline_id: String,
    pub nodes: Vec<PipelineNodeV0>,
    pub edges: Vec<PipelineEdgeV0>,
    pub input_mapping: Vec<InputMappingRuleV0>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_limits: Option<ResourceLimitsV0>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_cap_sets: Option<BTreeMap<String, Vec<String>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_policy: Option<RunPolicyV0>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineNodeV0 {
    pub id: String,
    pub skill: SkillRefV0,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_caps: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<ResourceLimitsV0>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SkillRefV0 {
    Name(String),
    Pinned(PinnedSkillRefV0),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedSkillRefV0 {
    pub hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineEdgeV0 {
    pub from: String,
    pub to: String,
    pub map: Vec<MappingRuleV0>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MappingRuleV0 {
    pub from_path: String,
    pub to_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputMappingRuleV0 {
    pub from: String,
    pub from_path: String,
    pub to: String,
    pub to_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimitsV0 {
    pub cpu_ms: u64,
    pub mem_mb: u64,
    pub io_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunPolicyV0 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_network_after_nodes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction: Option<RedactionPolicyV0>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionPolicyV0 {
    pub mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapGrantV0 {
    pub name: String,
    #[serde(default)]
    pub constraints: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ResolvedCapV0 {
    pub name: String,
    pub handle: String,
    pub constraints: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRecordV0 {
    pub ts: String,
    pub run_id: String,
    pub node_id: String,
    pub r#type: String,
    pub data: serde_json::Value,
    pub integrity: EventIntegrityV0,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventIntegrityV0 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
    pub hash: String,
}

#[derive(Debug, Serialize)]
struct EventHashPayloadV0<'a> {
    prev_hash: Option<&'a str>,
    ts: &'a str,
    run_id: &'a str,
    node_id: &'a str,
    r#type: &'a str,
    data: &'a serde_json::Value,
}

pub fn parse_skill_manifest_v0_json(bytes: &[u8]) -> Result<SkillManifestV0, VerifyError> {
    let manifest: SkillManifestV0 =
        serde_json::from_slice(bytes).map_err(|_| VerifyError::InvalidV0SkillManifest {
            reason: "invalid manifest JSON".to_string(),
        })?;

    if manifest.schema_version != "v0" {
        return Err(VerifyError::InvalidV0SkillManifest {
            reason: "schema_version must be v0".to_string(),
        });
    }
    if manifest.skill_id.trim().is_empty() {
        return Err(VerifyError::InvalidV0SkillManifest {
            reason: "skill_id must be non-empty".to_string(),
        });
    }
    if manifest.version.trim().is_empty() {
        return Err(VerifyError::InvalidV0SkillManifest {
            reason: "version must be non-empty".to_string(),
        });
    }
    if manifest.entrypoint.wasm.trim().is_empty() {
        return Err(VerifyError::InvalidV0SkillManifest {
            reason: "entrypoint.wasm must be non-empty".to_string(),
        });
    }
    if manifest.entrypoint.wasi != "preview2" {
        return Err(VerifyError::InvalidV0SkillManifest {
            reason: "entrypoint.wasi must be preview2".to_string(),
        });
    }
    if manifest.description.trim().is_empty() {
        return Err(VerifyError::InvalidV0SkillManifest {
            reason: "description must be non-empty".to_string(),
        });
    }
    for io in [&manifest.inputs, &manifest.outputs] {
        if io.content_type.trim().is_empty() {
            return Err(VerifyError::InvalidV0SkillManifest {
                reason: "io.content_type must be non-empty".to_string(),
            });
        }
        if !io.json_schema.is_object() {
            return Err(VerifyError::InvalidV0SkillManifest {
                reason: "io.json_schema must be a JSON object".to_string(),
            });
        }
    }
    for cap in &manifest.caps {
        if cap.name.trim().is_empty() {
            return Err(VerifyError::InvalidV0SkillManifest {
                reason: "cap.name must be non-empty".to_string(),
            });
        }
        if !cap.constraints.is_object() {
            return Err(VerifyError::InvalidV0SkillManifest {
                reason: "cap.constraints must be an object".to_string(),
            });
        }
    }
    if manifest.limits.cpu_ms == 0 || manifest.limits.mem_mb == 0 || manifest.limits.io_bytes == 0 {
        return Err(VerifyError::InvalidV0SkillManifest {
            reason: "limits fields must be greater than zero".to_string(),
        });
    }
    if let Some(supply_chain) = &manifest.supply_chain {
        if let Some(sbom) = &supply_chain.sbom {
            if sbom.trim().is_empty() {
                return Err(VerifyError::InvalidV0SkillManifest {
                    reason: "supply_chain.sbom must be non-empty when present".to_string(),
                });
            }
        }
        if let Some(signatures) = &supply_chain.signatures {
            if signatures.is_empty() || signatures.iter().any(|sig| sig.trim().is_empty()) {
                return Err(VerifyError::InvalidV0SkillManifest {
                    reason: "supply_chain.signatures must contain non-empty values".to_string(),
                });
            }
        }
    }

    Ok(manifest)
}

pub fn parse_pipeline_v0_json(bytes: &[u8]) -> Result<PipelineDagV0, VerifyError> {
    let pipeline: PipelineDagV0 =
        serde_json::from_slice(bytes).map_err(|_| VerifyError::InvalidV0Pipeline {
            reason: "invalid pipeline JSON".to_string(),
        })?;

    if pipeline.schema_version != "v0" {
        return Err(VerifyError::InvalidV0Pipeline {
            reason: "schema_version must be v0".to_string(),
        });
    }
    if pipeline.pipeline_id.trim().is_empty() {
        return Err(VerifyError::InvalidV0Pipeline {
            reason: "pipeline_id must be non-empty".to_string(),
        });
    }
    if pipeline.nodes.is_empty() {
        return Err(VerifyError::InvalidV0Pipeline {
            reason: "nodes must be non-empty".to_string(),
        });
    }

    let mut node_ids = HashSet::new();
    for node in &pipeline.nodes {
        if node.id.trim().is_empty() {
            return Err(VerifyError::InvalidV0Pipeline {
                reason: "node.id must be non-empty".to_string(),
            });
        }
        if !node_ids.insert(node.id.as_str()) {
            return Err(VerifyError::InvalidV0Pipeline {
                reason: format!("duplicate node.id: {}", node.id),
            });
        }
        match &node.skill {
            SkillRefV0::Name(skill) => {
                if !is_sha256_prefixed_digest(skill) {
                    return Err(VerifyError::InvalidV0Pipeline {
                        reason: format!("node {} has invalid skill hash", node.id),
                    });
                }
            }
            SkillRefV0::Pinned(pinned) => {
                if !is_sha256_prefixed_digest(&pinned.hash) {
                    return Err(VerifyError::InvalidV0Pipeline {
                        reason: format!("node {} has invalid skill hash", node.id),
                    });
                }
                if let Some(source) = pinned.source.as_deref() {
                    if source.trim().is_empty() {
                        return Err(VerifyError::InvalidV0Pipeline {
                            reason: format!("node {} has empty skill source", node.id),
                        });
                    }
                }
            }
        }
        if let Some(on_error) = &node.on_error {
            if on_error != "abort" && on_error != "skip" {
                return Err(VerifyError::InvalidV0Pipeline {
                    reason: format!("node {} has unsupported on_error", node.id),
                });
            }
        }
        if let Some(input) = &node.input {
            if !input.is_object() {
                return Err(VerifyError::InvalidV0Pipeline {
                    reason: format!("node {} input must be an object", node.id),
                });
            }
        }
        if let Some(requested_caps) = &node.requested_caps {
            if requested_caps.is_empty()
                || requested_caps
                    .iter()
                    .any(|capability| capability.trim().is_empty())
            {
                return Err(VerifyError::InvalidV0Pipeline {
                    reason: format!("node {} has invalid requested_caps", node.id),
                });
            }
        }
        if let Some(limits) = &node.limits {
            validate_resource_limits(limits, &format!("node {} limits", node.id))?;
        }
    }

    let mut inbound_count = HashMap::new();
    let mut adjacency = HashMap::<&str, Vec<&str>>::new();

    for edge in &pipeline.edges {
        if !node_ids.contains(edge.from.as_str()) {
            return Err(VerifyError::InvalidV0Pipeline {
                reason: format!("edge.from references unknown node: {}", edge.from),
            });
        }
        if !node_ids.contains(edge.to.as_str()) {
            return Err(VerifyError::InvalidV0Pipeline {
                reason: format!("edge.to references unknown node: {}", edge.to),
            });
        }
        if edge.map.is_empty() {
            return Err(VerifyError::InvalidV0Pipeline {
                reason: "edge.map must be non-empty".to_string(),
            });
        }
        for rule in &edge.map {
            if !is_json_path_subset(&rule.from_path) {
                return Err(VerifyError::InvalidV0Pipeline {
                    reason: format!("unsupported from_path: {}", rule.from_path),
                });
            }
            if !is_json_path_subset(&rule.to_path) {
                return Err(VerifyError::InvalidV0Pipeline {
                    reason: format!("unsupported to_path: {}", rule.to_path),
                });
            }
        }

        adjacency
            .entry(edge.from.as_str())
            .or_default()
            .push(edge.to.as_str());
        *inbound_count.entry(edge.to.as_str()).or_insert(0usize) += 1;
    }

    for rule in &pipeline.input_mapping {
        if rule.from != "input" && rule.from != "context" {
            return Err(VerifyError::InvalidV0Pipeline {
                reason: "input_mapping.from must be input or context".to_string(),
            });
        }
        if !is_json_path_subset(&rule.from_path) {
            return Err(VerifyError::InvalidV0Pipeline {
                reason: format!("unsupported input_mapping.from_path: {}", rule.from_path),
            });
        }
        if !node_ids.contains(rule.to.as_str()) {
            return Err(VerifyError::InvalidV0Pipeline {
                reason: format!("input_mapping.to references unknown node: {}", rule.to),
            });
        }
        if !is_json_path_subset(&rule.to_path) {
            return Err(VerifyError::InvalidV0Pipeline {
                reason: format!("unsupported input_mapping.to_path: {}", rule.to_path),
            });
        }
    }

    if let Some(limits) = &pipeline.resource_limits {
        validate_resource_limits(limits, "resource_limits")?;
    }
    if let Some(required_cap_sets) = &pipeline.required_cap_sets {
        if required_cap_sets.is_empty() {
            return Err(VerifyError::InvalidV0Pipeline {
                reason: "required_cap_sets must be non-empty when present".to_string(),
            });
        }
        for (set_name, caps) in required_cap_sets {
            if set_name.trim().is_empty()
                || caps.is_empty()
                || caps.iter().any(|capability| capability.trim().is_empty())
            {
                return Err(VerifyError::InvalidV0Pipeline {
                    reason: "required_cap_sets entries must use non-empty names and capabilities"
                        .to_string(),
                });
            }
        }
    }

    if let Some(policy) = &pipeline.run_policy {
        if let Some(no_net_after) = &policy.no_network_after_nodes {
            for node in no_net_after {
                if !node_ids.contains(node.as_str()) {
                    return Err(VerifyError::InvalidV0Pipeline {
                        reason: format!(
                            "run_policy.no_network_after_nodes references unknown node: {node}"
                        ),
                    });
                }
            }
        }
        if let Some(max_total_bytes) = policy.max_total_bytes {
            if max_total_bytes == 0 {
                return Err(VerifyError::InvalidV0Pipeline {
                    reason: "run_policy.max_total_bytes must be greater than zero".to_string(),
                });
            }
        }
        if let Some(redaction) = &policy.redaction {
            if redaction.mode != "strict" && redaction.mode != "permissive" {
                return Err(VerifyError::InvalidV0Pipeline {
                    reason: "run_policy.redaction.mode must be strict or permissive".to_string(),
                });
            }
        }
    }

    // Kahn topological check for acyclic DAG.
    let mut queue = VecDeque::new();
    for node in &pipeline.nodes {
        if !inbound_count.contains_key(node.id.as_str()) {
            queue.push_back(node.id.as_str());
        }
    }

    let mut visited = 0usize;
    while let Some(node_id) = queue.pop_front() {
        visited += 1;
        if let Some(children) = adjacency.get(node_id) {
            for child in children {
                let counter = inbound_count
                    .get_mut(child)
                    .expect("child should have inbound edge count");
                *counter -= 1;
                if *counter == 0 {
                    queue.push_back(child);
                }
            }
        }
    }
    if visited != pipeline.nodes.len() {
        return Err(VerifyError::InvalidV0Pipeline {
            reason: "pipeline contains a cycle".to_string(),
        });
    }

    Ok(pipeline)
}

pub fn resolve_effective_caps_v0(
    requested: &[CapabilityRequestV0],
    org_policy: &[CapGrantV0],
    run_policy: &[CapGrantV0],
) -> Result<Vec<ResolvedCapV0>, VerifyError> {
    let org_by_name = policy_by_name(org_policy);
    let run_by_name = policy_by_name(run_policy);

    let mut resolved = Vec::new();
    for (index, cap) in requested.iter().enumerate() {
        let org = org_by_name.get(cap.name.as_str());
        let run = run_by_name.get(cap.name.as_str());

        if org.is_none() || run.is_none() {
            if cap.required {
                return Err(VerifyError::MissingRequiredCapabilityV0(cap.name.clone()));
            }
            continue;
        }

        let constraints = combine_constraints_stub(
            &cap.constraints,
            &org.expect("checked is_some").constraints,
            &run.expect("checked is_some").constraints,
        );

        resolved.push(ResolvedCapV0 {
            name: cap.name.clone(),
            handle: format!("cap:{}:{}", cap.name, index),
            constraints,
        });
    }

    Ok(resolved)
}

pub fn compute_event_hash_v0(
    prev_hash: Option<&str>,
    ts: &str,
    run_id: &str,
    node_id: &str,
    event_type: &str,
    data: &serde_json::Value,
) -> Result<String, VerifyError> {
    let payload = EventHashPayloadV0 {
        prev_hash,
        ts,
        run_id,
        node_id,
        r#type: event_type,
        data,
    };
    let bytes = serde_jcs::to_vec(&payload).map_err(|_| VerifyError::CanonicalJson)?;
    Ok(sha256_prefixed(&bytes))
}

pub fn verify_event_chain_v0(events: &[EventRecordV0]) -> Result<(), VerifyError> {
    let mut prev = None;

    for (idx, event) in events.iter().enumerate() {
        if event.integrity.prev_hash.as_deref() != prev.as_deref() {
            return Err(VerifyError::EventChainViolationV0 {
                reason: format!("event {idx} prev_hash does not match chain head"),
            });
        }

        let expected = compute_event_hash_v0(
            event.integrity.prev_hash.as_deref(),
            &event.ts,
            &event.run_id,
            &event.node_id,
            &event.r#type,
            &event.data,
        )?;

        if expected != event.integrity.hash {
            return Err(VerifyError::EventChainViolationV0 {
                reason: format!("event {idx} hash mismatch"),
            });
        }

        prev = Some(event.integrity.hash.clone());
    }

    Ok(())
}

fn policy_by_name(items: &[CapGrantV0]) -> BTreeMap<&str, &CapGrantV0> {
    let mut map = BTreeMap::new();
    for item in items {
        map.insert(item.name.as_str(), item);
    }
    map
}

fn combine_constraints_stub(
    requested: &serde_json::Value,
    org: &serde_json::Value,
    run: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "requested": requested,
        "org_policy": org,
        "run_policy": run
    })
}

fn is_json_path_subset(path: &str) -> bool {
    let Some(tail) = path.strip_prefix("$.") else {
        return false;
    };
    if tail.is_empty() {
        return false;
    }
    tail.split('.').all(|segment| {
        !segment.is_empty()
            && segment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

fn validate_resource_limits(limits: &ResourceLimitsV0, field: &str) -> Result<(), VerifyError> {
    if limits.cpu_ms == 0 || limits.mem_mb == 0 || limits.io_bytes == 0 {
        return Err(VerifyError::InvalidV0Pipeline {
            reason: format!("{field} must have cpu_ms/mem_mb/io_bytes > 0"),
        });
    }
    if limits.timeout_ms.is_some_and(|value| value == 0) {
        return Err(VerifyError::InvalidV0Pipeline {
            reason: format!("{field}.timeout_ms must be greater than zero"),
        });
    }
    Ok(())
}

fn is_sha256_prefixed_digest(value: &str) -> bool {
    if value.len() != 71 || !value.starts_with("sha256:") {
        return false;
    }
    value[7..]
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}
