use std::path::Path;

use provenact_verifier::{
    compute_manifest_hash, parse_manifest_json, parse_signatures_json, verify_artifact_hash,
};

use crate::constants::{MAX_JSON_BYTES, MAX_WASM_BYTES};
use crate::fileio::read_file_limited;

pub struct VerifiedBundle {
    pub wasm: Vec<u8>,
    pub manifest: provenact_verifier::Manifest,
    pub signatures: provenact_verifier::Signatures,
}

pub fn read_manifest_and_signatures(
    bundle_dir: &Path,
) -> Result<(provenact_verifier::Manifest, provenact_verifier::Signatures), String> {
    let manifest_raw = read_file_limited(
        &bundle_dir.join("manifest.json"),
        MAX_JSON_BYTES,
        "manifest.json",
    )?;
    let signatures_raw = read_file_limited(
        &bundle_dir.join("signatures.json"),
        MAX_JSON_BYTES,
        "signatures.json",
    )?;
    let manifest = parse_manifest_json(&manifest_raw).map_err(|e| e.to_string())?;
    let signatures = parse_signatures_json(&signatures_raw).map_err(|e| e.to_string())?;
    Ok((manifest, signatures))
}

pub fn load_verified_bundle(bundle_dir: &Path) -> Result<VerifiedBundle, String> {
    let wasm = read_file_limited(&bundle_dir.join("skill.wasm"), MAX_WASM_BYTES, "skill.wasm")?;
    let (manifest, signatures) = read_manifest_and_signatures(bundle_dir)?;

    if manifest.artifact != signatures.artifact {
        return Err("manifest.artifact must equal signatures.artifact".to_string());
    }
    let manifest_hash = compute_manifest_hash(&manifest).map_err(|e| e.to_string())?;
    if signatures.manifest_hash != manifest_hash {
        return Err("signatures.manifest_hash must equal canonical manifest hash".to_string());
    }
    verify_artifact_hash(&wasm, &manifest.artifact).map_err(|e| e.to_string())?;

    Ok(VerifiedBundle {
        wasm,
        manifest,
        signatures,
    })
}
