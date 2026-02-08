use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{SigningKey, VerifyingKey};
use provenact_verifier::sha256_prefixed;

pub fn parse_signing_key(bytes: &[u8]) -> Result<SigningKey, String> {
    let trimmed = std::str::from_utf8(bytes)
        .map_err(|e| format!("invalid secret key encoding (utf8): {e}"))?
        .trim();
    let key_bytes = STANDARD
        .decode(trimmed.as_bytes())
        .map_err(|_| "invalid base64 secret key".to_string())?;
    let arr: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "invalid secret key length (expected 32 bytes)".to_string())?;
    Ok(SigningKey::from_bytes(&arr))
}

pub fn parse_public_keys(bytes: &[u8]) -> Result<HashMap<String, VerifyingKey>, String> {
    let raw: HashMap<String, String> =
        serde_json::from_slice(bytes).map_err(|e| format!("invalid keys JSON: {e}"))?;
    let mut out = HashMap::new();
    for (signer, key_b64) in raw {
        let key_bytes = STANDARD
            .decode(key_b64.as_bytes())
            .map_err(|_| format!("invalid base64 key for signer: {signer}"))?;
        let arr: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| format!("invalid key length for signer: {signer}"))?;
        let key = VerifyingKey::from_bytes(&arr)
            .map_err(|_| format!("invalid key bytes for signer: {signer}"))?;
        out.insert(signer, key);
    }
    Ok(out)
}

pub fn verify_keys_digest(keys_raw: &[u8], expected: &str) -> Result<(), String> {
    if !is_valid_sha256_digest(expected) {
        return Err(format!(
            "invalid --keys-digest format (expected sha256:<64 lowercase hex>): {expected}"
        ));
    }
    let actual = sha256_prefixed(keys_raw);
    if actual != expected {
        return Err(format!(
            "public keys digest mismatch (expected {expected}, got {actual})"
        ));
    }
    Ok(())
}

fn is_valid_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}
