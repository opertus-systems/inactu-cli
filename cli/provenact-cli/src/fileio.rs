use std::fs;
use std::path::Path;

pub fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn read_file_limited(
    path: &Path,
    max_bytes: u64,
    logical_name: &str,
) -> Result<Vec<u8>, String> {
    if let Ok(meta) = fs::metadata(path) {
        if meta.len() > max_bytes {
            return Err(format!(
                "{} exceeds maximum size ({} bytes > {} bytes): {}",
                logical_name,
                meta.len(),
                max_bytes,
                path.display()
            ));
        }
    }
    let bytes = read_file(path)?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!(
            "{} exceeds maximum size ({} bytes > {} bytes): {}",
            logical_name,
            bytes.len(),
            max_bytes,
            path.display()
        ));
    }
    Ok(bytes)
}

pub fn write_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes).map_err(|e| format!("{}: {e}", path.display()))
}
