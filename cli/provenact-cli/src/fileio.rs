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
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(format!(
                "refusing to write through symlink: {}",
                path.display()
            ))
        }
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(format!("{}: {err}", path.display())),
    }
    fs::write(path, bytes).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_temp_dir(prefix: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        path.push(format!("{prefix}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path).expect("temp dir should be created");
        path
    }

    #[test]
    fn write_file_writes_regular_paths() {
        let dir = test_temp_dir("provenact-fileio-write");
        let path = dir.join("regular.txt");
        write_file(&path, b"hello").expect("regular path write should succeed");
        assert_eq!(fs::read(&path).expect("read"), b"hello");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn write_file_rejects_symlink_targets() {
        let dir = test_temp_dir("provenact-fileio-symlink");
        let target = dir.join("target.txt");
        let link = dir.join("link.txt");
        fs::write(&target, b"original").expect("target write");
        std::os::unix::fs::symlink(&target, &link).expect("symlink create");

        let err = write_file(&link, b"replacement").expect_err("symlink writes must fail");
        assert!(err.contains("refusing to write through symlink"));
        assert_eq!(fs::read(&target).expect("target read"), b"original");
        let _ = fs::remove_dir_all(&dir);
    }
}
