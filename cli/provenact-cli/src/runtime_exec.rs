use anyhow::anyhow;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::json;
use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(unix)]
use std::{fs::Permissions, os::unix::fs::PermissionsExt};

use getrandom::fill as random_fill_os;
use provenact_verifier::{sha256_prefixed, Capability};
use url::Url;
use wasmtime::{
    Caller, Config, Engine, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder,
};

use crate::constants::{
    WASM_FUEL_LIMIT, WASM_INSTANCES_LIMIT, WASM_MEMORIES_LIMIT, WASM_MEMORY_LIMIT_BYTES,
    WASM_TABLES_LIMIT, WASM_TABLE_ELEMENTS_LIMIT,
};

struct HostState {
    limits: StoreLimits,
    input: Vec<u8>,
    output: Option<Vec<u8>>,
    capabilities: HashMap<String, Vec<String>>,
    caps_used: BTreeSet<String>,
}

pub struct ExecutionOutcome {
    pub outputs: Vec<u8>,
    pub caps_used: Vec<String>,
}

pub fn execute_wasm(
    wasm: &[u8],
    entrypoint: &str,
    input: &[u8],
    capabilities: &[Capability],
) -> Result<ExecutionOutcome, String> {
    let mut config = Config::new();
    config.consume_fuel(true);
    let engine = Engine::new(&config).map_err(|e| format!("wasm engine init failed: {e}"))?;
    let module =
        Module::from_binary(&engine, wasm).map_err(|e| format!("invalid wasm module: {e}"))?;

    let mut caps_map = HashMap::<String, Vec<String>>::new();
    for cap in capabilities {
        caps_map
            .entry(cap.kind.clone())
            .or_default()
            .push(cap.value.clone());
    }

    let host_state = HostState {
        limits: StoreLimitsBuilder::new()
            .memory_size(WASM_MEMORY_LIMIT_BYTES)
            .table_elements(WASM_TABLE_ELEMENTS_LIMIT)
            .instances(WASM_INSTANCES_LIMIT)
            .tables(WASM_TABLES_LIMIT)
            .memories(WASM_MEMORIES_LIMIT)
            .build(),
        input: input.to_vec(),
        output: None,
        capabilities: caps_map,
        caps_used: BTreeSet::new(),
    };

    let mut store = Store::new(&engine, host_state);
    store.limiter(|state| &mut state.limits);
    store
        .set_fuel(WASM_FUEL_LIMIT)
        .map_err(|e| format!("wasm fuel configuration failed: {e}"))?;

    let mut linker = Linker::new(&engine);
    define_hostcalls(&mut linker).map_err(|e| format!("hostcall registration failed: {e}"))?;

    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| format!("wasm instantiation failed: {e}"))?;

    let result = if let Ok(func) = instance.get_typed_func::<(), i32>(&mut store, entrypoint) {
        let result = func.call(&mut store, ()).map_err(|e| {
            if matches!(store.get_fuel(), Ok(0)) {
                format!("wasm execution failed: fuel exhausted: {e}")
            } else {
                format!("wasm execution failed: {e}")
            }
        })?;
        result.to_string().into_bytes()
    } else if let Ok(func) = instance.get_typed_func::<(), ()>(&mut store, entrypoint) {
        func.call(&mut store, ()).map_err(|e| {
            if matches!(store.get_fuel(), Ok(0)) {
                format!("wasm execution failed: fuel exhausted: {e}")
            } else {
                format!("wasm execution failed: {e}")
            }
        })?;
        Vec::new()
    } else {
        return Err(format!(
            "entrypoint not found with supported signature (() -> i32 | ()) : {entrypoint}"
        ));
    };

    let output = store.data().output.clone().unwrap_or(result);
    let caps_used = store.data().caps_used.iter().cloned().collect::<Vec<_>>();
    Ok(ExecutionOutcome {
        outputs: output,
        caps_used,
    })
}

fn define_hostcalls(linker: &mut Linker<HostState>) -> Result<(), wasmtime::Error> {
    linker.func_wrap(
        "provenact",
        "input_len",
        |caller: Caller<'_, HostState>| -> i32 { caller.data().input.len() as i32 },
    )?;

    linker.func_wrap(
        "provenact",
        "input_read",
        |mut caller: Caller<'_, HostState>, ptr: i32, offset: i32, len: i32| -> i32 {
            if ptr < 0 || offset < 0 || len < 0 {
                return -1;
            }
            let bytes = {
                let state = caller.data();
                let start = offset as usize;
                let end = start.saturating_add(len as usize);
                if end > state.input.len() {
                    return -1;
                }
                state.input[start..end].to_vec()
            };
            write_to_memory(&mut caller, ptr as usize, &bytes).unwrap_or(-1)
        },
    )?;

    linker.func_wrap(
        "provenact",
        "output_write",
        |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| -> i32 {
            if ptr < 0 || len < 0 {
                return -1;
            }
            let Some(bytes) = read_from_memory(&mut caller, ptr as usize, len as usize) else {
                return -1;
            };
            caller.data_mut().output = Some(bytes);
            0
        },
    )?;

    linker.func_wrap(
        "provenact",
        "time_now_unix",
        |mut caller: Caller<'_, HostState>| -> anyhow::Result<i64> {
            require_capability(
                &mut caller,
                "time.now",
                |value| !value.is_empty(),
                "time.now",
            )?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| anyhow!("time error: {e}"))?;
            Ok(now.as_secs() as i64)
        },
    )?;

    linker.func_wrap(
        "provenact",
        "random_fill",
        |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| -> anyhow::Result<i32> {
            require_capability(
                &mut caller,
                "random.bytes",
                |value| !value.is_empty(),
                "random.bytes",
            )?;
            if ptr < 0 || len < 0 {
                return Ok(-1);
            }
            let mut buf = vec![0_u8; len as usize];
            random_fill_os(&mut buf).map_err(|e| anyhow!("random_fill failed: {e}"))?;
            Ok(write_to_memory(&mut caller, ptr as usize, &buf).unwrap_or(-1))
        },
    )?;

    linker.func_wrap(
        "provenact",
        "sha256_input_hex",
        |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| -> i32 {
            if ptr < 0 || len < 0 {
                return -1;
            }
            let digest = sha256_prefixed(&caller.data().input);
            let hex = digest.strip_prefix("sha256:").unwrap_or(&digest);
            let bytes = hex.as_bytes();
            if bytes.len() > len as usize {
                return -1;
            }
            write_to_memory(&mut caller, ptr as usize, bytes).unwrap_or(-1)
        },
    )?;

    linker.func_wrap(
        "provenact",
        "fs_read_file",
        |mut caller: Caller<'_, HostState>,
         path_ptr: i32,
         path_len: i32,
         out_ptr: i32,
         out_len: i32|
         -> anyhow::Result<i32> {
            if path_ptr < 0 || path_len < 0 || out_ptr < 0 || out_len < 0 {
                return Ok(-1);
            }
            let Some(path) =
                read_utf8_from_memory(&mut caller, path_ptr as usize, path_len as usize)
            else {
                return Ok(-1);
            };
            let Some(path_norm) = normalize_abs_path(&path) else {
                return Ok(-1);
            };
            require_fs_path_capability(&mut caller, "fs.read", &path_norm, "fs.read", false)?;
            let data = match fs::read(&path_norm) {
                Ok(v) => v,
                Err(_) => return Ok(-1),
            };
            if data.len() > out_len as usize {
                return Ok(-1);
            }
            Ok(write_to_memory(&mut caller, out_ptr as usize, &data).unwrap_or(-1))
        },
    )?;

    linker.func_wrap(
        "provenact",
        "fs_read_tree",
        |mut caller: Caller<'_, HostState>,
         root_ptr: i32,
         root_len: i32,
         out_ptr: i32,
         out_len: i32|
         -> anyhow::Result<i32> {
            if root_ptr < 0 || root_len < 0 || out_ptr < 0 || out_len < 0 {
                return Ok(-1);
            }
            let Some(root) =
                read_utf8_from_memory(&mut caller, root_ptr as usize, root_len as usize)
            else {
                return Ok(-1);
            };
            let Some(root_norm) = normalize_abs_path(&root) else {
                return Ok(-1);
            };
            require_fs_path_capability(&mut caller, "fs.read", &root_norm, "fs.read", false)?;

            let mut entries = Vec::new();
            collect_tree_entries(Path::new(&root_norm), Path::new(&root_norm), &mut entries)?;
            entries.sort_by(|a, b| {
                let ap = a["path"].as_str().unwrap_or_default();
                let bp = b["path"].as_str().unwrap_or_default();
                ap.cmp(bp)
            });
            let body = json!({
                "root": root_norm,
                "entries": entries,
                "truncated": false
            });
            let encoded =
                serde_json::to_vec(&body).map_err(|e| anyhow!("json encode failed: {e}"))?;
            if encoded.len() > out_len as usize {
                return Ok(-1);
            }
            Ok(write_to_memory(&mut caller, out_ptr as usize, &encoded).unwrap_or(-1))
        },
    )?;

    linker.func_wrap(
        "provenact",
        "fs_write_file",
        |mut caller: Caller<'_, HostState>,
         path_ptr: i32,
         path_len: i32,
         data_ptr: i32,
         data_len: i32|
         -> anyhow::Result<i32> {
            if path_ptr < 0 || path_len < 0 || data_ptr < 0 || data_len < 0 {
                return Ok(-1);
            }
            let Some(path) =
                read_utf8_from_memory(&mut caller, path_ptr as usize, path_len as usize)
            else {
                return Ok(-1);
            };
            let Some(path_norm) = normalize_abs_path(&path) else {
                return Ok(-1);
            };
            require_fs_path_capability(&mut caller, "fs.write", &path_norm, "fs.write", true)?;
            let Some(bytes) = read_from_memory(&mut caller, data_ptr as usize, data_len as usize)
            else {
                return Ok(-1);
            };
            if let Some(parent) = Path::new(&path_norm).parent() {
                if fs::create_dir_all(parent).is_err() {
                    return Ok(-1);
                }
            }
            if secure_write_bytes(Path::new(&path_norm), &bytes).is_err() {
                return Ok(-1);
            }
            Ok(0)
        },
    )?;

    linker.func_wrap(
        "provenact",
        "http_fetch",
        |mut caller: Caller<'_, HostState>,
         url_ptr: i32,
         url_len: i32,
         out_ptr: i32,
         out_len: i32|
         -> anyhow::Result<i32> {
            if url_ptr < 0 || url_len < 0 || out_ptr < 0 || out_len < 0 {
                return Ok(-1);
            }
            let Some(url) = read_utf8_from_memory(&mut caller, url_ptr as usize, url_len as usize)
            else {
                return Ok(-1);
            };
            let requested = match Url::parse(&url) {
                Ok(v) => v,
                Err(_) => return Ok(-1),
            };
            require_capability(
                &mut caller,
                "net.http",
                |value| {
                    Url::parse(value)
                        .map(|allowed| net_uri_within_prefix(&requested, &allowed))
                        .unwrap_or(false)
                },
                "net.http",
            )?;
            let response = match ureq::get(&url).call() {
                Ok(v) => v,
                Err(_) => return Ok(-1),
            };
            let mut body = Vec::new();
            let max = out_len as usize;
            let mut reader = response.into_body().into_reader().take(max as u64);
            if reader.read_to_end(&mut body).is_err() {
                return Ok(-1);
            }
            if body.len() > max {
                return Ok(-1);
            }
            Ok(write_to_memory(&mut caller, out_ptr as usize, &body).unwrap_or(-1))
        },
    )?;

    linker.func_wrap(
        "provenact",
        "kv_put",
        |mut caller: Caller<'_, HostState>,
         key_ptr: i32,
         key_len: i32,
         val_ptr: i32,
         val_len: i32|
         -> anyhow::Result<i32> {
            if key_ptr < 0 || key_len < 0 || val_ptr < 0 || val_len < 0 {
                return Ok(-1);
            }
            let Some(key_bytes) = read_from_memory(&mut caller, key_ptr as usize, key_len as usize)
            else {
                return Ok(-1);
            };
            let key = String::from_utf8_lossy(&key_bytes).to_string();
            require_capability(
                &mut caller,
                "kv.write",
                |value| value == "*" || value == key,
                "kv.put",
            )?;
            let Some(value) = read_from_memory(&mut caller, val_ptr as usize, val_len as usize)
            else {
                return Ok(-1);
            };
            let path = kv_file_path(&key_bytes);
            if let Some(parent) = path.parent() {
                if fs::create_dir_all(parent).is_err() {
                    return Ok(-1);
                }
            }
            if secure_write_bytes(&path, &value).is_err() {
                return Ok(-1);
            }
            Ok(0)
        },
    )?;

    linker.func_wrap(
        "provenact",
        "kv_get",
        |mut caller: Caller<'_, HostState>,
         key_ptr: i32,
         key_len: i32,
         out_ptr: i32,
         out_len: i32|
         -> anyhow::Result<i32> {
            if key_ptr < 0 || key_len < 0 || out_ptr < 0 || out_len < 0 {
                return Ok(-1);
            }
            let Some(key_bytes) = read_from_memory(&mut caller, key_ptr as usize, key_len as usize)
            else {
                return Ok(-1);
            };
            let key = String::from_utf8_lossy(&key_bytes).to_string();
            require_capability(
                &mut caller,
                "kv.read",
                |value| value == "*" || value == key,
                "kv.get",
            )?;
            let data = match fs::read(kv_file_path(&key_bytes)) {
                Ok(v) => v,
                Err(_) => return Ok(-1),
            };
            if data.len() > out_len as usize {
                return Ok(-1);
            }
            Ok(write_to_memory(&mut caller, out_ptr as usize, &data).unwrap_or(-1))
        },
    )?;

    linker.func_wrap(
        "provenact",
        "queue_publish",
        |mut caller: Caller<'_, HostState>,
         topic_ptr: i32,
         topic_len: i32,
         msg_ptr: i32,
         msg_len: i32|
         -> anyhow::Result<i32> {
            if topic_ptr < 0 || topic_len < 0 || msg_ptr < 0 || msg_len < 0 {
                return Ok(-1);
            }
            let Some(topic_bytes) =
                read_from_memory(&mut caller, topic_ptr as usize, topic_len as usize)
            else {
                return Ok(-1);
            };
            let topic = String::from_utf8_lossy(&topic_bytes).to_string();
            require_capability(
                &mut caller,
                "queue.publish",
                |value| value == "*" || value == topic,
                "queue.publish",
            )?;
            let Some(message) = read_from_memory(&mut caller, msg_ptr as usize, msg_len as usize)
            else {
                return Ok(-1);
            };
            let path = queue_file_path(&topic_bytes);
            if let Some(parent) = path.parent() {
                if fs::create_dir_all(parent).is_err() {
                    return Ok(-1);
                }
            }
            if matches!(fs::symlink_metadata(&path), Ok(meta) if meta.file_type().is_symlink()) {
                return Ok(-1);
            }
            let encoded = STANDARD.encode(message);
            let mut file = match OpenOptions::new().create(true).append(true).open(path) {
                Ok(f) => f,
                Err(_) => return Ok(-1),
            };
            if file.write_all(encoded.as_bytes()).is_err() || file.write_all(b"\n").is_err() {
                return Ok(-1);
            }
            Ok(0)
        },
    )?;

    linker.func_wrap(
        "provenact",
        "queue_consume",
        |mut caller: Caller<'_, HostState>,
         topic_ptr: i32,
         topic_len: i32,
         out_ptr: i32,
         out_len: i32|
         -> anyhow::Result<i32> {
            if topic_ptr < 0 || topic_len < 0 || out_ptr < 0 || out_len < 0 {
                return Ok(-1);
            }
            let Some(topic_bytes) =
                read_from_memory(&mut caller, topic_ptr as usize, topic_len as usize)
            else {
                return Ok(-1);
            };
            let topic = String::from_utf8_lossy(&topic_bytes).to_string();
            require_capability(
                &mut caller,
                "queue.consume",
                |value| value == "*" || value == topic,
                "queue.consume",
            )?;
            let path = queue_file_path(&topic_bytes);
            if matches!(fs::symlink_metadata(&path), Ok(meta) if meta.file_type().is_symlink()) {
                return Ok(-1);
            }
            let file = match OpenOptions::new().read(true).open(&path) {
                Ok(f) => f,
                Err(_) => return Ok(-1),
            };
            let reader = BufReader::new(file);
            let mut lines = reader
                .lines()
                .collect::<Result<Vec<_>, _>>()
                .unwrap_or_default();
            if lines.is_empty() {
                return Ok(-1);
            }
            let first = lines.remove(0);
            let payload = match STANDARD.decode(first.as_bytes()) {
                Ok(v) => v,
                Err(_) => return Ok(-1),
            };
            if payload.len() > out_len as usize {
                return Ok(-1);
            }
            let rewritten = if lines.is_empty() {
                String::new()
            } else {
                format!("{}\n", lines.join("\n"))
            };
            if secure_write_bytes(&path, rewritten.as_bytes()).is_err() {
                return Ok(-1);
            }
            Ok(write_to_memory(&mut caller, out_ptr as usize, &payload).unwrap_or(-1))
        },
    )?;

    Ok(())
}

fn get_memory(caller: &mut Caller<'_, HostState>) -> Option<Memory> {
    caller.get_export("memory").and_then(|e| e.into_memory())
}

fn read_from_memory(caller: &mut Caller<'_, HostState>, ptr: usize, len: usize) -> Option<Vec<u8>> {
    let memory = get_memory(caller)?;
    let data = memory.data(caller);
    let end = ptr.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    Some(data[ptr..end].to_vec())
}

fn read_utf8_from_memory(
    caller: &mut Caller<'_, HostState>,
    ptr: usize,
    len: usize,
) -> Option<String> {
    let bytes = read_from_memory(caller, ptr, len)?;
    String::from_utf8(bytes).ok()
}

fn write_to_memory(caller: &mut Caller<'_, HostState>, ptr: usize, bytes: &[u8]) -> Option<i32> {
    let memory = get_memory(caller)?;
    let data = memory.data_mut(caller);
    let end = ptr.checked_add(bytes.len())?;
    if end > data.len() {
        return None;
    }
    data[ptr..end].copy_from_slice(bytes);
    Some(bytes.len() as i32)
}

fn require_capability(
    caller: &mut Caller<'_, HostState>,
    kind: &str,
    matches_value: impl Fn(&str) -> bool,
    used_marker: &str,
) -> anyhow::Result<()> {
    let allowed = caller
        .data()
        .capabilities
        .get(kind)
        .map(|values| values.iter().any(|value| matches_value(value)))
        .unwrap_or(false);
    if !allowed {
        return Err(anyhow!("required capability missing: {kind}"));
    }
    caller.data_mut().caps_used.insert(used_marker.to_string());
    Ok(())
}

fn require_fs_path_capability(
    caller: &mut Caller<'_, HostState>,
    kind: &str,
    requested_path: &str,
    used_marker: &str,
    allow_missing_leaf: bool,
) -> anyhow::Result<()> {
    let allowed = caller
        .data()
        .capabilities
        .get(kind)
        .map(|values| {
            values.iter().any(|value| {
                let Some(prefix) = normalize_abs_path(value) else {
                    return false;
                };
                if !path_within_prefix(requested_path, &prefix) {
                    return false;
                }
                path_within_resolved_prefix(
                    Path::new(requested_path),
                    Path::new(&prefix),
                    allow_missing_leaf,
                )
            })
        })
        .unwrap_or(false);
    if !allowed {
        return Err(anyhow!("required capability missing: {kind}"));
    }
    caller.data_mut().caps_used.insert(used_marker.to_string());
    Ok(())
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

fn path_within_resolved_prefix(path: &Path, prefix: &Path, allow_missing_leaf: bool) -> bool {
    let Some(path_real) = resolve_path_for_comparison(path, allow_missing_leaf) else {
        return false;
    };
    let Some(prefix_real) = resolve_path_for_comparison(prefix, true) else {
        return false;
    };
    path_real == prefix_real || path_real.starts_with(&prefix_real)
}

fn resolve_path_for_comparison(path: &Path, allow_missing_leaf: bool) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    if let Ok(canonical) = fs::canonicalize(path) {
        return Some(canonical);
    }
    if !allow_missing_leaf {
        return None;
    }

    let mut current = path;
    let mut suffix = Vec::<std::ffi::OsString>::new();
    loop {
        if fs::metadata(current).is_ok() {
            break;
        }
        let name = current.file_name()?;
        suffix.push(name.to_os_string());
        current = current.parent()?;
    }
    let mut resolved = fs::canonicalize(current).ok()?;
    for segment in suffix.iter().rev() {
        resolved.push(segment);
    }
    Some(resolved)
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

fn kv_root() -> PathBuf {
    env::var("PROVENACT_KV_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_runtime_subdir("kv"))
}

fn kv_file_path(key: &[u8]) -> PathBuf {
    let digest = sha256_prefixed(key);
    let suffix = digest.strip_prefix("sha256:").unwrap_or(&digest);
    kv_root().join(format!("{suffix}.bin"))
}

fn queue_root() -> PathBuf {
    env::var("PROVENACT_QUEUE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_runtime_subdir("queue"))
}

fn queue_file_path(topic: &[u8]) -> PathBuf {
    let digest = sha256_prefixed(topic);
    let suffix = digest.strip_prefix("sha256:").unwrap_or(&digest);
    queue_root().join(format!("{suffix}.log"))
}

fn default_runtime_subdir(name: &str) -> PathBuf {
    if let Ok(home) = env::var("HOME") {
        return PathBuf::from(home).join(".provenact/runtime").join(name);
    }
    PathBuf::from(".provenact-runtime").join(name)
}

fn secure_write_bytes(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            let _ = fs::set_permissions(parent, Permissions::from_mode(0o700));
        }
    }
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::other("refusing to write through symlink"));
        }
    }
    let mut temp = path.to_path_buf();
    temp.set_extension("tmp");
    if let Ok(meta) = fs::symlink_metadata(&temp) {
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::other(
                "refusing to write through symlink temp path",
            ));
        }
    }
    fs::write(&temp, bytes)?;
    fs::rename(temp, path)?;
    Ok(())
}

fn collect_tree_entries(
    root: &Path,
    current: &Path,
    out: &mut Vec<serde_json::Value>,
) -> anyhow::Result<()> {
    let mut children = fs::read_dir(current)
        .map_err(|e| anyhow!("read_dir failed for {}: {e}", current.display()))?
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    children.sort_by_key(|a| a.file_name());

    for child in children {
        let path = child.path();
        let meta = fs::symlink_metadata(&path)
            .map_err(|e| anyhow!("metadata failed for {}: {e}", path.display()))?;
        if meta.file_type().is_symlink() {
            continue;
        }
        let rel = match path.strip_prefix(root) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        if meta.is_dir() {
            out.push(json!({
                "path": rel_str,
                "kind": "dir"
            }));
            collect_tree_entries(root, &path, out)?;
        } else if meta.is_file() {
            out.push(json!({
                "path": rel_str,
                "kind": "file",
                "bytes": meta.len()
            }));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use wat::parse_str;

    #[cfg(unix)]
    fn make_test_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("provenact-{name}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).expect("temp dir should be created");
        path
    }

    #[cfg(unix)]
    fn fs_read_test_wasm() -> Vec<u8> {
        parse_str(
            r#"(module
  (import "provenact" "input_len" (func $input_len (result i32)))
  (import "provenact" "input_read" (func $input_read (param i32 i32 i32) (result i32)))
  (import "provenact" "fs_read_file" (func $fs_read_file (param i32 i32 i32 i32) (result i32)))
  (import "provenact" "output_write" (func $output_write (param i32 i32) (result i32)))
  (memory (export "memory") 2)
  (func (export "run") (result i32)
    (local $path_len i32)
    (local $n i32)
    call $input_len
    local.set $path_len
    i32.const 0
    i32.const 0
    local.get $path_len
    call $input_read
    drop
    i32.const 0
    local.get $path_len
    i32.const 2048
    i32.const 65536
    call $fs_read_file
    local.set $n
    local.get $n
    i32.const 0
    i32.lt_s
    if
      i32.const 1
      return
    end
    i32.const 2048
    local.get $n
    call $output_write
    drop
    i32.const 0
  )
)"#,
        )
        .expect("wat should compile")
    }

    #[test]
    #[cfg(unix)]
    fn fs_read_allows_normal_path_inside_capability_prefix() {
        let root = make_test_dir("fs-read-allow");
        let allowed = root.join("allowed");
        fs::create_dir_all(&allowed).expect("allowed dir should exist");
        let file = allowed.join("ok.txt");
        fs::write(&file, b"ok").expect("file write should succeed");

        let wasm = fs_read_test_wasm();
        let capabilities = vec![Capability {
            kind: "fs.read".to_string(),
            value: allowed.to_string_lossy().to_string(),
        }];
        let input = file.to_string_lossy().to_string().into_bytes();
        let outcome = execute_wasm(&wasm, "run", &input, &capabilities).expect("wasm should run");
        assert_eq!(outcome.outputs, b"ok");
    }

    #[test]
    #[cfg(unix)]
    fn fs_read_rejects_symlink_escape_even_when_prefix_matches_lexically() {
        use std::os::unix::fs::symlink;

        let root = make_test_dir("fs-read-symlink-deny");
        let allowed = root.join("allowed");
        fs::create_dir_all(&allowed).expect("allowed dir should exist");

        let secret = root.join("secret.txt");
        fs::write(&secret, b"TOP-SECRET-SYMLINK-ESCAPE").expect("secret file write should succeed");
        symlink(&root, allowed.join("link")).expect("symlink should be created");

        let escape_path = allowed.join("link").join("secret.txt");
        let wasm = fs_read_test_wasm();
        let capabilities = vec![Capability {
            kind: "fs.read".to_string(),
            value: allowed.to_string_lossy().to_string(),
        }];
        let input = escape_path.to_string_lossy().to_string().into_bytes();
        let result = execute_wasm(&wasm, "run", &input, &capabilities);
        assert!(result.is_err(), "symlink escape should be denied");
    }
}
