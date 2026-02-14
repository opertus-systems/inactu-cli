use anyhow::anyhow;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::json;
use std::collections::{BTreeSet, HashMap};
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use getrandom::fill as random_fill_os;
use provenact_verifier::{sha256_prefixed, Capability};
use url::Url;
use wasmtime::{
    Caller, Config, Engine, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder,
};

use crate::constants::{
    MAX_FS_TREE_ENTRIES, MAX_FS_TREE_TOTAL_BYTES, MAX_HOSTCALL_COPY_BYTES, MAX_KV_VALUE_BYTES,
    MAX_QUEUE_FILE_BYTES, MAX_QUEUE_MESSAGE_BYTES, WASM_FUEL_LIMIT, WASM_INSTANCES_LIMIT,
    WASM_MEMORIES_LIMIT, WASM_MEMORY_LIMIT_BYTES, WASM_TABLES_LIMIT, WASM_TABLE_ELEMENTS_LIMIT,
};

const PATH_LOCK_RETRIES: usize = 50;
const PATH_LOCK_RETRY_DELAY_MS: u64 = 10;
const PATH_LOCK_STALE_SECS: u64 = 120;
const HTTP_CONNECT_TIMEOUT_SECS: u64 = 5;
const HTTP_TOTAL_TIMEOUT_SECS: u64 = 10;
const SAFE_WRITE_TEMP_ATTEMPTS: usize = 16;

static SAFE_WRITE_NONCE: AtomicU64 = AtomicU64::new(0);

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
            let Some(fill_len) = bounded_guest_len(len, MAX_HOSTCALL_COPY_BYTES) else {
                return Ok(-1);
            };
            let mut buf = vec![0_u8; fill_len];
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
            let path_buf = PathBuf::from(&path_norm);
            let Some(path_resolved) = resolve_path_for_prefix_check(&path_buf, false) else {
                return Ok(-1);
            };
            let Some(max_output) = bounded_guest_out_len(out_len) else {
                return Ok(-1);
            };
            require_capability(
                &mut caller,
                "fs.read",
                |value| {
                    normalize_abs_path(value)
                        .and_then(|p| {
                            resolve_path_for_prefix_check(Path::new(&p), true)
                                .map(|prefix| path_buf_within_prefix(&path_resolved, &prefix))
                        })
                        .unwrap_or(false)
                },
                "fs.read",
            )?;
            let Some(data) = read_file_bytes_capped(&path_resolved, max_output) else {
                return Ok(-1);
            };
            if data.len() > max_output {
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
            let root_buf = PathBuf::from(&root_norm);
            let Some(root_resolved) = resolve_path_for_prefix_check(&root_buf, false) else {
                return Ok(-1);
            };
            let Some(max_output) = bounded_guest_out_len(out_len) else {
                return Ok(-1);
            };
            if !root_resolved.is_dir() {
                return Ok(-1);
            }
            require_capability(
                &mut caller,
                "fs.read",
                |value| {
                    normalize_abs_path(value)
                        .and_then(|p| {
                            resolve_path_for_prefix_check(Path::new(&p), true)
                                .map(|prefix| path_buf_within_prefix(&root_resolved, &prefix))
                        })
                        .unwrap_or(false)
                },
                "fs.read",
            )?;

            let mut entries = Vec::new();
            let mut state = TreeCollectionState::default();
            collect_tree_entries(&root_resolved, &root_resolved, &mut entries, &mut state)?;
            entries.sort_by(|a, b| {
                let ap = a["path"].as_str().unwrap_or_default();
                let bp = b["path"].as_str().unwrap_or_default();
                ap.cmp(bp)
            });
            let body = json!({
                "root": root_norm,
                "entries": entries,
                "truncated": state.truncated
            });
            let encoded =
                serde_json::to_vec(&body).map_err(|e| anyhow!("json encode failed: {e}"))?;
            if encoded.len() > max_output {
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
            let path_buf = PathBuf::from(&path_norm);
            let Some(path_resolved) = resolve_path_for_prefix_check(&path_buf, true) else {
                return Ok(-1);
            };
            require_capability(
                &mut caller,
                "fs.write",
                |value| {
                    normalize_abs_path(value)
                        .and_then(|p| {
                            resolve_path_for_prefix_check(Path::new(&p), true)
                                .map(|prefix| path_buf_within_prefix(&path_resolved, &prefix))
                        })
                        .unwrap_or(false)
                },
                "fs.write",
            )?;
            let Some(bytes) = read_from_memory(&mut caller, data_ptr as usize, data_len as usize)
            else {
                return Ok(-1);
            };
            let Some(parent) = path_resolved.parent() else {
                return Ok(-1);
            };
            if fs::create_dir_all(parent).is_err() {
                return Ok(-1);
            }
            let canonical_parent = match fs::canonicalize(parent) {
                Ok(value) => value,
                Err(_) => return Ok(-1),
            };
            let Some(file_name) = path_resolved.file_name() else {
                return Ok(-1);
            };
            let final_path = canonical_parent.join(file_name);
            require_capability(
                &mut caller,
                "fs.write",
                |value| {
                    normalize_abs_path(value)
                        .and_then(|p| {
                            resolve_path_for_prefix_check(Path::new(&p), true)
                                .map(|prefix| path_buf_within_prefix(&final_path, &prefix))
                        })
                        .unwrap_or(false)
                },
                "fs.write",
            )?;
            if write_file_replace_symlink_safe(&final_path, &bytes).is_err() {
                return Ok(-1);
            };
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
            let agent: ureq::Agent = ureq::Agent::config_builder()
                .timeout_connect(Some(Duration::from_secs(HTTP_CONNECT_TIMEOUT_SECS)))
                .timeout_global(Some(Duration::from_secs(HTTP_TOTAL_TIMEOUT_SECS)))
                // Capability checks are evaluated against the requested URL only.
                // Disallow redirects to prevent cross-origin/path bypass.
                .max_redirects(0)
                .build()
                .into();
            let response = match agent.get(&url).call() {
                Ok(v) => v,
                Err(_) => return Ok(-1),
            };
            if response.status().is_redirection() {
                return Ok(-1);
            }
            let Some(max_output) = bounded_guest_out_len(out_len) else {
                return Ok(-1);
            };
            let mut reader = response.into_body().into_reader();
            let Some(body) = read_limited_bytes(&mut reader, max_output) else {
                return Ok(-1);
            };
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
                "kv.write",
            )?;
            let Some(value) = read_from_memory(&mut caller, val_ptr as usize, val_len as usize)
            else {
                return Ok(-1);
            };
            if value.len() > MAX_KV_VALUE_BYTES {
                return Ok(-1);
            }
            let path = kv_file_path(&key_bytes);
            if let Some(parent) = path.parent() {
                if fs::create_dir_all(parent).is_err() {
                    return Ok(-1);
                }
            }
            let _guard = match acquire_path_lock(&path) {
                Some(guard) => guard,
                None => return Ok(-1),
            };
            if is_symlink_path(&path) {
                return Ok(-1);
            }
            if write_file_replace_symlink_safe(&path, &value).is_err() {
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
                "kv.read",
            )?;
            let path = kv_file_path(&key_bytes);
            let _guard = match acquire_path_lock(&path) {
                Some(guard) => guard,
                None => return Ok(-1),
            };
            if is_symlink_path(&path) {
                return Ok(-1);
            }
            let data = match fs::read(path) {
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
            if message.len() > MAX_QUEUE_MESSAGE_BYTES {
                return Ok(-1);
            }
            let path = queue_file_path(&topic_bytes);
            if let Some(parent) = path.parent() {
                if fs::create_dir_all(parent).is_err() {
                    return Ok(-1);
                }
            }
            let encoded = STANDARD.encode(message);
            let _guard = match acquire_path_lock(&path) {
                Some(guard) => guard,
                None => return Ok(-1),
            };
            if is_symlink_path(&path) {
                return Ok(-1);
            }
            let current_size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            if current_size > MAX_QUEUE_FILE_BYTES {
                return Ok(-1);
            }
            let mut file = match open_append_no_follow(&path) {
                Ok(f) => f,
                Err(_) => return Ok(-1),
            };
            let mut line = encoded.into_bytes();
            line.push(b'\n');
            if current_size.saturating_add(line.len() as u64) > MAX_QUEUE_FILE_BYTES {
                return Ok(-1);
            }
            if file.write_all(&line).is_err() {
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
            let _guard = match acquire_path_lock(&path) {
                Some(guard) => guard,
                None => return Ok(-1),
            };
            if is_symlink_path(&path) {
                return Ok(-1);
            }
            if fs::metadata(&path).map(|m| m.len()).unwrap_or(0) > MAX_QUEUE_FILE_BYTES {
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
            if write_file_replace_symlink_safe(&path, rewritten.as_bytes()).is_err() {
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

fn bounded_guest_len(len: i32, max_allowed: usize) -> Option<usize> {
    if len < 0 {
        return None;
    }
    let len = len as usize;
    if len > max_allowed {
        return None;
    }
    Some(len)
}

fn bounded_guest_out_len(out_len: i32) -> Option<usize> {
    bounded_guest_len(out_len, MAX_HOSTCALL_COPY_BYTES)
}

fn read_limited_bytes(reader: &mut impl Read, max_bytes: usize) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    if reader
        .take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .is_err()
    {
        return None;
    }
    if bytes.len() > max_bytes {
        return None;
    }
    Some(bytes)
}

fn read_file_bytes_capped(path: &Path, max_bytes: usize) -> Option<Vec<u8>> {
    let mut file = fs::File::open(path).ok()?;
    if file.metadata().ok()?.len() > max_bytes as u64 {
        return None;
    }
    read_limited_bytes(&mut file, max_bytes)
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

fn normalize_abs_path(path: &str) -> Option<String> {
    if !path.starts_with('/') {
        return None;
    }
    let mut normalized = Vec::new();
    for part in path.split('/') {
        if part.is_empty() {
            continue;
        }
        if part == "." || part == ".." || part.chars().any(char::is_control) {
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

fn resolve_path_for_prefix_check(path: &Path, allow_missing_leaf: bool) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut probe = path.to_path_buf();
    let mut suffix = Vec::<OsString>::new();
    loop {
        match fs::canonicalize(&probe) {
            Ok(resolved) => {
                if !allow_missing_leaf && !suffix.is_empty() {
                    return None;
                }
                let mut full = resolved;
                for part in suffix.iter().rev() {
                    full.push(part);
                }
                return Some(full);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let name = probe.file_name()?.to_os_string();
                suffix.push(name);
                if !probe.pop() {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }
}

fn path_buf_within_prefix(path: &Path, prefix: &Path) -> bool {
    path == prefix || path.strip_prefix(prefix).is_ok()
}

fn normalize_uri_path(path: &str) -> Option<String> {
    let raw = if path.is_empty() { "/" } else { path };
    if raw.contains('\\') || contains_pct_encoded_triplet(raw) {
        return None;
    }
    normalize_abs_path(raw)
}

fn contains_pct_encoded_triplet(value: &str) -> bool {
    value.as_bytes().windows(3).any(|window| {
        window[0] == b'%' && window[1].is_ascii_hexdigit() && window[2].is_ascii_hexdigit()
    })
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
        .unwrap_or_else(|_| default_runtime_root("kv"))
}

fn kv_file_path(key: &[u8]) -> PathBuf {
    let digest = sha256_prefixed(key);
    let suffix = digest.strip_prefix("sha256:").unwrap_or(&digest);
    kv_root().join(format!("{suffix}.bin"))
}

fn queue_root() -> PathBuf {
    env::var("PROVENACT_QUEUE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_runtime_root("queue"))
}

fn queue_file_path(topic: &[u8]) -> PathBuf {
    let digest = sha256_prefixed(topic);
    let suffix = digest.strip_prefix("sha256:").unwrap_or(&digest);
    queue_root().join(format!("{suffix}.log"))
}

fn write_file_replace_symlink_safe(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let Some(parent) = path.parent() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path has no parent",
        ));
    };

    for _ in 0..SAFE_WRITE_TEMP_ATTEMPTS {
        let nonce = SAFE_WRITE_NONCE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let tmp_name = format!(
            ".{}.tmp.{}.{}.{}",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("provenact"),
            std::process::id(),
            nanos,
            nonce
        );
        let tmp_path = parent.join(tmp_name);

        let mut file = match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)
        {
            Ok(value) => value,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        };
        if let Err(err) = file.write_all(bytes) {
            let _ = fs::remove_file(&tmp_path);
            return Err(err);
        }
        drop(file);

        #[cfg(windows)]
        {
            if path.exists() {
                let _ = fs::remove_file(path);
            }
        }
        match fs::rename(&tmp_path, path) {
            Ok(()) => return Ok(()),
            Err(err) => {
                let _ = fs::remove_file(&tmp_path);
                return Err(err);
            }
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "failed to allocate temporary write path",
    ))
}

fn is_symlink_path(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(false)
}

fn open_append_no_follow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn default_runtime_root(kind: &str) -> PathBuf {
    if let Some(home) = env::var_os("PROVENACT_HOME") {
        return PathBuf::from(home).join("runtime").join(kind);
    }
    if let Some(home) = env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".provenact")
            .join("runtime")
            .join(kind);
    }
    env::temp_dir().join(format!("provenact-{kind}"))
}

fn path_lock_path(path: &Path) -> PathBuf {
    let mut lock_name: OsString = path.as_os_str().to_os_string();
    lock_name.push(".lock");
    PathBuf::from(lock_name)
}

fn acquire_path_lock(path: &Path) -> Option<PathLockGuard> {
    let lock_path = path_lock_path(path);
    if let Some(parent) = lock_path.parent() {
        if fs::create_dir_all(parent).is_err() {
            return None;
        }
    }

    for _ in 0..PATH_LOCK_RETRIES {
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&lock_path)
        {
            Ok(_) => return Some(PathLockGuard { lock_path }),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                if is_stale_lock(&lock_path) {
                    let _ = fs::remove_file(&lock_path);
                    continue;
                }
                thread::sleep(Duration::from_millis(PATH_LOCK_RETRY_DELAY_MS));
            }
            Err(_) => return None,
        }
    }
    None
}

struct PathLockGuard {
    lock_path: PathBuf,
}

impl Drop for PathLockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

fn is_stale_lock(lock_path: &Path) -> bool {
    let Ok(meta) = fs::metadata(lock_path) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    let Ok(age) = modified.elapsed() else {
        return false;
    };
    age.as_secs() > PATH_LOCK_STALE_SECS
}

#[derive(Default)]
struct TreeCollectionState {
    truncated: bool,
    total_file_bytes: u64,
}

fn collect_tree_entries(
    root: &Path,
    current: &Path,
    out: &mut Vec<serde_json::Value>,
    state: &mut TreeCollectionState,
) -> anyhow::Result<()> {
    if state.truncated {
        return Ok(());
    }
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
            if out.len() >= MAX_FS_TREE_ENTRIES {
                state.truncated = true;
                return Ok(());
            }
            out.push(json!({
                "path": rel_str,
                "kind": "dir"
            }));
            collect_tree_entries(root, &path, out, state)?;
        } else if meta.is_file() {
            if out.len() >= MAX_FS_TREE_ENTRIES {
                state.truncated = true;
                return Ok(());
            }
            state.total_file_bytes = state.total_file_bytes.saturating_add(meta.len());
            if state.total_file_bytes > MAX_FS_TREE_TOTAL_BYTES {
                state.truncated = true;
                return Ok(());
            }
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

    #[test]
    fn normalize_uri_path_rejects_percent_encoded_bytes() {
        assert!(normalize_uri_path("/v1/%2f..%2fadmin").is_none());
        assert!(normalize_uri_path("/v1/%20file").is_none());
    }

    #[test]
    fn normalize_abs_path_rejects_control_characters() {
        assert!(normalize_abs_path("/tmp/hello\nworld").is_none());
        assert!(normalize_abs_path("/tmp/\u{0000}").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn safe_write_replaces_symlink_without_touching_target() {
        let base = std::env::temp_dir().join(format!(
            "provenact-safe-write-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&base).expect("temp dir should exist");

        let target = base.join("target.txt");
        fs::write(&target, b"original").expect("target write");
        let sink = base.join("sink.txt");
        std::os::unix::fs::symlink(&target, &sink).expect("symlink create");

        write_file_replace_symlink_safe(&sink, b"new-value").expect("safe write");

        assert_eq!(fs::read(&target).expect("target read"), b"original");
        let sink_meta = fs::symlink_metadata(&sink).expect("sink metadata");
        assert!(!sink_meta.file_type().is_symlink());
        assert_eq!(fs::read(&sink).expect("sink read"), b"new-value");

        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn open_append_no_follow_rejects_symlink_targets() {
        let base = std::env::temp_dir().join(format!(
            "provenact-open-append-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&base).expect("temp dir should exist");

        let target = base.join("target.log");
        fs::write(&target, b"seed").expect("target write");
        let sink = base.join("sink.log");
        std::os::unix::fs::symlink(&target, &sink).expect("symlink create");
        assert!(is_symlink_path(&sink));
        assert!(open_append_no_follow(&sink).is_err());

        let _ = fs::remove_dir_all(&base);
    }
}
