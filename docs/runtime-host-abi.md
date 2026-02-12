# Runtime Host ABI (v0, Experimental)

Status: experimental. This ABI can change before v1 freeze.

This document describes the host imports exposed by `provenact-cli run`.

Module name: `provenact`

v0 runtime profile note:
- Skills are expected to target the Provenact host ABI in this document.
- WASI imports are not part of the v0 normative execution profile.

## Imports

- `input_len() -> i32`
  - Returns input byte length passed via `--input`.

- `input_read(ptr: i32, offset: i32, len: i32) -> i32`
  - Copies `len` bytes from runtime input at `offset` into guest memory at `ptr`.
  - Returns bytes written, or `-1` on invalid bounds.

- `output_write(ptr: i32, len: i32) -> i32`
  - Copies `len` bytes from guest memory at `ptr` into runtime output buffer.
  - Returns `0` on success, `-1` on invalid bounds.

- `time_now_unix() -> i64`
  - Returns UNIX time seconds.
  - Requires declared capability kind `time.now`.
  - Records `caps_used` entry: `time.now`.

- `random_fill(ptr: i32, len: i32) -> i32`
  - Fills guest memory range with OS randomness.
  - Requires declared capability kind `random.bytes`.
  - Records `caps_used` entry: `random.bytes`.
  - Returns bytes written, or `-1` on invalid bounds.

- `sha256_input_hex(ptr: i32, len: i32) -> i32`
  - Writes lowercase hex SHA-256 digest of runtime input bytes into guest memory.
  - Returns bytes written, or `-1` if `len` is too small.

- `fs_read_file(path_ptr: i32, path_len: i32, out_ptr: i32, out_len: i32) -> i32`
  - Reads file content at absolute normalized path.
  - Requires declared capability kind `fs.read` with matching path prefix.
  - Records `caps_used` entry: `fs.read`.

- `fs_write_file(path_ptr: i32, path_len: i32, data_ptr: i32, data_len: i32) -> i32`
  - Writes bytes to file path (creating parent directories).
  - Requires declared capability kind `fs.write` with matching path prefix.
  - Records `caps_used` entry: `fs.write`.

- `http_fetch(url_ptr: i32, url_len: i32, out_ptr: i32, out_len: i32) -> i32`
  - Performs HTTP GET and writes response body bytes.
  - Requires declared capability kind `net.http` with URI-prefix match.
  - Records `caps_used` entry: `net.http`.

- `kv_put(key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32) -> i32`
  - Stores key/value bytes in local runtime KV storage.
  - Requires declared capability kind `kv.write`.
  - Records `caps_used` entry: `kv.write`.

- `kv_get(key_ptr: i32, key_len: i32, out_ptr: i32, out_len: i32) -> i32`
  - Reads key/value bytes from local runtime KV storage.
  - Requires declared capability kind `kv.read`.
  - Records `caps_used` entry: `kv.read`.

- `queue_publish(topic_ptr: i32, topic_len: i32, msg_ptr: i32, msg_len: i32) -> i32`
  - Appends message bytes to local queue topic.
  - Requires declared capability kind `queue.publish`.
  - Records `caps_used` entry: `queue.publish`.

- `queue_consume(topic_ptr: i32, topic_len: i32, out_ptr: i32, out_len: i32) -> i32`
  - Pops one message from local queue topic and writes it to guest memory.
  - Requires declared capability kind `queue.consume`.
  - Records `caps_used` entry: `queue.consume`.

## Output selection

- If `output_write` is called successfully, receipt/output hashes are computed from
  that output buffer.
- Otherwise output defaults to the legacy entrypoint return behavior:
  - `() -> i32`: decimal UTF-8 of return value
  - `() -> ()`: empty output

## Capability ceiling compatibility

`core/verifier` maps additional manifest capability kinds for policy ceiling checks:
- `net.http` uses existing `capability_ceiling.net` URI-prefix semantics.
- `time.now` uses `capability_ceiling.time`.
- `random.bytes` uses `capability_ceiling.random`.
- `kv.read` / `kv.write` use `capability_ceiling.kv`.
- `queue.publish` / `queue.consume` use `capability_ceiling.queue`.

## Local Runtime Storage

Defaults (works on macOS and Linux):
- KV root directory: `/tmp/provenact-kv` (override with `PROVENACT_KV_DIR`)
- Queue root directory: `/tmp/provenact-queue` (override with `PROVENACT_QUEUE_DIR`)
