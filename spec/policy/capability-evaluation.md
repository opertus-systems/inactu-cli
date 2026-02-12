# Capability Evaluation Semantics (v0)

This document defines how requested capabilities in `manifest.json` are matched
against policy ceilings.

## Request Shape

Manifest capability entries are objects:

```json
{"kind":"<kind>", "value":"<value>"}
```

The evaluator MUST process each requested entry independently. Execution is
allowed only when all requested entries are allowed.

## Supported Requested Kinds (v0)

- `fs.read` with `value` as an absolute path.
- `fs.write` with `value` as an absolute path.
- `net.http` with `value` as an absolute URI.
- `env` with `value` as an environment variable name.
- `exec` with `value` equal to `"true"`.
- `exec.safe` with non-empty `value`.
- `time.now` with non-empty `value`.
- `random.bytes` with non-empty `value`.
- `kv.read` with key string `value` (`"*"` allowed by policy).
- `kv.write` with key string `value` (`"*"` allowed by policy).
- `queue.publish` with topic string `value` (`"*"` allowed by policy).
- `queue.consume` with topic string `value` (`"*"` allowed by policy).

Unknown kinds MUST be denied.

## Normalization and Safety Rules

- File paths MUST be absolute (`/`-prefixed).
- File paths MUST be normalized before policy matching:
  - no `.` segments
  - no `..` segments
  - no empty segments except root
- Environment variable names MUST match `^[A-Z_][A-Z0-9_]*$`.
- URIs MUST be absolute and parseable.

Invalid requested values MUST be denied.

## Matching Rules

- `fs.read`:
  - Allowed when request path is within at least one policy
    `capability_ceiling.fs.read` prefix.
- `fs.write`:
  - Allowed when request path is within at least one policy
    `capability_ceiling.fs.write` prefix.
- `net.http`:
  - Allowed when request URI matches at least one
    `capability_ceiling.net` URI prefix after structured comparison:
    - same scheme
    - same host
    - same effective port
    - request path is within the policy path prefix (boundary-safe)
  - Policy URI prefixes MUST be absolute authority URIs without query/fragment.
- `env`:
  - Allowed on exact name match against `capability_ceiling.env`.
- `exec`:
  - Allowed only when `capability_ceiling.exec` is `true`.
- `exec.safe`:
  - Allowed only when `capability_ceiling.exec` is `true`.
- `time.now`:
  - Allowed only when `capability_ceiling.time` is `true`.
- `random.bytes`:
  - Allowed only when `capability_ceiling.random` is `true`.
- `kv.read`:
  - Allowed on exact key match against `capability_ceiling.kv.read`.
  - Policy item `"*"` matches any requested key.
- `kv.write`:
  - Allowed on exact key match against `capability_ceiling.kv.write`.
  - Policy item `"*"` matches any requested key.
- `queue.publish`:
  - Allowed on exact topic match against `capability_ceiling.queue.publish`.
  - Policy item `"*"` matches any requested topic.
- `queue.consume`:
  - Allowed on exact topic match against `capability_ceiling.queue.consume`.
  - Policy item `"*"` matches any requested topic.

For filesystem prefix checks, boundary-safe prefix matching MUST be used:
- `/tmp` allows `/tmp/a.txt`
- `/tmp` does not allow `/tmp2/a.txt`

## Decision Outcome

- If any requested capability is denied, execution MUST be denied.
- The runtime SHOULD report denied capability entries in diagnostics.
