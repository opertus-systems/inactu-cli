# inactu-cli

Minimal CLI for Inactu v0 verification workflows.

## Architecture

The CLI is organized into small internal modules:
- `preflight`: shared bundle validation (`artifact`, `manifest_hash`, wasm digest)
- `keys`: signer/key parsing and required key-file digest pinning
- `runtime_exec`: Wasmtime execution with fuel/resource limits
- `fileio`/`flags`/`constants`: bounded I/O and argument handling

This keeps security-critical checks centralized and reused by both `verify` and
`run`.

## Commands

- `verify --bundle <bundle-dir> --keys <public-keys.json> --keys-digest <sha256:...> [--require-cosign --oci-ref <oci-ref>] [--allow-experimental]`
- `inspect --bundle <bundle-dir> [--allow-experimental]`
- `pack --bundle <bundle-dir> --wasm <skill.wasm> --manifest <manifest.json> [--allow-experimental]`
- `archive --bundle <bundle-dir> --output <skill.tar.zst>`
- `sign --bundle <bundle-dir> --signer <signer-id> --secret-key <ed25519-secret-key-file> [--allow-experimental]`
- `install --artifact <path|file://...|http(s)://...|oci://...> [--keys <public-keys.json> --keys-digest <sha256:...>] [--policy <policy.{json|yaml}>] [--require-signatures] [--allow-experimental]`
- `export agentskills --agent <claude|codex|cursor> --scope <user|repo|admin>`
- `run --bundle <bundle-dir> --keys <public-keys.json> --keys-digest <sha256:...> --policy <policy.{json|yaml}> --input <input-file> --receipt <receipt.json> [--receipt-format <v0|v1-draft>] [--require-cosign --oci-ref <oci-ref>] [--allow-experimental]`
- `verify-receipt --receipt <receipt.json>`
- `verify-registry-entry --artifact <artifact-bytes-file> --sha256 <sha256:...> --md5 <32-lowercase-hex>`
- `experimental-validate-manifest-v1 --manifest <manifest.json>`
- `experimental-validate-receipt-v1 --receipt <receipt.json>`

Success output contract:
- command success lines start with `OK <command> ...` for stable log parsing
- `inspect` intentionally emits only deterministic field lines

Experimental schema gate:
- manifests with `schema_version: "1.0.0-draft"` are rejected unless
  `--allow-experimental` is explicitly passed
- gate failure message is deterministic:
  `manifest schema_version '1.0.0-draft' requires --allow-experimental`

Recommended for untrusted environments:
- always pass `--keys-digest` on `verify` and `run` (required by CLI)
- keep `public-keys.json` under change control and pin by digest

`verify` checks:
- `manifest.json` and `signatures.json` parse and schema-shape constraints
- `manifest.artifact == signatures.artifact`
- `sha256(JCS(manifest.json)) == signatures.manifest_hash`
- `signatures.signatures` is non-empty
- `skill.wasm` hash matches `manifest.artifact`
- Ed25519 signatures over `signatures.manifest_hash` using supplied public keys
- required trust-anchor pin: `sha256(public-keys.json)` must match `--keys-digest`
- optional OCI signature check: when `--require-cosign` is set, `cosign verify <oci-ref>` must succeed
- bounded input sizes for untrusted files (`skill.wasm`, JSON metadata, key file)

`inspect` prints deterministic bundle metadata for review and does not execute
skills.
When `bundle-meta.json` exists, `inspect` prints deterministic metadata lines for
its schema/artifact/manifest hash.

`pack` creates/overwrites the bundle directory with:
- `skill.wasm` copied from `--wasm`
- `manifest.json` normalized from `--manifest`
- `signatures.json` initialized with matching `artifact`, `manifest_hash`, and empty signatures
- `bundle-meta.json` initialized with deterministic `schema_version`, `artifact`,
  and `manifest_hash`

`pack` requires `manifest.artifact` to match the SHA-256 digest of the supplied
WASM bytes.

`archive` emits a deterministic canonical install package (`skill.tar.zst`) from
a bundle directory:
- required bundle inputs: `manifest.json`, `skill.wasm`
- optional bundle inputs: `signatures.json`, `sbom.spdx.json`, `sigstore.bundle.json`
- required consistency checks: `manifest.artifact` matches `skill.wasm`; when
  `signatures.json` exists, `signatures.artifact` and `signatures.manifest_hash`
  must match manifest-derived values
- deterministic tar metadata: fixed uid/gid/uname/gname/mtime and stable file
  modes (`0644` JSON, `0755` WASM)
- canonical entry order: `manifest.json`, `skill.wasm`, `sbom.spdx.json`,
  `sigstore.bundle.json`, `signatures.json` (optional files included only when
  present)

`sign` reads bundle metadata, requires the signer to be declared in
`manifest.signers`, and adds or updates an Ed25519 signature in
`signatures.json`.

The secret key file passed to `--secret-key` must contain a base64-encoded 32
byte Ed25519 secret key seed.

`install` ingests canonical `skill.tar.zst` packages into a local content store:
- accepted sources: local file path, `file://...`, `http(s)://...`
- reserved future source syntax: `oci://...` (currently fails closed with
  explicit message)
- computes archive digest (`sha256:<hex>`) as skill identity of record
- unpacks and validates required files (`manifest.json`, `skill.wasm`)
- validates `manifest.artifact` against bundled `skill.wasm`
- optional signature verification in dev mode (`--keys` + `--keys-digest`)
- mandatory signature verification in prod mode (`--require-signatures`)
- optional policy-gated install checks via `--policy`
- stores installed content under `~/.inactu/store/sha256/<hash>/`
  (or `$INACTU_HOME/store/sha256/<hash>/`)
- updates local metadata index at `~/.inactu/index.json`

`export agentskills` bridges installed skills into filesystem-scanned AgentSkills
layouts while keeping execution in Inactu wrappers:
- source of truth: installed skills from `~/.inactu/index.json`
- generated layout per skill: `SKILL.md`, `scripts/run.sh`, `scripts/run.ps1`, `references/*`
- supported targets:
  - Claude: `~/.claude/skills` (user), `./.claude/skills` (repo)
  - Codex: `~/.agents/skills` (user), `./.agents/skills` (repo), `/etc/codex/skills` (admin)
  - Cursor: `~/.cursor/skills` (user), `./.cursor/skills` (repo)
- wrappers call `inactu-cli run` with an exported `ide-safe` policy profile
  (network denied, write constrained to scratch, exec/time denied)

`run` is an M3 scaffold that performs pre-execution checks and emits a receipt:
- artifact hash verification
- signature verification
- trusted signer policy checks
- capability ceiling evaluation
- fuel-metered and resource-limited WASM entrypoint execution (`manifest.entrypoint`)
- receipt emission to `--receipt`
- receipt format defaults to `v0`; `--receipt-format v1-draft` emits draft v1
  receipt fields including `bundle_hash`, `policy_hash`,
  `runtime_version_digest`, and `result_digest`
- required trust-anchor pin: `sha256(public-keys.json)` must match `--keys-digest`
- optional OCI signature check: when `--require-cosign` is set, `cosign verify <oci-ref>` must succeed before execution
- bounded file sizes for policy/input/receipt parsing and bundle metadata

Current execution support covers entrypoints with signatures:
- `() -> i32` (output bytes are decimal UTF-8 of the return value)
- `() -> ()` (output bytes are empty)

`verify-receipt` validates v0 or v1-draft receipt schema shape and `receipt_hash`
integrity.
Receipt invariants expected by the golden flow:
- `receipt.artifact` equals `manifest.artifact`
- `receipt_hash` verifies from payload fields (excluding `receipt_hash`)
- `caps_used` is deterministic for a fixed manifest/policy/input set

`verify-registry-entry` validates downloaded artifact bytes against registry
entry digests:
- `md5` transport checksum must match exactly
- `sha256` artifact identity digest must match exactly

Experimental validation commands:
- `experimental-validate-manifest-v1` validates full draft v1 manifest shape
  and field constraints.
- `experimental-validate-receipt-v1` validates full draft v1 receipt shape and
  field constraints.

## Secure End-To-End Example

1. `inactu-cli pack --bundle ./bundle --wasm ./skill.wasm --manifest ./manifest.json`
2. `inactu-cli sign --bundle ./bundle --signer alice.dev --secret-key ./alice.key`
3. `inactu-cli archive --bundle ./bundle --output ./skill.tar.zst`
4. `KEYS_DIGEST=\"$(shasum -a 256 ./public-keys.json | awk '{print \"sha256:\"$1}')\"`
5. `inactu-cli install --artifact ./skill.tar.zst --keys ./public-keys.json --keys-digest \"$KEYS_DIGEST\" --require-signatures`
6. `inactu-cli verify --bundle ./bundle --keys ./public-keys.json --keys-digest \"$KEYS_DIGEST\"`
7. `inactu-cli run --bundle ./bundle --keys ./public-keys.json --keys-digest \"$KEYS_DIGEST\" --policy ./policy.json --input ./input.json --receipt ./receipt.json`
8. `inactu-cli verify-receipt --receipt ./receipt.json`

## Conformance

Run all current verifier + CLI conformance suites from repo root:

`cargo conformance`
