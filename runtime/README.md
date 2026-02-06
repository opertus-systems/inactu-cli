# Runtime (v0)

The runtime executes skills (WASM by default), enforces capability sandboxing, and produces execution transcripts.

Rules:
- Deny-by-default capabilities.
- Enforce requested caps at execution.
- Emit transcripts for every run.
- Successful runs require receipt emission; failed runs must not produce success
  receipts.
- Enforce verification gate ordering before execution:
  1. artifact hash
  2. signature verification
  3. trusted signer and capability policy checks
  4. execution
- Current v0 entrypoint support:
  - `() -> i32` (output bytes are decimal UTF-8 return value)
  - `() -> ()` (output bytes are empty)
- WASM execution is fuel-metered and resource-limited (memory/tables/instances) per run.
- v0 runtime profile uses the Inactu host ABI; WASI is not part of the v0
  normative contract.
- Failed runs MUST not emit a success receipt.

Normative references:
- `spec/policy/capability-evaluation.md`
- `runtime/transcript.md`
