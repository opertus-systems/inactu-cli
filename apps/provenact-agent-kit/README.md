# provenact-agent-kit (in-repo v0 scaffold)

This directory is a temporary in-repo scaffold for v0 demo coverage.

It does not add planner loops, memory, scheduling, or autonomous behavior to
Provenact core. It only demonstrates adapter boundaries that call the existing
`provenact-cli` execution path.

## What It Proves

- One manual agent-framework style integration (`manual-agent.sh`)
- One end-to-end `agent -> skill -> receipt` flow
- One explicit proof that MCP is optional (`direct` vs `mcp` receipt semantics)
- Explicit capability enforcement deny behavior

## Run The Full v0 Demo Set

From repo root:

```bash
./apps/provenact-agent-kit/scripts/demo-v0.sh
```

Optional custom working directory:

```bash
./apps/provenact-agent-kit/scripts/demo-v0.sh /tmp/provenact-v0-demo
```

## Individual Demo Entrypoints

- Direct native invoke:
  `./apps/provenact-agent-kit/scripts/run-direct.sh <out-dir> <receipt-path>`
- Manual agent integration:
  `./apps/provenact-agent-kit/scripts/manual-agent.sh [request.json] <out-dir> <receipt-path>`
- MCP-style adapter invoke:
  `./apps/provenact-agent-kit/scripts/mcp-tool-adapter.sh [request.json] <out-dir> <receipt-path>`

## Notes

- Security/trust semantics remain in `provenact-cli` and verifier core.
- Adapter scripts translate invocation shape only; they do not redefine policy,
  signature checks, or receipt logic.
- This scaffold can move to a standalone `provenact-agent-kit` repository without
  changing core substrate behavior.
