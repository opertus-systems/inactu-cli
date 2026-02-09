# v0 Demo Status

This tracks the demo criteria needed for v0 confidence without expanding core
scope.

## Criteria Coverage

- `one agent framework integration (even manual)`
  - covered by: `apps/provenact-agent-kit/scripts/manual-agent.sh`
- `one end-to-end agent -> skill -> receipt flow`
  - covered by: `apps/provenact-agent-kit/scripts/demo-v0.sh`
  - flow: `pack -> sign -> verify -> run -> verify-receipt`
- `one clear proof that MCP is optional`
  - covered by: `apps/provenact-agent-kit/scripts/demo-v0.sh`
  - proof: direct and MCP-adapter runs produce matching receipt semantics for
    `artifact`, `inputs_hash`, `outputs_hash`, and `caps_used`

## Security Gate Included In Demo

- explicit capability enforcement deny path is exercised in
  `apps/provenact-agent-kit/scripts/demo-v0.sh`
  - expected result: denied run exits non-zero and no receipt is emitted

## Run

From repo root:

```bash
./apps/provenact-agent-kit/scripts/demo-v0.sh
```
