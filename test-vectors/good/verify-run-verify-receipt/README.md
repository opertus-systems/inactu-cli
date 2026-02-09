# verify-run-verify-receipt

Canonical end-to-end fixture inputs for:

1. `provenact-cli verify`
2. `provenact-cli run`
3. `provenact-cli verify-receipt`

This vector stores deterministic source inputs and policy material. Tests
compile `skill.wat`, derive `manifest.artifact`, then execute the full flow in
a temporary bundle.

Golden-flow assertions:
- success log lines are stable (`OK verify`, `OK run`, `OK verify-receipt`)
- run output receipt parses and verifies via `receipt_hash`
- receipt artifact digest matches the verified manifest artifact digest
