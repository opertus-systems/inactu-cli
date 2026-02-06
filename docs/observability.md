# Observability

This document defines the baseline observability contract for Inactu v0.

## Goals

- Detect verification and execution failures quickly.
- Attribute security denials to a concrete gate.
- Measure runtime cost by stage (`verify`, `execute`, `receipt`).
- Keep telemetry deterministic and machine-parsable.

## Telemetry Mode

The CLI emits structured JSON events to `stderr` when:

- `INACTU_OBS_JSON=1` (also accepts `true` or `yes`)

Normal CLI behavior is unchanged when telemetry is disabled.

## Emitted Events

`inactu.command`
- command-level result for `verify`, `inspect`, `pack`, `sign`, `run`, `verify-receipt`
- fields: `command`, `status`, `duration_ms`, optional `error`

`inactu.verify`
- bundle verification flow
- fields: `status`, `artifact`, `signer_count`, `preflight_ms`, `trust_ms`, `duration_ms`, optional `error`

`inactu.run`
- end-to-end execution flow
- fields: `status`, `artifact`, `capability_count`, `verify_ms`, `execute_ms`, `receipt_ms`, `duration_ms`, optional `error`

`inactu.verify_receipt`
- receipt validation flow
- fields: `status`, `artifact`, `duration_ms`, optional `error`

All events include:
- `event`
- `timestamp` (unix seconds)

## Metric Mapping

Recommended metrics derived from events:

- `inactu_command_total{command,status}`
- `inactu_command_duration_ms{command}` (histogram)
- `inactu_verify_total{status}`
- `inactu_verify_duration_ms` (histogram)
- `inactu_run_total{status}`
- `inactu_run_duration_ms` (histogram)
- `inactu_run_stage_duration_ms{stage=verify|execute|receipt}` (histogram)
- `inactu_verify_receipt_total{status}`
- `inactu_verify_receipt_duration_ms` (histogram)

Error analysis:

- `inactu_error_total{event,error_class}`
  - classify from `error` string prefix (for example: hash mismatch, signature invalid, policy deny, runtime trap)

## Initial SLO Targets

- Verify p95 latency: under 200 ms for standard v0 vectors.
- Run p95 latency: under 500 ms for standard v0 vectors.
- Receipt verification success rate: 99.99%+ on valid receipts.
- Security bypass rate: 0 accepted runs that should have failed verification/policy.

## Operational Notes

- Keep high-cardinality fields (for example full signer lists) out of metric labels.
- Store raw JSON events in logs; derive aggregate metrics in pipeline/collector.
- Treat artifact digests as identifiers; avoid logging sensitive input payloads.
