# CDN Distribution and Funding Logic (Draft)

Status: draft (non-normative).

This document defines practical CDN/operator behavior for artifact distribution
without changing Provenact's core cryptographic profile.

## Scope

This draft is about artifact distribution only:
- origin storage ownership
- CDN caching behavior
- integrity checks in transit
- cost controls before external funding exists

It does not introduce agent behavior, orchestration, or scheduling.

## Responsibility Model (Until Funding)

- Package manager/registry operator is financially responsible for origin and CDN
  costs by default.
- Maintainers/publishers are not billed unless an explicit paid plan exists.
- If sponsorship/foundation funding exists, it offsets shared infra costs but does
  not change integrity enforcement.

## Integrity Model

- Cryptographic source of truth remains `manifest.artifact` (`sha256:...`).
- MD5 is required as an additional transport integrity check for CDN/object
  delivery.
- MD5 is not accepted as artifact identity and cannot override SHA-256 decisions.

## Required Metadata Per Artifact

Each published object must carry:
- `sha256` (required): canonical digest matching `manifest.artifact`.
- `md5` (required): transport checksum of exact object bytes served by CDN.
- `size_bytes` (required).
- `content_type` (required).
- `published_at` (required).

Recommended exposure:
- `ETag` set to a stable token that is not ambiguous with multipart MD5.
- `Content-MD5` header set when upstream/CDN supports it end-to-end.
- `X-Provenact-SHA256` and `X-Provenact-MD5` response headers for explicit client checks.

## Upload/Publish Gate

Publish MUST fail if any check fails:
1. Compute `sha256` and `md5` from uploaded bytes.
2. Verify computed `sha256` equals `manifest.artifact`.
3. Persist both checksums with immutable metadata.
4. Reject overwrite attempts for existing `sha256` (immutable artifact identity).

## Download/Resolution Gate

Client or edge verifier MUST enforce:
1. Resolve artifact by `sha256` identity.
2. Fetch bytes from CDN.
3. Recompute MD5 and compare with expected `md5`.
4. Recompute SHA-256 and compare with expected `sha256`.
5. Accept only if both checks pass.

Failure semantics:
- MD5 mismatch: retry once from a different edge/POP, then fail closed.
- SHA-256 mismatch: fail closed immediately and mark as integrity incident.
- Missing MD5 metadata: fail closed (policy exception requires explicit override).

## Mirror and Failover Logic

- Primary path: nearest CDN POP.
- Retry path: alternate POP or origin (single retry only).
- Never fall back to unchecked content.
- Mirror promotion must preserve checksum metadata and immutability guarantees.

## Cost Controls Before Funding

- Cache immutable artifacts aggressively (`Cache-Control: public, max-age=31536000, immutable`).
- Deny mutable tags without pinned `sha256`.
- Enforce per-IP and per-token rate limits.
- Prefer deduplicated storage keyed by `sha256`.
- Use tiered egress controls:
  - anonymous traffic: stricter limits
  - authenticated CI/org traffic: higher limits

## Minimal Verification Pseudocode

```text
resolve(artifact_sha256) -> { url, expected_sha256, expected_md5 }
bytes = fetch(url)
if md5(bytes) != expected_md5:
  bytes = retry_fetch_alternate_pop(url)
  if md5(bytes) != expected_md5: reject("md5_transport_mismatch")
if sha256(bytes) != expected_sha256:
  reject("sha256_identity_mismatch")
accept(bytes)
```

## Operational Signals and Alerts

Track:
- `cdn_md5_mismatch_total`
- `cdn_sha256_mismatch_total`
- `cdn_retry_success_total`
- `cdn_retry_failure_total`
- `artifact_egress_bytes_total`
- `artifact_cache_hit_ratio`

Alert immediately on any SHA-256 mismatch event.
Alert on MD5 mismatch rate above baseline (possible CDN corruption/path issue).

## Rollout Policy

Phase 1:
- Enforce SHA-256 + MD5 on publish.
- Warn (not fail) on missing MD5 header at fetch boundary if metadata exists.

Phase 2:
- Hard fail on missing MD5 metadata or mismatch.
- Hard fail on any SHA-256 mismatch (already required).

Phase 3:
- Add signed transparency records for publish/fetch events (optional future work).

## Compatibility Note

Because Provenact v0 cryptographic profile is SHA-256 + Ed25519, this draft treats
MD5 as transport corruption detection only. Security trust and artifact identity
remain bound to SHA-256 digests and signatures.
