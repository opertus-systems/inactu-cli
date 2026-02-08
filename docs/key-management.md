# Key Management (Rotation and Revocation)

This runbook defines operator procedures for trust-anchor key lifecycle in
Provenact.

Scope:
- trust anchor file: `public-keys.json`
- trust anchor pin: `--keys-digest sha256:...`

## Core Rule

Any change to `public-keys.json` requires an updated digest pin and coordinated
rollout. `verify` and `run` are expected to fail if the digest pin is stale.

## Rotation Procedure

Use this for planned signer key replacement.

1. Prepare new key material offline.
- Generate new Ed25519 keypair for signer identity.
- Keep private key handling outside this repository.

2. Stage trust-anchor update.
- Add the new public key to `public-keys.json`.
- Keep existing key(s) during overlap window.

3. Compute and publish new trust-anchor digest.
- `NEW_KEYS_DIGEST="$(shasum -a 256 ./public-keys.json | awk '{print \"sha256:\"$1}')"`.
- Update deployment/config references that pass `--keys-digest`.

4. Re-sign artifacts.
- Sign new bundle outputs with the rotated key.
- Verify with:
  `provenact-cli verify --bundle <bundle> --keys ./public-keys.json --keys-digest "$NEW_KEYS_DIGEST"`.

5. Rollout and observe.
- Deploy trust-anchor update and digest pin atomically where possible.
- Monitor failed verify/run attempts caused by stale pins.

6. Remove old key after overlap.
- Remove the retired key from `public-keys.json`.
- Recompute digest and repeat rollout for final trust set.

## Emergency Revocation Procedure

Use this when a signing key is suspected compromised.

1. Remove compromised key from `public-keys.json` immediately.
2. Compute new digest pin:
- `NEW_KEYS_DIGEST="$(shasum -a 256 ./public-keys.json | awk '{print \"sha256:\"$1}')"`.
3. Roll out updated `public-keys.json` and digest pin at highest priority.
4. Block execution of artifacts signed only by the revoked key.
5. Re-sign required artifacts using healthy signer keys.
6. Capture incident evidence:
- previous and new key sets (redacted as needed)
- old and new digest pins
- affected artifact identities
- verify/run failure and recovery timestamps

## Operational Controls

- Keep `public-keys.json` under strict change control.
- Require peer review for key-set changes.
- Store approved digest pins in deployment config, not ad-hoc operator shells.
- Retain a change log for key additions/removals and effective timestamps.

## Validation Checklist

- [ ] `public-keys.json` updated as intended.
- [ ] New digest pin computed and distributed.
- [ ] Golden flow passes with new pin:
  `pack -> sign -> verify -> run -> verify-receipt`.
- [ ] Old pin intentionally fails where expected.
- [ ] Incident/audit evidence recorded.
