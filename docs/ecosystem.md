# Ecosystem Map

This document defines repository roles for the Inactu ecosystem and points to
release-coupling metadata.

## Repository Roles

- `inactu-cli`: substrate authority (pack/sign/verify/run, policy, conformance)
- `inactu-control`: control-plane APIs and metadata services
- `inactu-sdk`: SDK layer with parity/conformance checks
- `inactu-skills`: signed skill bundles and lock metadata

## Release Coupling

Cross-repo release coupling is recorded in `docs/release-manifest.json`.

The manifest must be updated for each public release and should include:
- repository commit references
- release tags
- compatibility pin references
- benchmark report pointer
