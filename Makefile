SHELL := /bin/bash

CLI := cargo run -p provenact-cli --
BUNDLE ?= ./bundle
WASM ?= ./skill.wasm
MANIFEST ?= ./manifest.json
SIGNER ?= alice.dev
SECRET_KEY ?= ./alice.key
KEYS ?= ./public-keys.json
POLICY ?= ./policy.json
INPUT ?= ./input.json
RECEIPT ?= ./receipt.json
OCI_REF ?=

.PHONY: help bootstrap build test conformance pack sign keys-digest verify run verify-receipt inspect verify-cosign run-cosign flow flow-cosign demo-v0

help:
	@echo "targets:"
	@echo "  bootstrap       - check local tools and build CLI"
	@echo "  build           - build provenact-cli"
	@echo "  test            - run provenact-cli tests"
	@echo "  conformance     - run full conformance"
	@echo "  pack            - pack bundle"
	@echo "  sign            - sign bundle"
	@echo "  verify          - verify bundle (keys digest pinned)"
	@echo "  run             - run bundle and emit receipt"
	@echo "  verify-receipt  - verify receipt integrity"
	@echo "  inspect         - inspect bundle metadata"
	@echo "  verify-cosign   - verify bundle with cosign gate (requires OCI_REF)"
	@echo "  run-cosign      - run bundle with cosign gate (requires OCI_REF)"
	@echo "  flow            - pack + sign + verify + run + verify-receipt"
	@echo "  flow-cosign     - flow + cosign gates"
	@echo "  demo-v0         - run v0 demo suite (manual agent + MCP optional proof)"

bootstrap:
	./scripts/bootstrap-local.sh

build:
	cargo build -p provenact-cli

test:
	cargo test -p provenact-cli

conformance:
	cargo conformance

pack:
	$(CLI) pack --bundle $(BUNDLE) --wasm $(WASM) --manifest $(MANIFEST)

sign:
	$(CLI) sign --bundle $(BUNDLE) --signer $(SIGNER) --secret-key $(SECRET_KEY)

keys-digest:
	@shasum -a 256 $(KEYS) | awk '{print "sha256:"$$1}'

verify:
	@KEYS_DIGEST=$$(shasum -a 256 $(KEYS) | awk '{print "sha256:"$$1}'); \
	$(CLI) verify --bundle $(BUNDLE) --keys $(KEYS) --keys-digest "$$KEYS_DIGEST"

run:
	@KEYS_DIGEST=$$(shasum -a 256 $(KEYS) | awk '{print "sha256:"$$1}'); \
	$(CLI) run --bundle $(BUNDLE) --keys $(KEYS) --keys-digest "$$KEYS_DIGEST" --policy $(POLICY) --input $(INPUT) --receipt $(RECEIPT)

verify-receipt:
	$(CLI) verify-receipt --receipt $(RECEIPT)

inspect:
	$(CLI) inspect --bundle $(BUNDLE)

verify-cosign:
	@if [[ -z "$(OCI_REF)" ]]; then echo "set OCI_REF=<registry/ref:tag>"; exit 1; fi
	@KEYS_DIGEST=$$(shasum -a 256 $(KEYS) | awk '{print "sha256:"$$1}'); \
	$(CLI) verify --bundle $(BUNDLE) --keys $(KEYS) --keys-digest "$$KEYS_DIGEST" --require-cosign --oci-ref $(OCI_REF)

run-cosign:
	@if [[ -z "$(OCI_REF)" ]]; then echo "set OCI_REF=<registry/ref:tag>"; exit 1; fi
	@KEYS_DIGEST=$$(shasum -a 256 $(KEYS) | awk '{print "sha256:"$$1}'); \
	$(CLI) run --bundle $(BUNDLE) --keys $(KEYS) --keys-digest "$$KEYS_DIGEST" --policy $(POLICY) --input $(INPUT) --receipt $(RECEIPT) --require-cosign --oci-ref $(OCI_REF)

flow: pack sign verify run verify-receipt

flow-cosign: pack sign verify-cosign run-cosign verify-receipt

demo-v0:
	./apps/provenact-agent-kit/scripts/demo-v0.sh
