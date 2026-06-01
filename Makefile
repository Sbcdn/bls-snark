# bls-snark — Makefile
# See README.md for usage; `make help` for target list.

GO       ?= go
BIN_DIR  := bin
OUT_DIR  := out
BINARY   := $(BIN_DIR)/bls-snark
PKG      := ./cmd/bls-snark

# Default flags
GOFLAGS  ?=
LDFLAGS  ?= -s -w

.PHONY: help all build vet lint test test-short test-soundness test-dumper smoke wrap-risc0 verify-smoke clean fmt deps tidy

# Tamper/soundness negative tests gated on `make wrap-risc0` artifacts
# (out/*.bin, out/cardano/*.bin). In `test-short` they SKIP because the
# artifacts don't exist yet, so they must be re-run AFTER wrap-risc0 and a
# silent SKIP must fail the build — otherwise "CI green" says nothing about
# the core soundness claims (see audit B1).
SOUNDNESS_TESTS := TestOuterVerifyTamperedPublicFails|TestOuterVerifyTamperedProofFails|TestOuterVerifyFromInnerPublicInputsDirectly|TestCardanoPublicLimbRoundTrip|TestCardanoVKv2_RoundTripVerifies|TestCardanoVKv2_Sizes|TestReferenceVerifierAccepts|TestReferenceMatchesGnarkOnTamper|TestParseProofRejectsForgedCommitment|TestParsePublicRejectsNonCanonicalLimb

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "Targets:\n"} /^[a-zA-Z_-]+:.*##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# ---------- build & quality ----------

build: ## Compile the CLI
	@mkdir -p $(BIN_DIR)
	$(GO) build -trimpath $(GOFLAGS) -ldflags='$(LDFLAGS)' -o $(BINARY) $(PKG)

vet: ## go vet
	$(GO) vet ./...

lint: ## golangci-lint (must be installed)
	golangci-lint run -v --timeout=5m

fmt: ## goimports + gofmt
	goimports -w .
	gofmt -w .

deps: ## Download module dependencies
	$(GO) mod download

tidy: ## go mod tidy
	$(GO) mod tidy

# ---------- tests ----------

test-short: ## Unit tests, short mode (CI baseline)
	$(GO) test -short ./...

test: ## Full test suite
	$(GO) test ./...

test-dumper: ## cargo test the Rust risc0-dump (NOT in CI: needs the zkr artifact — see scripts/README for RECURSION_SRC_PATH). Covers the journal↔claim self-check.
	cargo test --release --manifest-path tools/risc0-dump/Cargo.toml

test-soundness: ## Re-run artifact-gated soundness tests; fail on any SKIP (run after `make wrap-risc0`)
	@out=$$($(GO) test -v -count=1 -run '^($(SOUNDNESS_TESTS))$$' \
	    ./internal/serialize/ ./internal/cardanoref/ 2>&1); \
	  echo "$$out"; \
	  if echo "$$out" | grep -q -- '--- SKIP'; then \
	    echo "ERROR: a soundness test SKIPPED — wrap-risc0 artifacts missing or wrong shape (audit B1)"; \
	    exit 1; \
	  fi
	@echo "[test-soundness] OK — all soundness tests executed"

# ---------- dev smoke (cubic inner) ----------

smoke: build ## Dev smoke test: setup + prove + verify with cubic inner
	@mkdir -p $(OUT_DIR)
	$(BINARY) setup  --inner-source cubic --insecure-dev-setup
	$(BINARY) prove  --inner-source cubic \
	    --pk  $(OUT_DIR)/outer_pk.bin \
	    --ccs $(OUT_DIR)/outer.ccs \
	    --inner-vk $(OUT_DIR)/inner_vk.bin
	$(BINARY) verify \
	    --vk     $(OUT_DIR)/outer_vk.bin \
	    --proof  $(OUT_DIR)/outer_proof.bin \
	    --public $(OUT_DIR)/outer_public.bin
	@echo "[smoke] OK"

# ---------- real RISC0 wrap ----------

wrap-risc0: build ## Wrap a real RISC0 BN254 Groth16 proof end-to-end + Cardano export
	@mkdir -p $(OUT_DIR)
	@test -f testdata/risc0/verification_key.json || { \
	    echo "ERROR: testdata/risc0/verification_key.json missing — run tools/risc0-dump first (see README)."; \
	    exit 1; \
	}
	$(BINARY) setup  --inner-source risc0 --insecure-dev-setup \
	    --inner-vk testdata/risc0/verification_key.json
	$(BINARY) prove  --inner-source risc0 \
	    --pk  $(OUT_DIR)/outer_pk.bin \
	    --ccs $(OUT_DIR)/outer.ccs \
	    --inner-vk $(OUT_DIR)/inner_vk.bin \
	    --inner-proof  testdata/risc0/proof.json \
	    --inner-public testdata/risc0/public.json
	$(BINARY) verify \
	    --vk     $(OUT_DIR)/outer_vk.bin \
	    --proof  $(OUT_DIR)/outer_proof.bin \
	    --public $(OUT_DIR)/outer_public.bin
	$(BINARY) export \
	    --vk     $(OUT_DIR)/outer_vk.bin \
	    --proof  $(OUT_DIR)/outer_proof.bin \
	    --public $(OUT_DIR)/outer_public.bin \
	    --journal testdata/risc0/journal.bin \
	    --risc0-params testdata/risc0/risc0_params.json \
	    --out-dir $(OUT_DIR)/cardano
	@echo "[wrap-risc0] OK — Cardano-ready bytes in $(OUT_DIR)/cardano/"

# ---------- combined ----------

all: vet test-short smoke wrap-risc0 test-soundness ## Full check: vet + tests + smoke + wrap-risc0 + soundness
	@echo "[all] OK"

# ---------- cleanup ----------

clean: ## Remove build artifacts and outputs
	rm -rf $(BIN_DIR) $(OUT_DIR)
