# bls-snark

Wrap a Groth16-BN254 proof in a Groth16-BLS12-381 proof verifiable on Cardano L1.

The outer proof attests *"I know a valid BN254 Groth16 proof for this verifying key and these public inputs"* — verifiable on-chain using the BLS12-381 group + pairing builtins that ship in Plutus.

A Rust companion (`tools/risc0-dump`) converts a RISC0 `Receipt` into the snarkjs JSON triple the Go CLI consumes. The Go CLI itself is generic over any snarkjs-shaped Groth16-BN254 input; RISC0 is one producer.

---

## Why

Cardano L1 ships BLS12-381 builtins (`bls12_381_G1_uncompress`, `bls12_381_G2_uncompress`, `bls12_381_miller_loop`, …) but no BN254 builtins. RISC0's Groth16 step produces a BN254 proof. To verify on-chain, that proof has to be lifted to BLS12-381. The wrapper does this lift in-circuit: the outer circuit emulates the BN254 pairing equation inside the BLS12-381 scalar field and emits a fresh BLS12-381 Groth16 proof that on-chain code can verify natively.

---

## How it works

```
┌─────────────────────────────────────────────────────────┐
│  RISC0 receipt (bincode-serialised risc0_zkvm::Receipt) │
│     • 256-byte BN254 seal                               │
│     • claim                                             │
│     • journal                                           │
└───────────────────────────┬─────────────────────────────┘
                            │  tools/risc0-dump (Rust)
                            ▼
┌─────────────────────────────────────────────────────────┐
│  snarkjs JSON triple + journal sidecar                  │
│     proof.json, public.json, verification_key.json,     │
│     journal.bin                                         │
└───────────────────────────┬─────────────────────────────┘
                            │  bls-snark setup
                            ▼
┌─────────────────────────────────────────────────────────┐
│  Outer circuit (compiled over BLS12-381)                │
│     • emulated BN254 pairing (gnark sw_bn254)           │
│     • inner VK baked as constant via                    │
│       stdgroth16.ValueOfVerifyingKeyFixed               │
│     • InnerWitness is PUBLIC (gnark:",public") so the   │
│       outer proof commits to WHICH inner statement      │
└───────────────────────────┬─────────────────────────────┘
                            │  bls-snark prove
                            ▼
┌─────────────────────────────────────────────────────────┐
│  Outer Groth16-BLS12-381 proof + public witness         │
│  bls-snark verify                                    │
└───────────────────────────┬─────────────────────────────┘
                            │  bls-snark export
                            ▼
┌─────────────────────────────────────────────────────────┐
│  Cardano-minimal byte files                             │
│     vk.bin, proof.bin, public.bin, journal.bin          │
│  → fed into a Plutus/Aiken on-chain verifier            │
└─────────────────────────────────────────────────────────┘
```

The outer circuit pattern is a direct adaptation of gnark v0.15.0's `std/recursion/groth16/verifier_test.go::OuterCircuitConstant`. The inner verifying key is a compile-time constant (baked into the R1CS via `ValueOfVerifyingKeyFixed`), so the outer verifying key transitively commits to which inner VK is being checked.

---

## Install

Requires:

- **Go 1.25.7+** (matches gnark v0.15.0's module declaration).
- **Rust** (for the dumper). The toolchain is pinned in `tools/risc0-dump/rust-toolchain.toml` (1.91.1) so the dumper builds reproducibly; rustup installs it automatically.

```bash
git clone https://github.com/sbcdn/bls-snark.git
cd bls-snark

# Go CLI
make build                                              # → bin/bls-snark
./bin/bls-snark --help

# Rust dumper (only needed if your input is a RISC0 receipt)
cargo build --release --manifest-path tools/risc0-dump/Cargo.toml
./tools/risc0-dump/target/release/risc0-dump --help
```

---

## Usage

### CLI overview — `bls-snark`

```
bls-snark setup    Compile the outer circuit and produce (pk, vk).
                      Default: single-party gnark.Setup (INSECURE — dev).
                      Production: --pk-input/--vk-input from an MPC ceremony.

bls-snark prove    Generate the outer Groth16-BLS12-381 proof.
                      Native-verifies the inner BN254 proof first.

bls-snark verify   Native Go verification of the outer proof.

bls-snark export   Re-serialise outer VK/proof/public to Cardano-minimal
                      bytes (compressed G1/G2 + limb-aware public inputs).
                      Optionally copies the journal alongside.
```

Each subcommand emits a single JSON object to stdout. Structured logs go to stderr (zerolog).

### Dev smoke test (cubic inner)

Round-trips the toolchain against a trivial inner circuit (`x^3 + x + 5 == y`) — no external dependencies. Use this first to validate your build.

```bash
make smoke
```

Expected: exits 0, prints `"valid": true`.

### Wrapping a real RISC0 BN254 Groth16 proof

```bash
# 1. Convert the RISC0 receipt to snarkjs JSON + emit the journal sidecar.
./tools/risc0-dump/target/release/risc0-dump \
    --input   testdata/risc0/chain_proof.bin \
    --out-dir testdata/risc0
# → testdata/risc0/{proof,public,verification_key}.json + journal.bin + risc0_params.json

# 2. Setup + prove + verify + export to Cardano bytes.
make wrap-risc0
# or call the binary directly:
./bin/bls-snark setup  --inner-source risc0 --insecure-dev-setup --inner-vk testdata/risc0/verification_key.json
./bin/bls-snark prove  --inner-source risc0 \
    --pk out/outer_pk.bin --ccs out/outer.ccs --inner-vk out/inner_vk.bin \
    --inner-proof testdata/risc0/proof.json \
    --inner-public testdata/risc0/public.json
./bin/bls-snark verify --vk out/outer_vk.bin --proof out/outer_proof.bin --public out/outer_public.bin
./bin/bls-snark export --vk out/outer_vk.bin --proof out/outer_proof.bin --public out/outer_public.bin \
    --journal testdata/risc0/journal.bin --risc0-params testdata/risc0/risc0_params.json --out-dir out/cardano
```

If your input isn't a RISC0 receipt — any snarkjs-shaped Groth16-BN254 triple works. Skip step 1; provide your own `proof.json` / `public.json` / `verification_key.json` and use `--inner-vk-fingerprint` (see below) to lock in the expected inner VK.

### Cardano output byte format (v2)

After `export`, `out/cardano/` contains:

| File | Size (RISC0, nC=1) | Layout |
|---|---:|---|
| `vk.bin`     | 1676 B | `α₁(48) ‖ β₂(96) ‖ γ₂(96) ‖ δ₂(96) ‖ uint32(ic_count) ‖ IC[ic_count]×G1(48) ‖ uint32(nC) ‖ per j: pedersen_G(96) ‖ pedersen_GSigmaNeg(96) ‖ uint32(len(committed_j)) ‖ committed_j[]×uint32` |
| `proof.bin`  | 388 B  | `a₁(48) ‖ b₂(96) ‖ c₁(48) ‖ uint32(nC) ‖ per j: commitment_compressed(48) ‖ commitment_uncompressed(96) ‖ commitment_pok(48)` |
| `public.bin` | 648 B  | `uint32(n_inner_pub) ‖ uint32(n_limbs_per_scalar) ‖ limb_values...` — each limb a 32 B BE BLS12-381 scalar, limb 0 = lowest 64 bits |
| `journal.bin`| varies | raw RISC0 journal bytes (copied from the dumper). Downstream verifier recomputes `claim_digest` from this and confirms it matches indices 2–3 of the public inputs. |
| `risc0_params.json` | 379 B  | JSON sidecar (schema v2) carrying `image_id`, `control_root`, `bn254_control_id_fr`, `claim_digest`. Lets downstream verifier scripts bake the canonical RISC0 platform constants without a separate Rust dependency. |

All G1/G2 compressed points are IETF/Zcash encoding (48 B / 96 B respectively); uncompressed G1 is `curve.G1Affine.Marshal()` = `x_be(48) ‖ y_be(48)` with no compression flags or length prefix.

#### What the wrap does NOT bind on its own

The outer proof commits to 5 BN254 Fr public inputs (`control_root_low`, `control_root_high`, `claim_digest_low`, `claim_digest_high`, `bn254_control_id_fr`) decomposed into 20 BLS12-381 Fr limbs. Nothing more. In particular:

- **The journal bytes.** Only `claim_digest` is in the public-input vector. A consumer must independently compute `claim_digest` from `(image_id, journal, …)` (per `risc0_binfmt::ReceiptClaim::digest()`) and confirm it matches `(claim_digest_low, claim_digest_high)`. Otherwise the proof can be paired with any other journal that lifts to the same scalars.
- **The image_id by itself.** It enters `claim_digest` transitively, not as a separate public input. A consumer who wants "this proof attests to RISC0 program X" must bake X's image_id into its `claim_digest` reconstruction. The `risc0_params.json` sidecar carries `image_id` for convenience but is metadata, not cryptographically bound.
- **The `control_root` / `bn254_control_id_fr` values** beyond their appearance as the other 3 scalars. A consumer must check them against the canonical risc0 platform constants for the pinned release; accepting arbitrary values lets an attacker forge a "valid" proof of any `(control_root, claim_digest, bn254_control_id)` tuple they can produce a BN254 Groth16 proof for.

The wrap is a faithful BN254→BLS12-381 lift of the inner Groth16 statement. Higher-level meaning (which program ran, what journal it produced) must be re-checked by the consumer against the journal + sidecar that ship alongside the proof.

#### Verification equation the on-chain code must implement

```
For each commitment j in 0..nC-1:
  prehash_j = commitment_uncompressed_j ‖ concat over k in committed_j: publicWitness[k-1].MarshalBE
  h_j       = HashToField(DST = "bsb22-commitment", prehash_j)             // → 1 fr element

publicWitness_extended = publicWitness ‖ [h_0, ..., h_{nC-1}]

kSum = K[0]
     + MSM(K[1..],  publicWitness_extended)                                 // K is vk.G1.K
     + Σ_{j=0..nC-1} commitment_compressed_j                                // raw point addition

Main pairing check:
  e(A, B) == e(α, β) · e(kSum, γ) · e(C, δ)

Pedersen pairing check (for nC = 1 this is just the direct case, no folding):
  challenge      = fr.Hash(DST = "G16-BSB22", concat over j: h_j.MarshalBE)
  folded_commit  = Σ_{j} challenge^j · commitment_compressed_j              // for nC=1: = commitment_compressed_0
  folded_pok     = commitment_pok                                           // gnark ships one when nC=1
  e(folded_commit, pedersen_GSigmaNeg_0) · e(folded_pok, pedersen_G_0) == 1
```

Both pairing checks must pass. The hash-to-field for `h_j` and the `fr.Hash` for the challenge are both gnark's BLAKE2b-based primitive (`internal/hash_to_field`); they take a domain-separation tag (DST) byte string and produce one `fr` element. Mismatching the DST or the input byte order produces a verifier that rejects all valid proofs.

For our specific outer circuit `committed_0 = [1, 2, ..., 20]` (the commitment binds the full 20-limb outer public-input vector), so the `h_0` prehash is `96 + 20·32 = 736 B`.

Round-trip validated in `internal/serialize/cardano_v2_test.go::TestCardanoVKv2_RoundTripVerifies` — parses the v2 bytes back into native gnark types and runs `groth16.Verify`. If anything in this byte layout is missing, that test fails.

---

## Onboarding a different program

The wrap is agnostic to which RISC0 guest produced the receipt. The inner verifying key it bakes in (`risc0_groth16::verifying_key()`) is a property of the RISC0 proof system and its one-time setup ceremony — **not** of your guest program. The guest's identity (`image_id`) enters the proof through `claim_digest`, which is a public input, never through the verifying key.

Two consequences follow:

- The inner-VK fingerprint, `control_root`, `bn254_control_id`, and `verifier_parameters` are **identical for every RISC0 Groth16 receipt on a given risc0 version.** A custom guest needs no `--inner-vk-fingerprint` override; the canonical check passes as-is. (That flag is for non-RISC0 BN254 inputs, which carry a different VK.)
- Because the baked inner VK is unchanged, the outer constraint system is byte-identical, so **the outer proving/verifying keys and the MPC ceremony are reusable.** Changing the guest does not require a new ceremony.

All three scenarios below share the same core procedure — dump → setup → prove → verify → export, exactly as in [Usage](#usage). They differ only as noted.

**1. Your own custom RISC0 guest.** The bls-snark procedure is unchanged. What differs is entirely downstream:
- Which `image_id` / `claim_digest` you expect. Pin it at prove time with `--expect-claim-digest` (and `--expect-control-root` / `--expect-bn254-control-id` for the platform constants); the on-chain validator reproduces `claim_digest` from your guest's `image_id`.
- The journal layout and meaning, which are application-specific. bls-snark never parses the journal in-circuit — the dumper only hashes the whole blob for the binding self-check — so the layout is purely a downstream-validator concern.

**2. Updating the oakshield guest.** Same as case 1. When the guest code changes its `image_id` changes, but the inner VK, the outer constraint system, and the ceremony are unchanged. Update the expected `image_id` pin, and check whether the journal struct layout changed — if it did, the downstream validator's journal parsing changes, not bls-snark.

**3. Bumping the risc0 version.** This is the only change that rotates the inner VK, and therefore the outer constraint system, requiring a fresh ceremony. Follow [Updating risc0 pins](#updating-risc0-pins), then re-run the production setup below.

---

## Production trusted setup

The single-party `setup` path runs gnark's `groth16.Setup`. That key is toxic-waste-equivalent and **must not** back any production deployment. It is **refused by default**: you must pass `--insecure-dev-setup` (or set `BLS_SNARK_INSECURE_DEV_SETUP=1`) to confirm dev/test use — otherwise the command errors and points you at the MPC path. When it does run it emits a multi-line `INSECURE` banner and stamps the result JSON with `"mode": "insecure-dev-setup"`.

For production, run an MPC ceremony externally and feed the result back in via passthrough mode. The wrapper compiles the outer circuit deterministically, so the ceremony's keys are valid against the same R1CS the wrapper produces.

### Procedure

1. **Compile the outer circuit and emit the constraint system only.** No setup, no keys yet.
   ```bash
   bls-snark setup \
       --inner-source risc0 \
       --inner-vk testdata/risc0/verification_key.json \
       --emit-ccs-only --out-ccs out/outer.ccs
   ```

2. **Obtain a BLS12-381 Phase 1 (Powers of Tau) SRS.** Use a published ceremony — `2^21` cycles is enough for our ~1.2M outer constraints; `2^23` gives headroom. Options:
   - **Aztec BLS12-381 PPoT** — up to `2^28`, published with a per-contribution transcript at https://github.com/AztecProtocol/setup-mpc-common.
   - **Filecoin BLS12-381 PPoT** — up to `2^27`, archived at https://github.com/arielgabizon/perpetualpowersoftau/blob/master/0080_aztec_response/bls12-381.
   - Verify the file's SHA-256 against the ceremony's published manifest before using.

3. **Run Phase 2** against `out/outer.ccs` using gnark's `backend/groth16/bls12-381/mpcsetup` package. Each contributor adds a contribution; at least three independent, non-colluding contributors is the practical minimum, more is better. Every contributor must destroy their randomness after contributing.

4. **Finalize** to extract `out/outer_pk.bin` and `out/outer_vk.bin` from the last transcript. Run the ceremony's own `verify-srs` against the final keys before using them.

5. **Feed the keys back into the wrapper.** Must use the same `--inner-vk` and any VK-fingerprint settings as in step 1 — otherwise the circuit differs and the keys won't work.
   ```bash
   bls-snark setup \
       --inner-source risc0 \
       --inner-vk testdata/risc0/verification_key.json \
       --pk-input out/outer_pk.bin \
       --vk-input out/outer_vk.bin
   ```
   The result JSON now reports `"mode": "passthrough"` and no `INSECURE` warning.

### What the wrapper checks vs what it doesn't

When `--pk-input` / `--vk-input` are supplied:

- ✓ Compiles the outer circuit deterministically and produces the canonical `ccs`.
- ✓ Decodes both keys for BLS12-381.
- ✓ Cross-checks the keys against the compiled circuit before accepting them: matching wire, public-input and commitment counts and a matching domain size, plus identical setup elements (`[α]₁`, `[β]₂`, `[δ]₂`) shared between the pair. This rejects a mismatched key pair or keys built for a different circuit, and fails the command closed.
- ✗ Does **not** by itself prove the keys encode this exact circuit's QAP — that guarantee comes from a full prove → verify round trip (which the normal prove and verify commands perform) and from the ceremony's own `verify-srs` step. Run both.

---

## Security model

### Built-in checks

| Check | Where | Default behaviour | Override |
|---|---|---|---|
| Inner BN254 proof native-verifies | every `prove` call | abort if invalid | none — soundness-critical |
| Outer circuit's `InnerWitness` is `gnark:",public"` | compile-time | enforced | none — soundness-critical |
| Inner VK matches canonical risc0 VK fingerprint | `setup --inner-source risc0` | abort if mismatch | `--inner-vk-fingerprint <hex>` (lock in alternative) or `--insecure-no-vk-check` |
| Receipt `verifier_parameters` matches risc0 default | `risc0-dump` | abort if mismatch | `--accept-fingerprint <hex>` or `--insecure-skip-fingerprint-check` |
| `bn254_control_id` LE value < r_BN254 | `risc0-dump` | abort if ≥ r | none — would diverge from risc0's behaviour |
| Outer-proof / outer-public-input binding | `verify` / `groth16.Verify` | tamper → reject (regression-tested) | none |

### Threat model assumptions

- **Trusted setup (production):** the wrapper trusts that any externally-supplied `(pk, vk)` came from a properly-run MPC ceremony. Pass in keys from a single-party `groth16.Setup` and the wrapper happily uses them — garbage in, garbage out. Always run the ceremony's `verify-srs`.
- **Phase 1 SRS:** the wrapper trusts whichever Powers of Tau you chose. Document the source URL + SHA-256 of the file you used.
- **Deterministic compile:** the wrapper trusts that gnark's `frontend.Compile` is deterministic across builds (it is, modulo gnark version changes). Pin gnark exactly.
- **Inner VK correctness:** the canonical risc0 VK fingerprint is embedded as a Go constant. If risc0 rotates its ceremony, the constant must be updated explicitly (process documented in [development → updating risc0 pins](#updating-risc0-pins)).
- **Journal propagation:** the outer proof commits to `claim_digest` only. The downstream verifier needs the journal bytes to recompute that digest. `export --journal` carries them through.

### Setup modes (visible in stdout JSON `"mode"` field)

```
bls-snark setup --insecure-dev-setup ...         "mode": "insecure-dev-setup"   (dev only; refused without the flag)
bls-snark setup --emit-ccs-only ...              "mode": "emit-ccs-only"        (ceremony handoff)
bls-snark setup --pk-input ... --vk-input ...    "mode": "passthrough"          (production)
```

---

## Measured numbers

Reference machine: 8 core / 32 GB RAM, Linux x86-64. CPU only (no GPU acceleration).

| Phase | Inner circuit | Outer constraints | Outer setup time | Outer prove time | Outer proof size |
|---|---|---:|---:|---:|---:|
| dev (cubic) | `x^3 + x + 5 == y` (3 constraints) | 766,622 | 86.3 s | 35.8 s | 292 B |
| RISC0 | `risc0_groth16::verifying_key()` (5 publics) | 1,127,541 | 131.8 s | 58.1 s | 292 B |

Outer-proof byte breakdown (both phases): `Ar(48) + Bs(96) + Krs(48) + slice_header(4) + Pedersen_Commitment(48) + CommitmentPok(48) = 292`. The commitment + PoK are part of gnark's native proof format (the std-recursion verifier reaches `std/multicommit` internally); Cardano's `proof.bin` keeps only the `Ar | Bs | Krs` slice (192 B).

---

## On-chain verifier development

The Cardano / Aiken validator that consumes `out/cardano/*.bin` is out of scope for this repo. [`internal/cardano_ref/`](./internal/cardano_ref/) ships a working reference implementation as the porting target:

- **Pure-Go reference verifier** — every primitive maps 1:1 to a Plutus/Aiken builtin (SHA-256, big-int reduction, G1/G2 decompress, scalar-mul, add, neg, pairing check). No MSM helpers, no gnark `Verify` shortcuts.
- **Hex oracle** — `go test ./internal/cardano_ref/ -v -run PrintIntermediates` prints every intermediate value (`h_0` after each step of `expand_message_xmd`, Pedersen pairing inputs, the reduced commitment hash). An Aiken port diffs against this transcript.
- **Tamper / acceptance gates** — `TestReferenceVerifierAccepts` confirms the reference accepts what gnark accepts; `TestReferenceMatchesGnarkOnTamper` confirms it rejects what gnark rejects.

[`internal/cardano_ref/README.md`](./internal/cardano_ref/README.md) has the builtin-mapping table and the step-by-step validation workflow.

---

## Repository layout

```
bls-snark/
├── cmd/bls-snark/         # main: cobra root wiring subcommands
├── internal/
│   ├── cli/                  # setup, prove, verify, export subcommands
│   ├── circuit/              # OuterCircuit (BN254-in-BLS12-381 verifier)
│   ├── inner/                # cubic + risc0 inner-proof sources, VK fingerprint
│   ├── parser/               # snarkjs JSON → native gnark BN254 types
│   ├── serialize/            # gnark binary I/O + Cardano-minimal v2 byte formats
│   ├── cardano_ref/          # pure-Go reference verifier (oracle for Aiken port)
│   └── logging/              # zerolog wiring (logs → stderr; JSON → stdout)
├── tools/
│   └── risc0-dump/           # Rust: bincode Receipt → snarkjs JSON + journal.bin
├── testdata/risc0/           # real oakshield receipt fixtures (JSON + journal + chain_proof.bin); alt/ second fixture
├── Makefile                  # build / smoke / wrap-risc0 / test / lint
├── go.mod / go.sum
├── LICENSE                   # Apache 2.0
└── README.md                 # this file
```

---

## Development

### Tests

```bash
go test ./...                 # unit + integration tests; ~350s total when uncached
go vet ./...
gofmt -l .                    # expect no output
golangci-lint run --timeout=5m ./...
```

Headline tests, grouped by what they prove:

**Wrapper soundness — inner→outer wrap is mathematically correct:**
- `internal/parser:TestRISC0VerifyAgainstTestdata` — native BN254 Groth16 verify of the dumper's snarkjs JSON. Ground truth for the dumper.
- `internal/serialize:TestOuterVerifyFromInnerPublicInputsDirectly` — canonical-lift the inner public inputs, outer-verify, must succeed. Strongest input/output equivalence statement.
- `internal/serialize:TestOuterVerifyTamperedPublicFails` / `TestOuterVerifyTamperedProofFails` — outer verifier binds proof + public inputs.
- `internal/serialize:TestCardanoPublicLimbRoundTrip` — recompose the 5 inner BN254 Frs from `public.bin` limbs; assert equality with originals.

**Cardano-minimal v2 byte format:**
- `internal/serialize:TestCardanoVKv2_RoundTripVerifies` — parse the v2 bytes back into native gnark types by hand (no gnark deserialisers); run `groth16.Verify`. Anything missing from v2 fails here.
- `internal/serialize:TestCardanoVKv2_Sizes` — pin exact byte sizes for the fixture (vk=1676, proof=388).

**Aiken-side reference:**
- `internal/cardano_ref:TestReferenceVerifierAccepts` — reference verifier accepts the real `out/cardano/*.bin`.
- `internal/cardano_ref:TestReferenceMatchesGnarkOnTamper` — reference and gnark agree on rejection.
- `internal/cardano_ref:TestReferencePrintIntermediates` — every intermediate value as a hex transcript.
- `internal/cardano_ref:TestJournalToOuterPublicOracle` — 5 BN254 scalars ↔ 20 BLS12-381 limbs reconstruction transcript.

**Built-in guards:**
- `internal/inner:TestLoadRISC0_*` (4 tests) — canonical-VK fingerprint check + override paths + insecure-skip path.
- `internal/inner:TestCanonicalFingerprintMatchesEmbeddedConst` — regression on the embedded canonical risc0 VK fingerprint.

**Gold reference:**
- `internal/circuit:TestCanonicalEmulatedConstantCounts` — compiles upstream gnark's BW6_761→BN254 pattern and the BN254→BLS12_381 wrapper in the same harness; pins the constraint count against a canonical baseline. Slow (~5 min, two full setup+prove cycles).

### Make targets

```bash
make build           # → bin/bls-snark
make smoke           # build + dev (cubic) end-to-end; exits 0 on success
make wrap-risc0      # build + risc0 end-to-end including Cardano export; needs testdata/risc0/*.json
make test            # full Go test suite
make test-short      # -short, CI-fast
make lint            # golangci-lint
make fmt             # goimports + gofmt
make clean           # rm -rf bin/ out/
```

### Updating risc0 pins

When risc0 rotates its ceremony (or you bump the dumper's pinned crates to a release that ships different defaults), several constants must move together. Drift between them causes silent failures.

1. **`tools/risc0-dump/Cargo.toml`** — bump `risc0-zkvm` / `risc0-groth16` / `risc0-circuit-recursion` together. Re-build the dumper.
2. **`tools/risc0-dump/src/main.rs::build_vk_json`** — if `risc0_groth16::verifying_key()` changed, regenerate the embedded decimal-string constants from the new `risc0/groth16/src/verifier.rs`.
3. **Regenerate `testdata/risc0/verification_key.json`** by re-running the dumper. Compare to the previous file to spot unexpected drift in α/β/γ/δ/IC values.
4. **Update `internal/inner/vk_fingerprint.go::CanonicalRISC0VKFingerprint`** with the new SHA-256 from `go test ./internal/inner -run TestPrintCanonical -v`. The companion test `TestCanonicalFingerprintMatchesEmbeddedConst` fails loudly until you do.
5. **Re-run `make wrap-risc0`** on the new testdata to confirm end-to-end.

---

## Pinned dependencies

### Go side (`go.mod`)

| Package | Version |
|---|---|
| `github.com/consensys/gnark` | v0.15.0 |
| `github.com/consensys/gnark-crypto` | v0.20.1 |
| `github.com/rs/zerolog` | v1.34.0 |
| `github.com/spf13/cobra` | v1.10.2 |
| Go toolchain | 1.25.7 |

### Rust side (`tools/risc0-dump/Cargo.toml`)

Pinned to match the version oakshield (the production producer) resolves to:

| Crate | Version |
|---|---|
| `risc0-zkvm` | =3.0.3 |
| `risc0-groth16` | =3.0.2 |
| `risc0-circuit-recursion` | =4.0.2 |
| `risc0-zkp` | =3.0.2 |
| `risc0-binfmt` | =3.0.2 |

Upgrades are deliberate, not automatic. See [Updating risc0 pins](#updating-risc0-pins).

---

## License

Apache License, Version 2.0. See [`LICENSE`](./LICENSE) for the full text.

```
Copyright 2026 Torben Poguntke
Licensed under the Apache License, Version 2.0
```
