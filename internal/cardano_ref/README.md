# cardano_ref — Go reference verifier for the Cardano-minimal v2 format

A dependency-light Go implementation of the on-chain Groth16-BLS12-381 verification equation for proofs produced by `bls-snark`. Reference code; optimised for clarity and 1:1 mapping with the Aiken / Plutus builtin surface.

The wrapper itself uses gnark's own verifier. This package exists as a byte-for-byte oracle for on-chain ports.

---

## When to read this

You are implementing a Cardano on-chain Groth16-BLS12-381 verifier in Aiken (or any Plutus-emitting language) that consumes the byte files in `out/cardano/` after `make wrap-risc0`. You want:

- Which primitives to call.
- The hash function and DST.
- The verification equation end-to-end.
- Expected intermediate values for the existing test fixture, so each step of your implementation can be verified as you write it.

If you're consuming the wrapper as a black box (proof bytes go into a dApp redeemer; the validator runs on chain), read the main repo `README.md` instead.

---

## Quick start

```bash
# 1. Make sure the wrapper has produced a real wrap.
make wrap-risc0
# → writes out/cardano/{vk,proof,public,journal}.bin + risc0_params.json

# 2. Run the reference verifier against the real bytes (passes if the
#    wrap is mathematically sound).
go test ./internal/cardano_ref/ -v -run TestReferenceVerifierAccepts

# 3. Dump every intermediate value the Aiken port needs to reproduce.
go test ./internal/cardano_ref/ -v -run TestReferencePrintIntermediates

# 4. Dump the journal-lifting oracle: 5 BN254 Fr scalars (input form) +
#    20 BLS12-381 Fr limbs (emulated form) in hex + decimal.
go test ./internal/cardano_ref/ -v -run TestJournalToOuterPublicOracle
```

The third command prints every intermediate value as hex/decimal — `h_0` after each step of the SHA-256 expand, the Pedersen pairing inputs, etc. Compare against the equivalent step in your Aiken port; any divergence pinpoints the bug.

The fourth command is the journal-lifting oracle. It logs the 5 BN254 Fr scalars risc0 derives from `(journal, image_id, control_root, bn254_control_id_fr)` and the 20 BLS12-381 Fr limbs gnark's emulated verifier ingests, and verifies the reconstruction `inner_j = Σ limb_{j,i} · 2^{64·i}`. Any port re-implementing the BN254→BLS12-381 decomposition diffs against this transcript.

---

## risc0_params.json sidecar

`make wrap-risc0` also writes `out/cardano/risc0_params.json` carrying
the three platform constants any downstream verifier needs to bake in:

```json
{
  "version": "1",
  "image_id":            "<64 hex>",
  "control_root":        "<64 hex>",
  "bn254_control_id_fr": "<decimal string>"
}
```

- `image_id` — the 32-byte RISC0 program identifier (`g16.claim.pre.digest()`).
- `control_root` — the canonical RISC0 ceremony control root in effect.
- `bn254_control_id_fr` — the BN254 Fr scalar (post-LE-reduction), i.e.
  the 5th element of the inner public-input vector. Decimal so consumers
  can paste it straight into an Aiken `vk.ak` without further reduction.

The schema is frozen at version `"1"`; any breaking change bumps the
version, so consumers can refuse mismatched files instead of silently
parsing stale data.

---

## The verification equation

For each commitment `j` in `0..nC-1`:

```
prehash_j = commitment_uncompressed_j ‖ concat over k in committed_j: publicWitness[k-1]
h_j       = HashToField(DST = "bsb22-commitment", prehash_j)
            └── = SHA-256 expand_message_xmd → reduce mod r_BLS12-381
```

Build `kSum`:

```
kSum = K[0]
     + Σ_{i=0..nbPub-1}  publicWitness[i] · K[i+1]
     + Σ_{j=0..nC-1}     h_j               · K[nbPub+1+j]
     + Σ_{j=0..nC-1}     commitment_j                          (raw G1 addition)
```

**Main Groth16 pairing check:**

```
e(A, B) == e(α, β) · e(kSum, γ) · e(C, δ)
```

equivalently (negate A so the right-hand side becomes identity):

```
e(-A, B) · e(α, β) · e(kSum, γ) · e(C, δ) == 1_GT
```

**Pedersen pairing check** (this repo only emits `nC = 1`; gnark's
`fr.Hash` challenge folding short-circuits to a no-op in that case):

```
e(commitment_0, GSigmaNeg_0) · e(pok_0, G_0) == 1_GT
```

Both pairing checks must pass. If `nC > 1` were ever emitted (it isn't
today), the Pedersen check would need to derive a challenge via
`HashToField(DST = "G16-BSB22", concat h_j)` and fold the commitments /
PoKs by powers of that challenge. The wrapper would have to bump the
format version before that becomes relevant.

---

## Byte format (Cardano-minimal v2)

All G1/G2 compressed encodings are IETF/Zcash (48 B / 96 B respectively).
The 96-byte uncompressed G1 is `curve.G1Affine.Marshal()` = `x_be(48) ‖ y_be(48)`
with no flags, no length prefix.

### `vk.bin`

```
α₁ (48)
β₂ (96)
γ₂ (96)
δ₂ (96)
uint32 BE: ic_count
ic[ic_count]                    ← each 48 B compressed G1
uint32 BE: nC
for j = 0..nC-1:
  pedersen_G[j] (96)
  pedersen_GSigmaNeg[j] (96)
  uint32 BE: len(committed_j)
  committed_j[len(committed_j)] ← each uint32 BE; 1-indexed into publicWitness
```

For our test fixture (`nb_inner_pub=5`, `nC=1`): `ic_count=22`,
`committed_0 = [1, 2, …, 20]`. Total size: **1676 B**.

### `proof.bin`

```
a_g1 (48)
b_g2 (96)
c_g1 (48)
uint32 BE: nC
for j = 0..nC-1:
  commitment[j] compressed (48)
  commitment[j] uncompressed (96)     ← fed VERBATIM to HashToField; do not parse
commitment_pok (48)
```

For our test fixture: total size **388 B**.

The dual compressed+uncompressed commitment is a deliberate choice for
Aiken stdlib v3, which can `compress` an in-memory G1Element but has no
public API for emitting the 96-B uncompressed form. The compressed copy
gets used for pairing arithmetic (via `g1.decompress`); the uncompressed
copy gets passed straight into the SHA-256 hash chain.

There is **no on-chain consistency check** between the two bytes — a
mismatch silently breaks the pairing equation, so the verifier rejects.
Don't add a `decompress(compressed) == from_bytes(uncompressed)` short-
circuit: it could mask a malicious-but-consistent-bytes attack class on
some implementations.

### `public.bin`

```
uint32 BE: n_inner_pub
uint32 BE: n_limbs_per_scalar           ← always 4 for BN254-in-BLS12-381
publicWitness[n_inner_pub × n_limbs_per_scalar]   ← each 32 B BE BLS12-381 fr
```

For our test fixture: `n_inner_pub=5`, `n_limbs=4`, total size **648 B**.

Limb 0 is the lowest 64 bits of the corresponding inner BN254 Fr; limb 3
is the highest. Recombination: `inner_fr_i = Σ_{j=0..3} limb[i·4+j] · 2^{64·j}`.

### `journal.bin`

Raw bytes of `risc0_zkvm::Receipt.journal`. The wrapper doesn't interpret
this; whoever consumes the wrap recomputes the RISC0 claim digest from
the journal and confirms it matches `(h_0_low ‖ h_0_high)` of the outer
public inputs.

---

## API

```go
// Hash-to-field.
ExpandMessageXmdSHA256(msg, dst []byte, lenInBytes int) ([]byte, error)
CommitmentHashH0(commitmentUncompressed []byte, publicWitnessBE [][]byte) (*big.Int, error)

// Byte-format parsers (hand-rolled, no gnark binary deserialisers).
ParseVK(data []byte) (*VK, error)
ParseProof(data []byte) (*Proof, error)
ParsePublic(data []byte) (*Public, error)

// Full verifier.
VerifyOuter(vk *VK, proof *Proof, public *Public) error

// Constants.
const DSTCommitment        = "bsb22-commitment"
const DSTPedersenChallenge = "G16-BSB22"            // only used if nC > 1
const BLS12_381_FrModulusHex = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
func BLS12_381_FrModulus() *big.Int
```

`VK`, `Proof`, `Public` are plain structs with one field per byte-format
element. Inspect them directly when developing the Aiken parser.

---

## Aiken builtin mapping

| Go reference call | Aiken / Plutus equivalent |
|---|---|
| `crypto/sha256.New() / Write / Sum` | `sha2_256` |
| `math/big.Int.SetBytes(be)` | `bytestring_to_integer(BigEndian, _)` |
| `math/big.Int.Mod(x, r)` | `x % r` (with `r` as a constant) |
| `bls12381.G1Affine.SetBytes(48 B)` | `bls12_381_g1_uncompress` |
| `bls12381.G2Affine.SetBytes(96 B)` | `bls12_381_g2_uncompress` |
| `G1Affine.ScalarMultiplication(p, n)` | `bls12_381_g1_scalar_mul(n, p)` |
| `G1Jac.AddMixed(p) / G1Affine.Add(p, q)` | `bls12_381_g1_add` |
| `G1Affine.Neg(p)` | `bls12_381_g1_neg` |
| `bls12381.PairingCheck(g1s, g2s)` | `bls12_381_miller_loop` + `bls12_381_mul_miller_loop_result` + `bls12_381_final_verify` |

The Go reference uses **no** gnark MSM helpers and **no** gnark Verify —
every loop is explicit, every pairing is a single `PairingCheck` call.
The structure is what you should mirror in Aiken; the only thing you
need to translate is the surface API.

---

## Tests

Four tests, all under `go test ./internal/cardano_ref/`:

### `TestReferenceVerifierAccepts`

Runs the entire reference verifier against `out/cardano/*.bin`. Passes
iff the wrap is mathematically valid. If your changes to the wrapper's
byte format would break the on-chain verifier, this test fails.

### `TestReferenceMatchesGnarkOnTamper`

Flips one byte of the public-witness limbs; both the reference and
gnark's `groth16.Verify` reject. If only one of them rejected, the
reference would be either over-permissive (soundness bug) or
over-strict (false rejection bug). Pinning this prevents drift.

### `TestReferencePrintIntermediates`

The Aiken author's tool. `t.Logf`-dumps every intermediate value with
hex / decimal output. The output for the current fixture looks like:

```
---- structural ----
n_inner_pub                    = 5
n_limbs_per_scalar             = 4
len(public.LimbsBE)            = 20
vk.NC                          = 1
len(vk.IC)                     = 22 (= 1 one-wire + 20 publics + 1 commitments)
vk.CommittedIndices[0]         = [1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20]

---- h_0 hash-to-field (DST = "bsb22-commitment") ----
commitment[0] uncompressed (96 B) = <hex…>
h_0 prehash length                = 736 B (= 96 + 32·20)
h_0 expand_message_xmd (48 B)     = <hex…>
h_0 (mod r, 32 B BE)              = 583fb815c64b4741d8f563675d95fdc4126c0b3e62f11c535ab9f2e27313764a
h_0 (mod r, decimal)              = 39916112548777971330273256408859703309294737451235651812796564506989420574282

---- pedersen pairing inputs ----
pedersen_G[0] (compressed)         = <hex…>
pedersen_GSigmaNeg[0] (compressed) = <hex…>
commitment[0] compressed (48 B)    = <hex…>
commitment_pok compressed (48 B)   = <hex…>

Pedersen check:  e(commitment, GSigmaNeg) · e(pok, G) == 1
```

Use these to gate the development of your Aiken implementation:

1. Implement `commitment_hash_h0` in Aiken. Run it against the same
   `commitment[0] uncompressed (96 B)` + the same 20 limbs. The
   `expand_message_xmd (48 B)` value must match hex-for-hex. Then the
   `h_0 (mod r, 32 B BE)` value must match.
2. Implement the kSum loop. Pin the final kSum G1 point (you can add
   another t.Logf in the Go reference to dump it; the existing tests
   verify pairing acceptance, which is a stricter check).
3. Implement the two pairing checks. Both must accept.
4. End-to-end: your Aiken verifier accepts iff `TestReferenceVerifierAccepts`
   accepts. Tamper any byte and both must reject.

### `TestJournalToOuterPublicOracle`

The journal-lifting transcript. Logs the 5 BN254 Fr scalars risc0-dump
derives from `(journal, image_id, control_root, bn254_control_id_fr)`
alongside the 20 BLS12-381 Fr limbs that the emulated outer verifier
ingests, and verifies the reconstruction
`inner_j = Σ limb_{j,i} · 2^{64·i}`. Any downstream re-implementing the
BN254 → BLS12-381 decomposition (Cardano on-chain, Solidity, off-chain
auditor) diffs against this transcript.

---

## Validation strategy for the Aiken implementation

Treat `TestReferenceVerifierAccepts` as the "wrapper output is well-formed"
oracle. Treat `TestReferencePrintIntermediates` as the "your hash / loop
implementation matches mine" oracle. Treat `TestReferenceMatchesGnarkOnTamper`
as the "your verifier is not too permissive" oracle.

Recommended workflow:

```bash
# Step 1: regenerate fixtures.
make wrap-risc0

# Step 2: capture the intermediate values for your Aiken test suite.
go test ./internal/cardano_ref/ -v -run PrintIntermediates > aiken-oracle.txt

# Step 3: develop your Aiken implementation, checking each step against
#         the oracle.

# Step 4: end-to-end — your Aiken validator on chain MUST accept the same
#         out/cardano/*.bin bytes that pass the Go reference.
```

If you ever bump the wrapper's byte format, all three of `TestReferenceVerifierAccepts`,
the intermediate-value oracle, and your Aiken test suite will need to be
regenerated together. The Go reference being green is the gate.

---

## Limitations

- **`nC = 1` only.** The wrapper today produces a single commitment, so
  the reference's `VerifyOuter` rejects anything with a different commit
  count. Generalising to `nC > 1` would mean implementing the Pedersen
  challenge derivation via `ExpandMessageXmdSHA256(commitments, "G16-BSB22", 48)`
  and folding commitments / PoKs by powers of that challenge.
- **BLS12-381 outer only.** The DST constants and the field modulus are
  hardcoded for this curve.
- **No subgroup-check fast-path.** gnark's `bls12381.PairingCheck` does
  the subgroup checks internally; Aiken's `bls12_381_*_uncompress` builtins
  do them too. If your validator implements its own decompression, make
  sure subgroup membership is enforced before passing to the pairing.
- **Reference is not gas-optimised.** The explicit loop over IC entries
  performs `nbPub + nC` scalar multiplications. An on-chain implementation
  can keep the same structure (Aiken's scalar multiplication is a builtin
  primitive) — there's no MSM-style optimisation needed at the proof
  sizes the wrapper produces.

---

## File map

- [`ref.go`](./ref.go) — implementation.
- [`ref_test.go`](./ref_test.go) — `TestReferenceVerifierAccepts`, `TestReferenceMatchesGnarkOnTamper`, `TestReferencePrintIntermediates`.
- [`journal_oracle_test.go`](./journal_oracle_test.go) — `TestJournalToOuterPublicOracle`.
