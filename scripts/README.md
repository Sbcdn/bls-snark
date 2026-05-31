# RISC0 testdata

The wrapper expects three snarkjs-style JSON files plus two sidecars under `testdata/risc0/`:

```
testdata/risc0/
  proof.json
  public.json
  verification_key.json
  journal.bin              # raw RISC0 journal bytes (sidecar, copied through to Cardano output)
  risc0_params.json        # schema v2: image_id, control_root, bn254_control_id_fr, claim_digest
```

The `.json` files, `journal.bin`, and the raw `chain_proof.bin` receipt (793 B) are all committed, so the dumper runs end-to-end from a fresh clone. A second verify-only fixture lives under `testdata/risc0/alt/` with its own `chain_proof.bin`. Both are real Mainnet oakshield receipts — the bytes are a zero-knowledge proof carrying only public chain data. To regenerate the JSON from the receipt:

```bash
cargo build --release --manifest-path tools/risc0-dump/Cargo.toml

./tools/risc0-dump/target/release/risc0-dump \
    --input   testdata/risc0/chain_proof.bin \
    --out-dir testdata/risc0
```

> **Build troubleshooting — `risc0-circuit-recursion` S3 SHA-mismatch.** The build script
> downloads `recursion_zkr.zip` from S3 and verifies its SHA-256
> (`744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849`); a stale/partial cached
> zip or a poisoned CDN edge makes it `panic` (`build.rs:80`, no retry). Fix:
> `cargo clean -p risc0-circuit-recursion && cargo build` (evicts the bad cache, re-downloads).
> If that keeps failing (locked-down CI, bad edge), supply the file locally and bypass S3:
> `cp <verified recursion_zkr.zip> ~/.cache/risc0-zkrs/ && export RECURSION_SRC_PATH=$HOME/.cache/risc0-zkrs/recursion_zkr.zip`
> then clean+rebuild. The build script verifies the supplied file against the same SHA, so there's
> no trust loss. (Hash MUST be `744b999f…d8849`.)

> **No fingerprint override needed.** The fixture's receipt carries the canonical `verifier_parameters` fingerprint `73c457ba…eedc` (= `Groth16ReceiptVerifierParameters::default().digest()`), so the dumper accepts it with **default flags**. The earlier `--accept-fingerprint 834d…1427` workaround (for the pre-fix producer) is retired. `--accept-fingerprint` still exists for legacy/quirky receipts; when set, the dumper prints a `WARN:` line on the success path so the override can't be missed in pipeline logs. **Never** pass `--insecure-skip-fingerprint-check` on a production receipt.

## Producing a non-RISC0 input

The Go CLI is generic over any snarkjs-shaped Groth16-BN254 triple. If you have one from circom or snarkjs directly, drop it in `testdata/risc0/` and skip the dumper. The format expected:

- `proof.json` — `{ "pi_a": [x, y, "1"], "pi_b": [[c1, c0], [c1, c0], ["1","0"]], "pi_c": [x, y, "1"], "protocol": "groth16", "curve": "bn128" }`. **Fp2 elements are c1-first** (snarkjs / Ethereum convention).
- `public.json` — top-level array of decimal strings (one per public input).
- `verification_key.json` — `{ "protocol", "curve", "nPublic", "vk_alpha_1", "vk_beta_2", "vk_gamma_2", "vk_delta_2", "vk_alphabeta_12", "IC" }`. Fp2 elements c1-first.

For non-canonical VKs (anything other than `risc0_groth16::verifying_key()`), pass `--inner-vk-fingerprint <hex>` to `setup` to lock in the expected SHA-256 of the gnark-binary VK form.
