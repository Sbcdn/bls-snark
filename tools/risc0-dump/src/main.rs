//! risc0-dump — convert a RISC0 Groth16 `Receipt` (bincode) into snarkjs-style
//! JSON consumed by the Go `bls-snark` CLI.
//!
//! The Groth16 verification public-input vector is derived inside risc0-zkvm
//! from `(control_root, claim_digest, bn254_control_id)` via `split_digest`
//! (`risc0/groth16/src/verifier.rs`). Re-implementing that in Go would drift
//! across risc0 releases; this tool keeps the derivation in Rust and feeds
//! the Go side standard snarkjs decimal-string JSON.
//!
//! Output:
//!     <out-dir>/proof.json              — snarkjs ProofJson (pi_a, pi_b, pi_c)
//!     <out-dir>/public.json             — snarkjs PublicInputsJson (5 Fr values)
//!     <out-dir>/verification_key.json   — snarkjs VerifyingKeyJson (static risc0 VK)
//!     <out-dir>/journal.bin             — raw receipt journal bytes
//!     <out-dir>/risc0_params.json       — schema v1: image_id, control_root,
//!                                          bn254_control_id_fr

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use clap::Parser;
use num_bigint::BigUint;

use risc0_binfmt::Digestible;
use risc0_circuit_recursion::control_id::{ALLOWED_CONTROL_ROOT, BN254_IDENTITY_CONTROL_ID};
use risc0_groth16::{verifying_key, Seal, Verifier};
use risc0_zkp::core::digest::Digest;
use risc0_zkvm::{sha, Groth16ReceiptVerifierParameters, InnerReceipt, Receipt};

#[derive(Parser, Debug)]
#[command(
    about = "Convert a RISC0 Groth16 Receipt (bincode) into snarkjs-style JSON for bls-snark.",
    version
)]
struct Cli {
    /// Path to the bincode-serialized risc0_zkvm::Receipt (e.g. oakshield's chain_proof_*.bin).
    #[arg(long, value_name = "PATH")]
    input: PathBuf,

    /// Output directory for proof.json, public.json, verification_key.json.
    #[arg(long, value_name = "DIR", default_value = "./testdata/risc0")]
    out_dir: PathBuf,

    /// Override control_root (hex, 32 bytes). Defaults to ALLOWED_CONTROL_ROOT
    /// from risc0_circuit_recursion. Use only when verifying receipts from a
    /// non-default risc0 ceremony.
    #[arg(long, value_name = "HEX")]
    control_root: Option<String>,

    /// Override bn254_control_id (hex, 32 bytes). Defaults to BN254_IDENTITY_CONTROL_ID.
    /// The value, when read as a little-endian 256-bit integer, MUST be less
    /// than the BN254 scalar field modulus r — otherwise the resulting Fr
    /// could diverge from what risc0 itself produces (risc0's
    /// `Fr::deserialize_uncompressed` either rejects or silently stores
    /// unreduced bytes, depending on arkworks version). The default value
    /// fits comfortably.
    #[arg(long, value_name = "HEX")]
    bn254_control_id: Option<String>,

    /// Accept a receipt whose verifier_parameters fingerprint differs from
    /// the canonical `Groth16ReceiptVerifierParameters::default().digest()`.
    /// INSECURE — pass only when you've verified the receipt's ceremony
    /// independently.
    #[arg(long, value_name = "HEX")]
    accept_fingerprint: Option<String>,

    /// Skip the receipt's verifier_parameters fingerprint check entirely.
    /// INSECURE — only for local development.
    #[arg(long, default_value_t = false)]
    insecure_skip_fingerprint_check: bool,

    /// Override the image_id written to risc0_params.json (hex, 32 bytes).
    /// Use only when `g16.claim` is pruned and the operator knows the
    /// image_id out-of-band. Default: extract from the receipt claim.
    #[arg(long, value_name = "HEX")]
    image_id: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let receipt_bytes = std::fs::read(&cli.input)
        .with_context(|| format!("read receipt: {}", cli.input.display()))?;
    let receipt: Receipt = bincode::deserialize(&receipt_bytes)
        .with_context(|| format!("bincode-deserialize Receipt from {}", cli.input.display()))?;

    let g16 = match &receipt.inner {
        InnerReceipt::Groth16(g) => g,
        other => {
            return Err(anyhow!(
                "receipt.inner is not Groth16; got {:?}",
                std::mem::discriminant(other)
            ))
        }
    };

    if g16.seal.len() != 256 {
        return Err(anyhow!(
            "expected 256-byte BN254 Groth16 seal; got {}",
            g16.seal.len()
        ));
    }

    // Receipt fingerprint check. The receipt commits to a
    // (control_root, bn254_control_id, vk) tuple via `verifier_parameters`.
    // A mismatch with the pinned risc0 crate's defaults would silently
    // produce public inputs from the wrong tuple; fail loudly unless opted out.
    let expected_fingerprint = Groth16ReceiptVerifierParameters::default().digest::<sha::Impl>();
    if cli.insecure_skip_fingerprint_check {
        eprintln!("WARN: --insecure-skip-fingerprint-check set; not validating receipt verifier_parameters");
    } else {
        let accept = match cli.accept_fingerprint.as_deref() {
            Some(hex) => digest_from_hex(hex)?,
            None => expected_fingerprint,
        };
        // A canonical run is silent; an override surfaces a WARN on stderr
        // regardless of receipt content so it can't be missed in CI logs.
        if cli.accept_fingerprint.is_some() && g16.verifier_parameters == accept {
            eprintln!(
                "WARN: --accept-fingerprint set; receipt verifier_parameters digest {} accepted (canonical default is {})",
                hex::encode(g16.verifier_parameters.as_bytes()),
                hex::encode(expected_fingerprint.as_bytes()),
            );
        }
        if g16.verifier_parameters != accept {
            bail!(
                "receipt verifier_parameters fingerprint mismatch:\n   \
                 expected: {}\n   \
                 got:      {}\n\
                 \n\
                 The expected value is `Groth16ReceiptVerifierParameters::default().digest()` \
                 of the pinned risc0 crate. A mismatch means the receipt was produced under \
                 non-default ceremony parameters OR the producer populated this slot with the \
                 wrong digest type (a known oakshield bug populates it with the \
                 SuccinctReceiptVerifierParameters digest instead).\n\
                 \n\
                 To proceed against an existing receipt:\n  \
                   • pass --accept-fingerprint {} to accept this specific value, OR\n  \
                   • pass --insecure-skip-fingerprint-check (INSECURE — only for dev).",
                hex::encode(expected_fingerprint.as_bytes()),
                hex::encode(g16.verifier_parameters.as_bytes()),
                hex::encode(g16.verifier_parameters.as_bytes()),
            );
        }
    }

    let control_root = match cli.control_root {
        Some(ref hex) => digest_from_hex(hex)?,
        None => ALLOWED_CONTROL_ROOT,
    };
    let bn254_control_id = match cli.bn254_control_id {
        Some(ref hex) => digest_from_hex(hex)?,
        None => BN254_IDENTITY_CONTROL_ID,
    };
    // The canonical bn254_control_id fits in BN254 Fr as a little-endian
    // u256; a user override might not. Reject up front rather than silently
    // diverging from risc0's Fr derivation.
    assert_bn254_id_in_field(&bn254_control_id)
        .context("bn254_control_id is out of range — see --bn254-control-id help")?;
    let claim_digest = g16.claim.digest::<sha::Impl>();

    let public_inputs = compute_public_inputs(&control_root, &claim_digest, &bn254_control_id)?;
    eprintln!("control_root      = {}", hex::encode(control_root.as_bytes()));
    eprintln!("claim_digest      = {}", hex::encode(claim_digest.as_bytes()));
    eprintln!(
        "bn254_control_id  = {}",
        hex::encode(bn254_control_id.as_bytes())
    );
    for (i, p) in public_inputs.iter().enumerate() {
        eprintln!("public_inputs[{i}] = {}", fr_to_decimal(p));
    }

    let seal = Seal::decode(&g16.seal).map_err(|e| anyhow!("Seal::decode failed: {e}"))?;

    // Pre-verify the seal against the resolved (control_root, claim_digest,
    // bn254_control_id, canonical vk) tuple before emitting JSON, so an
    // invalid seal is diagnosed here rather than at downstream native verify.
    Verifier::new(
        &g16.seal,
        control_root,
        claim_digest,
        bn254_control_id,
        &verifying_key(),
    )
    .map_err(|e| anyhow!("Verifier::new (pre-verify): {e}"))?
    .verify()
    .map_err(|e| anyhow!("seal failed risc0_groth16 pre-verify: {e}"))?;
    eprintln!("seal_preverify     = OK");

    let proof_json = build_proof_json(&seal);
    let public_json = build_public_json(&public_inputs);
    let vk_json = build_vk_json();

    std::fs::create_dir_all(&cli.out_dir).with_context(|| {
        format!("mkdir output dir {}", cli.out_dir.display())
    })?;
    write_pretty(&cli.out_dir.join("proof.json"), &proof_json)?;
    write_pretty(&cli.out_dir.join("public.json"), &public_json)?;
    write_pretty(&cli.out_dir.join("verification_key.json"), &vk_json)?;

    // The outer proof commits only to claim_digest_{low,high}; downstream
    // verifiers need the journal bytes to recompute claim_digest.
    let journal_path = cli.out_dir.join("journal.bin");
    std::fs::write(&journal_path, &receipt.journal.bytes)
        .with_context(|| format!("write {}", journal_path.display()))?;
    eprintln!("journal            = {} bytes \u{2192} {}", receipt.journal.bytes.len(), journal_path.display());

    // image_id: CLI override wins. Otherwise read from claim.pre — Pruned
    // returns the image_id verbatim; Value(SystemState) requires pc==0 to
    // match risc0's canonical SystemState{pc:0, merkle_root}.digest() formula.
    let image_id = match cli.image_id.as_deref() {
        Some(hex) => digest_from_hex(hex)?,
        None => match &g16.claim {
            risc0_zkvm::MaybePruned::Value(claim) => match &claim.pre {
                risc0_zkvm::MaybePruned::Pruned(d) => *d,
                risc0_zkvm::MaybePruned::Value(state) => {
                    if state.pc != 0 {
                        bail!(
                            "claim.pre is a SystemState with pc={} (expected pc=0); \
                             SystemState.digest() under non-zero pc is not the canonical \
                             image_id. Pass --image-id <hex> if you know it out-of-band.",
                            state.pc,
                        );
                    }
                    claim.pre.digest::<sha::Impl>()
                }
            },
            risc0_zkvm::MaybePruned::Pruned(_) => bail!(
                "receipt claim is pruned — image_id cannot be recovered from the \
                 receipt alone. Pass --image-id <hex> if you know it out-of-band.",
            ),
        },
    };
    // Journal ↔ claim_digest binding self-check:
    // the exported journal + resolved image_id must reproduce the claim_digest
    // the proof is bound to. This also asserts the final claim is ok()-shaped
    // (empty assumptions, Halted(0), no input) — the property the on-chain
    // claim_digest reproduction depends on. A swapped/padded journal, or a
    // non-ok()-shaped receipt, aborts here rather than producing a wrap whose
    // journal doesn't match its bound claim.
    {
        let recomputed = reproduce_claim_digest(image_id, &receipt.journal.bytes);
        if recomputed != claim_digest {
            bail!(
                "journal + image_id do not reproduce claim_digest — the receipt is not \
                 ok()-shaped (non-empty assumptions / non-Halted(0) / non-empty input) or the \
                 journal/image_id don't match the claim. expected {}, recomputed {}.",
                hex::encode(claim_digest.as_bytes()),
                hex::encode(recomputed.as_bytes()),
            );
        }
        eprintln!("journal_binding    = OK (claim_digest reproduced from journal+image_id)");
    }

    let params_path = cli.out_dir.join("risc0_params.json");
    // Schema v2 adds claim_digest (the journal-bound value). Downstream readers
    // accept v1 and v2 (see internal/cli/prove.go::readRISC0Params).
    let params_json = serde_json::json!({
        "version": "2",
        "image_id": hex::encode(image_id.as_bytes()),
        "control_root": hex::encode(control_root.as_bytes()),
        "bn254_control_id_fr": fr_to_decimal(&public_inputs[4]),
        "claim_digest": hex::encode(claim_digest.as_bytes()),
    });
    write_pretty(&params_path, &params_json)?;
    eprintln!("image_id           = {}", hex::encode(image_id.as_bytes()));
    eprintln!("risc0_params       = {}", params_path.display());

    // Structured stdout result. Built via serde_json so an out-dir containing
    // a quote/backslash can't produce malformed JSON.
    let result = serde_json::json!({
        "out_dir": cli.out_dir.display().to_string(),
        "proof": "proof.json",
        "public": "public.json",
        "vk": "verification_key.json",
        "journal": "journal.bin",
        "risc0_params": "risc0_params.json",
        "n_public": public_inputs.len(),
    });
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

// assert_bn254_id_in_field checks that the supplied digest, read as a
// little-endian 256-bit integer (the way risc0's Fr derivation interprets
// it), fits in the BN254 scalar field. Without this, an override whose LE
// value ≥ r would diverge from risc0's `Fr::deserialize_uncompressed`
// behaviour (which either rejects or stores unreduced bytes).
fn assert_bn254_id_in_field(d: &Digest) -> Result<()> {
    // BN254 r in big-endian bytes: 0x30644e72…0000001.
    const BN254_R_BE: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
        0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
        0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
        0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
    ];
    let r = BigUint::from_bytes_be(&BN254_R_BE);
    let v = BigUint::from_bytes_le(d.as_bytes());
    if v >= r {
        bail!(
            "control_id LE value ({}) is ≥ BN254 r ({}); risc0's Fr derivation would either reject or silently store unreduced bytes, so our reduction would diverge. Use a different value.",
            v, r
        );
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// Public-input derivation — mirrors risc0/groth16/src/verifier.rs::Verifier::new
// and split_digest. Output order: [cr_low, cr_high, claim_low, claim_high, id_fr].
// ----------------------------------------------------------------------------

fn compute_public_inputs(
    control_root: &Digest,
    claim_digest: &Digest,
    bn254_control_id: &Digest,
) -> Result<[Fr; 5]> {
    let (a0, a1) = split_digest(control_root);
    let (c0, c1) = split_digest(claim_digest);

    // Per risc0: bn254_control_id has its bytes reversed in place, then is
    // parsed as a single Fr (with implicit modular reduction).
    let mut id_bytes = bn254_control_id.as_bytes().to_vec();
    id_bytes.reverse();
    let id_fr = fr_from_be_bytes_reduced(&id_bytes);

    Ok([a0, a1, c0, c1, id_fr])
}

/// Split a 32-byte digest into (low_128, high_128) Fr scalars, matching
/// risc0/groth16/src/verifier.rs::split_digest.
fn split_digest(d: &Digest) -> (Fr, Fr) {
    let big_endian: Vec<u8> = d.as_bytes().iter().rev().cloned().collect();
    let middle = big_endian.len() / 2;
    let (high, low) = big_endian.split_at(middle);
    // split_digest returns (low_half, high_half) per the risc0 source.
    let low_fr = fr_from_be_bytes_reduced(&pad32(low));
    let high_fr = fr_from_be_bytes_reduced(&pad32(high));
    (low_fr, high_fr)
}

fn pad32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let off = 32 - bytes.len();
    out[off..].copy_from_slice(bytes);
    out
}

/// Parse a 32-byte BE buffer as an Fr, reducing modulo r if necessary.
/// risc0 does this in two steps (fr_from_bytes reverses to LE then
/// CanonicalDeserialize), which works as long as the value already fits;
/// for bn254_control_id the value can exceed r, so we reduce up front via
/// arkworks' canonical modular ingestion (no decimal-string detour, no panic).
fn fr_from_be_bytes_reduced(be: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(be)
}

fn fr_to_decimal(fr: &Fr) -> String {
    // Canonical-serialize gives 32 LE bytes; convert to BE then to BigUint.
    let mut buf = Vec::with_capacity(32);
    ark_serialize::CanonicalSerialize::serialize_uncompressed(fr, &mut buf)
        .expect("Fr serializes");
    buf.reverse();
    BigUint::from_bytes_be(&buf).to_str_radix(10)
}

// ----------------------------------------------------------------------------
// JSON builders — snarkjs ProofJson / PublicInputsJson / VerifyingKeyJson layout
// matching what risc0_groth16's types expose and what circom2gnark and any
// snarkjs-aware parser will accept.
// ----------------------------------------------------------------------------

/// Convert a 32-byte BE chunk (BN254 Fq coordinate, taken from the seal) into
/// its decimal-string representation.
fn fq_be_chunk_to_decimal(chunk: &[u8]) -> String {
    BigUint::from_bytes_be(chunk).to_str_radix(10)
}

fn build_proof_json(seal: &Seal) -> serde_json::Value {
    // Seal byte layout (256 B BE, see risc0/groth16/src/types.rs). The seal
    // and the snarkjs/Ethereum JSON convention BOTH use **c1-first** per Fp2
    // coordinate — confirmed against risc0's own static constants
    // (e.g. GAMMA_X1 is gnark's A1 = c1, GAMMA_X2 is A0 = c0, and the gamma
    // point parses to the BN254 G2 generator round-trip). So we emit:
    //     pi_b[i][0] = decimal(seal.b[i][0])  (= c1)
    //     pi_b[i][1] = decimal(seal.b[i][1])  (= c0)
    let a = vec![
        fq_be_chunk_to_decimal(&seal.a[0]),
        fq_be_chunk_to_decimal(&seal.a[1]),
        "1".to_string(),
    ];
    let b = vec![
        vec![
            fq_be_chunk_to_decimal(&seal.b[0][0]),
            fq_be_chunk_to_decimal(&seal.b[0][1]),
        ],
        vec![
            fq_be_chunk_to_decimal(&seal.b[1][0]),
            fq_be_chunk_to_decimal(&seal.b[1][1]),
        ],
        vec!["1".to_string(), "0".to_string()],
    ];
    let c = vec![
        fq_be_chunk_to_decimal(&seal.c[0]),
        fq_be_chunk_to_decimal(&seal.c[1]),
        "1".to_string(),
    ];

    serde_json::json!({
        "pi_a": a,
        "pi_b": b,
        "pi_c": c,
        "protocol": "groth16",
        "curve": "bn128",
    })
}

fn build_public_json(public_inputs: &[Fr; 5]) -> serde_json::Value {
    serde_json::Value::Array(
        public_inputs
            .iter()
            .map(|fr| serde_json::Value::String(fr_to_decimal(fr)))
            .collect(),
    )
}

/// The risc0-groth16 VerifyingKey is the same for every RISC0 Groth16 proof
/// produced after the published ceremony. We embed the canonical decimal
/// strings from risc0/groth16/src/verifier.rs verbatim so the JSON is bit-
/// identical to what `risc0_groth16::verifying_key()` produces.
fn build_vk_json() -> serde_json::Value {
    serde_json::json!({
        "protocol": "groth16",
        "curve": "bn128",
        "nPublic": 5,
        "vk_alpha_1": [
            "20491192805390485299153009773594534940189261866228447918068658471970481763042",
            "9383485363053290200918347156157836566562967994039712273449902621266178545958",
            "1"
        ],
        "vk_beta_2": [
            [
                "4252822878758300859123897981450591353533073413197771768651442665752259397132",
                "6375614351688725206403948262868962793625744043794305715222011528459656738731"
            ],
            [
                "21847035105528745403288232691147584728191162732299865338377159692350059136679",
                "10505242626370262277552901082094356697409835680220590971873171140371331206856"
            ],
            ["1", "0"]
        ],
        "vk_gamma_2": [
            [
                "11559732032986387107991004021392285783925812861821192530917403151452391805634",
                "10857046999023057135944570762232829481370756359578518086990519993285655852781"
            ],
            [
                "4082367875863433681332203403145435568316851327593401208105741076214120093531",
                "8495653923123431417604973247489272438418190587263600148770280649306958101930"
            ],
            ["1", "0"]
        ],
        "vk_delta_2": [
            [
                "1668323501672964604911431804142266013250380587483576094566949227275849579036",
                "12043754404802191763554326994664886008979042643626290185762540825416902247219"
            ],
            [
                "7710631539206257456743780535472368339139328733484942210876916214502466455394",
                "13740680757317479711909903993315946540841369848973133181051452051592786724563"
            ],
            ["1", "0"]
        ],
        "IC": [
            [
                "8446592859352799428420270221449902464741693648963397251242447530457567083492",
                "1064796367193003797175961162477173481551615790032213185848276823815288302804",
                "1"
            ],
            [
                "3179835575189816632597428042194253779818690147323192973511715175294048485951",
                "20895841676865356752879376687052266198216014795822152491318012491767775979074",
                "1"
            ],
            [
                "5332723250224941161709478398807683311971555792614491788690328996478511465287",
                "21199491073419440416471372042641226693637837098357067793586556692319371762571",
                "1"
            ],
            [
                "12457994489566736295787256452575216703923664299075106359829199968023158780583",
                "19706766271952591897761291684837117091856807401404423804318744964752784280790",
                "1"
            ],
            [
                "19617808913178163826953378459323299110911217259216006187355745713323154132237",
                "21663537384585072695701846972542344484111393047775983928357046779215877070466",
                "1"
            ],
            [
                "6834578911681792552110317589222010969491336870276623105249474534788043166867",
                "15060583660288623605191393599883223885678013570733629274538391874953353488393",
                "1"
            ]
        ]
    })
}

// ----------------------------------------------------------------------------
// IO helpers
// ----------------------------------------------------------------------------

fn write_pretty(path: &std::path::Path, value: &serde_json::Value) -> Result<()> {
    let s = serde_json::to_string_pretty(value)
        .with_context(|| format!("serialize {}", path.display()))?;
    std::fs::write(path, s).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

// digest_from_hex parses a 32-byte hex string into a risc0 Digest, in the
// SAME byte order as risc0's own `Digest: Display`/`FromHex` (which encode
// `as_bytes()`, the native little-endian cast of the underlying [u32; 8]).
// So `hex::encode(digest_from_hex(h)?.as_bytes()) == h`, matching anything a
// user copies from risc0's Digest output. `TryFrom<&[u8]>` performs the exact
// same [u8; 32] → [u32; 8] cast as the previous hand-rolled loop. See the
// round-trip test below.
fn digest_from_hex(hex_str: &str) -> Result<Digest> {
    let bytes = hex::decode(hex_str.trim_start_matches("0x"))
        .map_err(|e| anyhow!("not hex: {e}"))?;
    Digest::try_from(bytes.as_slice())
        .map_err(|_| anyhow!("digest hex must be 32 bytes, got {}", bytes.len()))
}

// reproduce_claim_digest computes risc0 `ReceiptClaim::ok(image_id, journal).digest()`
// — the value the journal-binding self-check (and a downstream on-chain
// verifier) recompute. Only sha256(journal) is per-journal; the rest
// is constant (empty assumptions, Halted(0), no input, post={pc:0,root:0}).
fn reproduce_claim_digest(image_id: Digest, journal: &[u8]) -> Digest {
    risc0_zkvm::ReceiptClaim::ok(image_id, journal.to_vec()).digest::<sha::Impl>()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The journal-binding self-check (main()) reproduces claim_digest from
    // (image_id, journal). Confirm it matches the committed fixture and DETECTS
    // a tampered journal or wrong image_id — the load-bearing negative path.
    #[test]
    fn journal_binding_reproduces_and_detects_tamper() {
        let image_id =
            digest_from_hex("50fca3d8ac3768a385ed9b56d48a2fa194496d5a25e8331151a8279ecf7a791b")
                .unwrap();
        let expected =
            digest_from_hex("3a01ada1d6df0f884426559b9902b1c03a9a348a58397e11c7e45470fadd1b11")
                .unwrap();
        let journal = match std::fs::read("../../testdata/risc0/journal.bin") {
            Ok(j) => j,
            Err(_) => return, // fixture absent (fresh checkout without testdata)
        };
        assert_eq!(
            reproduce_claim_digest(image_id, &journal),
            expected,
            "fixture journal+image_id must reproduce the bound claim_digest"
        );
        let mut tampered = journal.clone();
        tampered[0] ^= 0x01;
        assert_ne!(
            reproduce_claim_digest(image_id, &tampered),
            expected,
            "a tampered journal must NOT reproduce claim_digest"
        );
        let wrong_id =
            digest_from_hex("00fca3d8ac3768a385ed9b56d48a2fa194496d5a25e8331151a8279ecf7a791b")
                .unwrap();
        assert_ne!(
            reproduce_claim_digest(wrong_id, &journal),
            expected,
            "a wrong image_id must NOT reproduce claim_digest"
        );
    }

    // digest_from_hex must round-trip with risc0's own Display/from_hex, since
    // every --control-root / --bn254-control-id / --image-id override path flows
    // through it. A byte-order regression here silently corrupts public inputs.
    #[test]
    fn digest_from_hex_round_trips() {
        // a fixed 64-hex-char (32-byte) value
        let h = "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f";
        let d = digest_from_hex(h).expect("parse");
        assert_eq!(hex::encode(d.as_bytes()), h, "as_bytes round-trip");
        // 0x prefix accepted and stripped
        let d2 = digest_from_hex(&format!("0x{h}")).expect("parse 0x");
        assert_eq!(d, d2);
    }

    #[test]
    fn digest_from_hex_matches_risc0_constants() {
        // Parsing the canonical control root's own Display string must reproduce it.
        let s = ALLOWED_CONTROL_ROOT.to_string();
        let d = digest_from_hex(&s).expect("parse control root");
        assert_eq!(d, ALLOWED_CONTROL_ROOT);
    }

    #[test]
    fn digest_from_hex_rejects_wrong_length() {
        assert!(digest_from_hex("dead").is_err());
    }

    // build_vk_json() embeds decimal-string constants copied from
    // risc0/groth16/src/verifier.rs. If a risc0 bump changes verifying_key(),
    // those constants silently go stale and the whole
    // wrap attests to the wrong inner VK. This test reconstructs an ark
    // VerifyingKey<Bn254> from build_vk_json() and diffs it byte-for-byte
    // against risc0_groth16::verifying_key(), so any drift fails loudly.
    #[test]
    fn build_vk_json_matches_risc0_verifying_key() {
        use ark_bn254::{Bn254, Fq, G1Affine, G2Affine};
        use ark_groth16::VerifyingKey;
        use ark_serialize::CanonicalDeserialize;
        use core::str::FromStr;

        // risc0's VerifyingKey is a newtype over ark VerifyingKey<Bn254> serialized
        // via serde_ark, which emits the inner ark VK's canonical-uncompressed
        // bytes as a Vec<u8>. Round-trip through serde_json to recover them, then
        // deserialise back into the ark type so we can read its coordinates.
        let ref_bytes: Vec<u8> =
            serde_json::from_value(serde_json::to_value(verifying_key()).unwrap()).unwrap();
        let vk = VerifyingKey::<Bn254>::deserialize_uncompressed(ref_bytes.as_slice())
            .expect("deserialise risc0 verifying_key() into ark VerifyingKey<Bn254>");

        let json = build_vk_json();
        let fq = |s: &serde_json::Value| Fq::from_str(s.as_str().unwrap()).unwrap();
        // snarkjs G1: [x, y, "1"].
        let chk_g1 = |label: &str, p: &G1Affine, v: &serde_json::Value| {
            assert_eq!(p.x, fq(&v[0]), "{label}.x");
            assert_eq!(p.y, fq(&v[1]), "{label}.y");
        };
        // snarkjs/circom G2 stores each Fq2 imaginary-part-first: [[x_c1, x_c0],
        // [y_c1, y_c0], ["1","0"]] — the EIP-197 convention, swapped relative to
        // ark's c0-first Fq2 = c0 + c1·u. (Verified empirically against verifying_key().)
        let chk_g2 = |label: &str, p: &G2Affine, v: &serde_json::Value| {
            assert_eq!(p.x.c1, fq(&v[0][0]), "{label}.x.c1");
            assert_eq!(p.x.c0, fq(&v[0][1]), "{label}.x.c0");
            assert_eq!(p.y.c1, fq(&v[1][0]), "{label}.y.c1");
            assert_eq!(p.y.c0, fq(&v[1][1]), "{label}.y.c0");
        };

        chk_g1("vk_alpha_1", &vk.alpha_g1, &json["vk_alpha_1"]);
        chk_g2("vk_beta_2", &vk.beta_g2, &json["vk_beta_2"]);
        chk_g2("vk_gamma_2", &vk.gamma_g2, &json["vk_gamma_2"]);
        chk_g2("vk_delta_2", &vk.delta_g2, &json["vk_delta_2"]);

        let ic = json["IC"].as_array().unwrap();
        assert_eq!(
            vk.gamma_abc_g1.len(),
            ic.len(),
            "IC length drift: risc0 has {}, build_vk_json has {}",
            vk.gamma_abc_g1.len(),
            ic.len()
        );
        for (i, v) in ic.iter().enumerate() {
            chk_g1(&format!("IC[{i}]"), &vk.gamma_abc_g1[i], v);
        }
    }
}
