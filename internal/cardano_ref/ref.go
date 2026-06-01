// Package cardano_ref is a dependency-light reference implementation of the
// on-chain Groth16-BLS12-381 verification equation for bls-snark's
// Cardano-minimal v2 byte format. Every primitive maps 1:1 to an Aiken builtin:
//
//	gnark-crypto's bls12381.G1Affine.SetBytes(compressed)  ↔  bls12_381_g1_uncompress
//	                bls12381.G2Affine.SetBytes(compressed)  ↔  bls12_381_g2_uncompress
//	                bls12381.G1Affine.ScalarMultiplication  ↔  bls12_381_g1_scalar_mul
//	                bls12381.G1Affine.Add                   ↔  bls12_381_g1_add
//	                bls12381.G1Affine.Neg                   ↔  bls12_381_g1_neg
//	                bls12381.PairingCheck                   ↔  bls12_381_miller_loop + mul_miller_loop_result + final_verify
//	                crypto/sha256.Sum256                    ↔  sha2_256
//	                math/big.Int.Mod                         ↔  builtin integer % (with mod-r constant)
//
// No MSM helpers; no gnark Verify; no gnark hash-to-field; v2 bytes are
// hand-parsed (see ref_parsers.go). TestReferenceVerifierAccepts cross-checks
// against gnark's groth16.Verify on the same inputs.
package cardano_ref

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// DST constants (gnark hardcodes these — see constraint/commitment.go and
// the BatchVerifyMultiVk caller in backend/groth16/bls12-381/verify.go).
const (
	DSTCommitment        = "bsb22-commitment"
	DSTPedersenChallenge = "G16-BSB22"
)

// BLS12-381 scalar-field modulus r, as a big-endian hex string.
// r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
const BLS12_381_FrModulusHex = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"

// BLS12_381_FrModulus returns a fresh *big.Int holding r. Cheap; safe to
// call on every verification.
func BLS12_381_FrModulus() *big.Int {
	r, ok := new(big.Int).SetString(BLS12_381_FrModulusHex, 16)
	if !ok {
		panic("cardano_ref: bad r constant")
	}
	return r
}

// =============================================================================
// Hash-to-field — RFC 9380 expand_message_xmd with SHA-256, then reduce mod r.
// =============================================================================

// ExpandMessageXmdSHA256 is RFC 9380 §5.4.1 expand_message_xmd with SHA-256.
// gnark uses this with lenInBytes = 48 (= 16 security bytes + 32 BLS12-381
// fr.Bytes) for every single-element hash-to-field call.
//
// b_in_bytes (SHA-256 output) = 32; s_in_bytes (SHA-256 block) = 64.
// dst must satisfy len(dst) ≤ 255.
func ExpandMessageXmdSHA256(msg, dst []byte, lenInBytes int) ([]byte, error) {
	const bInBytes = 32
	const rInBytes = 64
	if len(dst) > 255 {
		return nil, errors.New("cardano_ref: DST > 255 bytes")
	}
	ell := (lenInBytes + bInBytes - 1) / bInBytes
	if ell > 255 {
		return nil, errors.New("cardano_ref: lenInBytes too large")
	}

	dstPrime := append(append([]byte{}, dst...), byte(len(dst)))
	zPad := make([]byte, rInBytes)
	libStr := []byte{byte(lenInBytes >> 8), byte(lenInBytes)}

	// b_0 = SHA256( Z_pad || msg || I2OSP(len_in_bytes, 2) || I2OSP(0, 1) || DST_prime )
	h := sha256.New()
	h.Write(zPad)
	h.Write(msg)
	h.Write(libStr)
	h.Write([]byte{0x00})
	h.Write(dstPrime)
	b0 := h.Sum(nil)

	// b_1 = SHA256( b_0 || I2OSP(1, 1) || DST_prime )
	h.Reset()
	h.Write(b0)
	h.Write([]byte{0x01})
	h.Write(dstPrime)
	b1 := h.Sum(nil)

	out := make([]byte, lenInBytes)
	copy(out[:bInBytes], b1)

	for i := 2; i <= ell; i++ {
		// b_i = SHA256( strxor(b_0, b_{i-1}) || I2OSP(i, 1) || DST_prime )
		var xored [bInBytes]byte
		for j := 0; j < bInBytes; j++ {
			xored[j] = b0[j] ^ b1[j]
		}
		h.Reset()
		h.Write(xored[:])
		h.Write([]byte{byte(i)})
		h.Write(dstPrime)
		b1 = h.Sum(nil)
		end := i * bInBytes
		if end > lenInBytes {
			end = lenInBytes
		}
		copy(out[(i-1)*bInBytes:end], b1[:end-(i-1)*bInBytes])
	}
	return out, nil
}

// CommitmentHashH0 computes h_j for commitment j, exactly matching gnark's
// `hash_to_field.New("bsb22-commitment")` ‖ Write(prehash) ‖ Sum() flow.
//
// commitmentUncompressed must be the 96-byte uncompressed G1 commitment
// in `x_be(48) || y_be(48)` form (= what proof.bin v2's uncompressed slot
// carries verbatim).
//
// publicWitnessBE is the slice of 32-byte BE-encoded BLS12-381 fr elements
// the commitment binds, in the order given by vk.bin's committed_indices_j
// (which is 1-indexed against the outer public-input vector; the caller
// has already resolved each index to its limb bytes).
//
// Returns h_j as a big.Int, already reduced mod r_BLS12-381.
func CommitmentHashH0(commitmentUncompressed []byte, publicWitnessBE [][]byte) (*big.Int, error) {
	if len(commitmentUncompressed) != 96 {
		return nil, fmt.Errorf("cardano_ref: commitmentUncompressed: want 96 B, got %d", len(commitmentUncompressed))
	}
	for i, w := range publicWitnessBE {
		if len(w) != 32 {
			return nil, fmt.Errorf("cardano_ref: publicWitnessBE[%d]: want 32 B, got %d", i, len(w))
		}
	}

	// prehash = commitment_uncompressed (96 B) || concat_be(committed public witnesses)
	prehash := make([]byte, 0, 96+32*len(publicWitnessBE))
	prehash = append(prehash, commitmentUncompressed...)
	for _, w := range publicWitnessBE {
		prehash = append(prehash, w...)
	}

	// expand_message_xmd(SHA-256) → 48 B → reduce mod r.
	// RFC 9380 hash-to-field length: L = ceil((ceil(log2 r) + k) / 8) with the
	// BLS12-381 scalar field r (255 bits) and k = 128-bit security →
	// ceil((255 + 128)/8) = 48. (gnark-crypto uses the same L.)
	const lenInBytes = 48
	uniform, err := ExpandMessageXmdSHA256(prehash, []byte(DSTCommitment), lenInBytes)
	if err != nil {
		return nil, err
	}
	val := new(big.Int).SetBytes(uniform) // big-endian unsigned
	return val.Mod(val, BLS12_381_FrModulus()), nil
}

// =============================================================================
// Reference verifier — runs the full equation using only primitive operations.
// =============================================================================

// VerifyOuter runs the on-chain verification equation against parsed v2 inputs
// and returns nil on success. Reference implementation: no MSM helpers, no
// gnark Verify; only ScalarMul / Add / PairingCheck / SHA-256 / mod r.
//
// Currently constrained to nC == 1 (which is what the wrapper produces).
// Generalising to nC > 1 would mean implementing the Pedersen challenge
// folding via the same ExpandMessageXmdSHA256 + Fold-by-powers-of-challenge
// loop gnark uses.
func VerifyOuter(vk *VK, proof *Proof, public *Public) error {
	if vk.NC != proof.NC {
		return fmt.Errorf("cardano_ref: vk.nC=%d but proof.nC=%d", vk.NC, proof.NC)
	}
	if vk.NC != 1 {
		return fmt.Errorf("cardano_ref: only nC=1 supported by this reference (got %d)", vk.NC)
	}
	nbPub := uint32(len(public.LimbsBE))
	expectedIC := 1 + nbPub + vk.NC // one-wire + publics + commitment wires
	if uint32(len(vk.IC)) != expectedIC {
		return fmt.Errorf("cardano_ref: ic_count=%d but expected 1+nbPub+nC=%d", len(vk.IC), expectedIC)
	}

	// -----------------------------------------------------------------------
	// Step 1 — Hash each commitment to h_j using the bound public witnesses.
	// -----------------------------------------------------------------------
	hashes := make([]*big.Int, vk.NC)
	for j := uint32(0); j < vk.NC; j++ {
		var committed [][]byte
		for _, idx := range vk.CommittedIndices[j] {
			if idx < 1 || idx > nbPub {
				return fmt.Errorf("cardano_ref: committed index %d out of range [1, %d]", idx, nbPub)
			}
			committed = append(committed, public.LimbsBE[idx-1])
		}
		h, err := CommitmentHashH0(proof.CommitmentsUncompressed[j], committed)
		if err != nil {
			return fmt.Errorf("cardano_ref: hash commitment[%d]: %w", j, err)
		}
		hashes[j] = h
	}

	// -----------------------------------------------------------------------
	// Step 2 — Build kSum the long way.
	//
	//   kSum = IC[0]
	//        + Σ_{i=0..nbPub-1}  public[i] · IC[i+1]
	//        + Σ_{j=0..nC-1}     h_j        · IC[nbPub+1+j]
	//        + Σ_{j=0..nC-1}     commitment_j                  (raw point addition)
	// -----------------------------------------------------------------------
	kSum := vk.IC[0] // affine; we'll accumulate via Add into a Jacobian.
	var kSumJac bls12381.G1Jac
	kSumJac.FromAffine(&kSum)

	// public[i] · IC[i+1]
	for i := uint32(0); i < nbPub; i++ {
		scalar := new(big.Int).SetBytes(public.LimbsBE[i]) // BE
		var scaled bls12381.G1Affine
		scaled.ScalarMultiplication(&vk.IC[i+1], scalar)
		kSumJac.AddMixed(&scaled)
	}

	// h_j · IC[nbPub+1+j]
	for j := uint32(0); j < vk.NC; j++ {
		var scaled bls12381.G1Affine
		scaled.ScalarMultiplication(&vk.IC[nbPub+1+j], hashes[j])
		kSumJac.AddMixed(&scaled)
	}

	// + commitment_j directly
	for j := uint32(0); j < vk.NC; j++ {
		kSumJac.AddMixed(&proof.CommitmentsCompressed[j])
	}

	var kSumAff bls12381.G1Affine
	kSumAff.FromJacobian(&kSumJac)

	// -----------------------------------------------------------------------
	// Step 3 — Main Groth16 pairing check.
	//
	// gnark form:    e(A, B) == e(α, β) · e(kSum, γ) · e(C, δ)
	// Equivalent:    e(-A, B) · e(α, β) · e(kSum, γ) · e(C, δ) == 1
	// -----------------------------------------------------------------------
	var negAr bls12381.G1Affine
	negAr.Neg(&proof.Ar)
	ok, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{negAr, vk.AlphaG1, kSumAff, proof.Krs},
		[]bls12381.G2Affine{proof.Bs, vk.BetaG2, vk.GammaG2, vk.DeltaG2},
	)
	if err != nil {
		return fmt.Errorf("cardano_ref: main pairing: %w", err)
	}
	if !ok {
		return errors.New("cardano_ref: main pairing check failed (Groth16 equation)")
	}

	// -----------------------------------------------------------------------
	// Step 4 — Pedersen knowledge-proof check.
	//
	// For nC=1, gnark's BatchVerifyMultiVk reduces to the 2-pairing check
	//   e(commitment_0, GSigmaNeg_0) · e(pok_0, G_0) == 1
	// (the fr.Hash([h_0], "G16-BSB22", 1) challenge IS computed by gnark but
	// is never used: the only commitment is implicitly at challenge^0=1 and
	// Fold([pok], _) = pok for length-1 inputs.)
	// -----------------------------------------------------------------------
	ok, err = bls12381.PairingCheck(
		[]bls12381.G1Affine{proof.CommitmentsCompressed[0], proof.CommitmentPok},
		[]bls12381.G2Affine{vk.PedersenGSigmaNeg[0], vk.PedersenG[0]},
	)
	if err != nil {
		return fmt.Errorf("cardano_ref: pedersen pairing: %w", err)
	}
	if !ok {
		return errors.New("cardano_ref: pedersen pairing check failed")
	}

	return nil
}
