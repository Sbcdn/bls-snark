// Cardano-side byte formats (v2). Compressed G1/G2 points use gnark-crypto's
// `.Bytes()` — IETF/Zcash encoding, matching Cardano's
// `bls12_381_G1_uncompress` / `_G2_uncompress` builtins. No CBOR.
//
// v2 carries the Pedersen commitment fields needed to reproduce gnark's full
// verification equation:
//
//	kSum = K[0]
//	     + Σ_{i=0..nbPublic-1} public[i] · K[i+1]
//	     + Σ_{j=0..nC-1}       h_j        · K[nbPublic+1+j]
//	     + Σ_{j=0..nC-1}       commitment[j]
//
//	main:     e(A, B) == e(α, β) · e(kSum, γ) · e(C, δ)
//	pedersen: e(commitment_folded, GSigmaNeg) · e(pok_folded, G) == 1   (nC=1: fold is identity)
//
// where for each commitment j:
//
//	h_j = HashToField(DST = "bsb22-commitment",
//	                  commitment[j].MarshalUncompressed (96 B) ‖ committed_values_serialised)

package serialize

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	groth16_bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
)

// EncodeCardanoVK encodes the verifying key in the Cardano-minimal byte
// layout (v2):
//
//	[α]_1 (48) || [β]_2 (96) || [γ]_2 (96) || [δ]_2 (96)
//	|| uint32 BE: ic_count || (each [K_i]_1, 48 B)                    // i = 0..ic_count-1
//	|| uint32 BE: nC
//	|| for j = 0..nC-1:
//	     pedersen_G_2 (96)
//	     pedersen_GSigmaNeg_2 (96)
//	     uint32 BE: len(committed_indices_j)
//	     committed_indices_j (each uint32 BE, 1-indexed public-wire indices)
//
// `ic_count` is the full `len(vk.G1.K)` and includes the trailing nC slots
// for commitment wires; every entry is required for verification.
//
// `committed_indices_j` lists the 1-indexed public-wire positions commitment
// j commits to. For each such index `idx`, `publicWitness[idx-1].Marshal()`
// (32 B BE) is appended to the h_j hash input after the 96-byte uncompressed
// commitment G1. For this wrapper's outer circuit the list is `[1..nbPublic]`
// (the commitment binds the entire public-input vector).
//
// Omits the bellman-compat-only G1.Beta / G1.Delta points and the precomputed
// pairing e — Cardano either doesn't use them or recomputes.
func EncodeCardanoVK(w io.Writer, vk *groth16_bls12381.VerifyingKey) error {
	if err := writeG1(w, vk.G1.Alpha); err != nil {
		return fmt.Errorf("alpha_g1: %w", err)
	}
	if err := writeG2(w, vk.G2.Beta); err != nil {
		return fmt.Errorf("beta_g2: %w", err)
	}
	if err := writeG2(w, vk.G2.Gamma); err != nil {
		return fmt.Errorf("gamma_g2: %w", err)
	}
	if err := writeG2(w, vk.G2.Delta); err != nil {
		return fmt.Errorf("delta_g2: %w", err)
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(vk.G1.K))); err != nil {
		return fmt.Errorf("ic_count: %w", err)
	}
	for i := range vk.G1.K {
		if err := writeG1(w, vk.G1.K[i]); err != nil {
			return fmt.Errorf("ic[%d]: %w", i, err)
		}
	}
	nC := uint32(len(vk.CommitmentKeys))
	if err := binary.Write(w, binary.BigEndian, nC); err != nil {
		return fmt.Errorf("nC: %w", err)
	}
	if len(vk.PublicAndCommitmentCommitted) != int(nC) {
		return fmt.Errorf("vk has %d CommitmentKeys but %d PublicAndCommitmentCommitted slots", nC, len(vk.PublicAndCommitmentCommitted))
	}
	for j := range vk.CommitmentKeys {
		if err := writeG2(w, vk.CommitmentKeys[j].G); err != nil {
			return fmt.Errorf("pedersen_G[%d]: %w", j, err)
		}
		if err := writeG2(w, vk.CommitmentKeys[j].GSigmaNeg); err != nil {
			return fmt.Errorf("pedersen_GSigmaNeg[%d]: %w", j, err)
		}
		idxs := vk.PublicAndCommitmentCommitted[j]
		if err := binary.Write(w, binary.BigEndian, uint32(len(idxs))); err != nil {
			return fmt.Errorf("committed_count[%d]: %w", j, err)
		}
		for _, idx := range idxs {
			if idx < 0 {
				return fmt.Errorf("PublicAndCommitmentCommitted[%d] contains negative index %d", j, idx)
			}
			if err := binary.Write(w, binary.BigEndian, uint32(idx)); err != nil {
				return fmt.Errorf("committed_index[%d][%d]: %w", j, idx, err)
			}
		}
	}
	return nil
}

// EncodeCardanoProof encodes the Groth16-BLS12-381 proof in the
// Cardano-minimal byte layout (v2):
//
//	a_g1                                48 B    (compressed)
//	b_g2                                96 B    (compressed)
//	c_g1                                48 B    (compressed)
//	uint32 BE: nC
//	for j = 0..nC-1:
//	  commitment_g1_compressed          48 B    (used in pairing arithmetic via g1.decompress)
//	  commitment_g1_uncompressed        96 B    (used VERBATIM as hash input for h_j; layout is x_be(48) || y_be(48))
//	commitment_pok_g1                   48 B    (compressed; never hashed, only pairing arithmetic)
//
// For nC=1 the proof is `48 + 96 + 48 + 4 + (48 + 96) + 48 = 388 B`.
//
// Dual-encoded commitments: Aiken stdlib v3 can compress an in-memory G1Element
// but has no API to emit the 96-byte uncompressed form gnark's HashToField
// consumes. The compressed copy is used for pairing arithmetic; the
// uncompressed copy is fed verbatim to the hash. No on-chain consistency
// check is needed — a mismatch silently breaks the pairing equation, so the
// verifier rejects. The PoK is compressed-only because gnark never hashes it.
//
// For nC=1, gnark emits an unfolded PoK directly. For nC>1, callers must
// fold the PoKs themselves before BatchVerifyMultiVk on chain.
func EncodeCardanoProof(w io.Writer, p *groth16_bls12381.Proof) error {
	if err := writeG1(w, p.Ar); err != nil {
		return fmt.Errorf("a_g1: %w", err)
	}
	if err := writeG2(w, p.Bs); err != nil {
		return fmt.Errorf("b_g2: %w", err)
	}
	if err := writeG1(w, p.Krs); err != nil {
		return fmt.Errorf("c_g1: %w", err)
	}
	nC := uint32(len(p.Commitments))
	if err := binary.Write(w, binary.BigEndian, nC); err != nil {
		return fmt.Errorf("nC: %w", err)
	}
	for j := range p.Commitments {
		if err := writeG1(w, p.Commitments[j]); err != nil {
			return fmt.Errorf("commitment[%d] compressed: %w", j, err)
		}
		// Uncompressed = curve.G1Affine.Marshal() = 96 B (x_be(48) || y_be(48)).
		// This is the EXACT input gnark's HashToField consumes — do not alter.
		raw := p.Commitments[j].Marshal()
		if len(raw) != 96 {
			return fmt.Errorf("commitment[%d] uncompressed: gnark-crypto returned %d B, expected 96", j, len(raw))
		}
		if _, err := w.Write(raw); err != nil {
			return fmt.Errorf("commitment[%d] uncompressed: %w", j, err)
		}
	}
	if err := writeG1(w, p.CommitmentPok); err != nil {
		return fmt.Errorf("commitment_pok: %w", err)
	}
	return nil
}

// EncodeCardanoPublic encodes the outer public-witness vector in the
// limb-aware layout:
//
//	uint32 BE: n_inner_pub             (the count of inner-circuit scalars)
//	uint32 BE: n_limbs_per_scalar      (4 for BN254 inner)
//	(n_inner_pub * n_limbs_per_scalar) BLS12-381 scalars, each 32 B BE,
//	    limb 0 = lowest 64 bits of the inner scalar.
//
// The witness binary read from `outer_public.bin` is the gnark-native
// witness with a 12-byte header (nbPublic, nbSecret, vector_len) followed
// by raw 32-byte BE scalars. We strip the gnark header and re-wrap with
// the Cardano two-uint32 header.
func EncodeCardanoPublic(w io.Writer, witnessBin []byte, nInnerPub, nLimbsPerScalar uint32) error {
	const gnarkHeader = 12 // 4 + 4 + 4
	const scalarBytes = 32
	want := int(nInnerPub) * int(nLimbsPerScalar)
	gotScalarBytes := len(witnessBin) - gnarkHeader
	if gotScalarBytes < 0 || gotScalarBytes%scalarBytes != 0 {
		return fmt.Errorf("witness binary length %d is not a valid gnark public-witness", len(witnessBin))
	}
	gotScalars := gotScalarBytes / scalarBytes
	if gotScalars != want {
		return fmt.Errorf("witness has %d scalars but n_inner_pub*n_limbs = %d", gotScalars, want)
	}
	if err := binary.Write(w, binary.BigEndian, nInnerPub); err != nil {
		return fmt.Errorf("n_inner_pub: %w", err)
	}
	if err := binary.Write(w, binary.BigEndian, nLimbsPerScalar); err != nil {
		return fmt.Errorf("n_limbs_per_scalar: %w", err)
	}
	if _, err := w.Write(witnessBin[gnarkHeader:]); err != nil {
		return fmt.Errorf("limb bytes: %w", err)
	}
	return nil
}

func writeG1(w io.Writer, p curve.G1Affine) error {
	b := p.Bytes()
	_, err := w.Write(b[:])
	return err
}

func writeG2(w io.Writer, p curve.G2Affine) error {
	b := p.Bytes()
	_, err := w.Write(b[:])
	return err
}

// readG1 / readG2 are the inverses of writeG1 / writeG2 — they consume the
// IETF/Zcash compressed bytes that `.Bytes()` produces and return the affine
// point (with subgroup checks).
func readG1(r io.Reader) (curve.G1Affine, error) {
	var buf [48]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return curve.G1Affine{}, fmt.Errorf("read g1: %w", err)
	}
	var p curve.G1Affine
	if _, err := p.SetBytes(buf[:]); err != nil {
		return curve.G1Affine{}, fmt.Errorf("decode g1: %w", err)
	}
	return p, nil
}

func readG2(r io.Reader) (curve.G2Affine, error) {
	var buf [96]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return curve.G2Affine{}, fmt.Errorf("read g2: %w", err)
	}
	var p curve.G2Affine
	if _, err := p.SetBytes(buf[:]); err != nil {
		return curve.G2Affine{}, fmt.Errorf("decode g2: %w", err)
	}
	return p, nil
}

// WriteCardanoVK writes the Cardano-minimal VK bytes to path.
func WriteCardanoVK(path string, vk *groth16_bls12381.VerifyingKey) (n int64, err error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, fmt.Errorf("create %q: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	if err = EncodeCardanoVK(f, vk); err != nil {
		return 0, fmt.Errorf("encode vk: %w", err)
	}
	st, serr := f.Stat()
	if serr != nil {
		return 0, fmt.Errorf("stat %q: %w", path, serr)
	}
	return st.Size(), nil
}

// WriteCardanoProof writes the Cardano-minimal proof bytes to path.
func WriteCardanoProof(path string, p *groth16_bls12381.Proof) (n int64, err error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, fmt.Errorf("create %q: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	if err = EncodeCardanoProof(f, p); err != nil {
		return 0, fmt.Errorf("encode proof: %w", err)
	}
	st, serr := f.Stat()
	if serr != nil {
		return 0, fmt.Errorf("stat %q: %w", path, serr)
	}
	return st.Size(), nil
}

// WriteCardanoPublic writes the Cardano-format public.bin to path. It reads
// the gnark-native public witness from witnessPath, strips its 12-byte gnark
// header (nbPublic, nbSecret, vector_len), and re-wraps the limb data with
// the Cardano-side two-uint32 header (n_inner_pub, n_limbs_per_scalar).
func WriteCardanoPublic(path, witnessPath string, nInnerPub, nLimbsPerScalar uint32) (n int64, err error) {
	bin, err := os.ReadFile(witnessPath)
	if err != nil {
		return 0, fmt.Errorf("read witness %q: %w", witnessPath, err)
	}
	f, err := os.Create(path)
	if err != nil {
		return 0, fmt.Errorf("create %q: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	if err = EncodeCardanoPublic(f, bin, nInnerPub, nLimbsPerScalar); err != nil {
		return 0, fmt.Errorf("encode public: %w", err)
	}
	st, serr := f.Stat()
	if serr != nil {
		return 0, fmt.Errorf("stat %q: %w", path, serr)
	}
	return st.Size(), nil
}
