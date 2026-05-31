package serialize

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/pedersen"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
)

// TestCardanoVKv2_ParsesAndVerifies is the strongest soundness check for the
// v2 export: take the gnark-native outer artifacts, run them through
// EncodeCardanoVK + EncodeCardanoProof, parse the resulting bytes BACK by
// hand (no gnark deserialiser), reassemble a `*groth16_bls12381.VerifyingKey`
// and `*groth16_bls12381.Proof`, then run `groth16.Verify` on them.
//
// If the v2 byte format omits anything gnark's verifier needs, this fails.
// Pairs with the earlier limb-recombination test for the public side —
// together they prove the v2 export is complete.
//
// Skipped if RISC0 artifacts aren't present.
func TestCardanoVKv2_RoundTripVerifies(t *testing.T) {
	vkPath := filepath.Join("..", "..", "out", "outer_vk.bin")
	proofPath := filepath.Join("..", "..", "out", "outer_proof.bin")
	publicPath := filepath.Join("..", "..", "out", "outer_public.bin")
	if !haveAll(vkPath, proofPath, publicPath) {
		t.Skip("artifacts not present — run `make wrap-risc0` first")
	}
	if !isRISC0OuterVKShape(t, vkPath) {
		t.Skip("outer_vk.bin doesn't look like a RISC0-shape VK — likely from `make smoke`")
	}

	// 1. Load native gnark artifacts and capture them as Cardano v2 bytes.
	nativeVK, err := readVK(vkPath)
	if err != nil {
		t.Fatalf("read native vk: %v", err)
	}
	nativeProof, err := readProof(proofPath)
	if err != nil {
		t.Fatalf("read native proof: %v", err)
	}
	pubW, err := readWitness(publicPath)
	if err != nil {
		t.Fatalf("read native public: %v", err)
	}

	concreteVK := nativeVK.(*groth16_bls12381.VerifyingKey)
	concreteProof := nativeProof.(*groth16_bls12381.Proof)

	var vkBytes bytes.Buffer
	if err := EncodeCardanoVK(&vkBytes, concreteVK); err != nil {
		t.Fatalf("EncodeCardanoVK: %v", err)
	}
	var proofBytes bytes.Buffer
	if err := EncodeCardanoProof(&proofBytes, concreteProof); err != nil {
		t.Fatalf("EncodeCardanoProof: %v", err)
	}

	// 2. Parse the Cardano bytes back BY HAND (no gnark deserialiser).
	roundVK, err := decodeCardanoVKV2(vkBytes.Bytes())
	if err != nil {
		t.Fatalf("decode v2 vk: %v", err)
	}
	roundProof, err := decodeCardanoProofV2(proofBytes.Bytes())
	if err != nil {
		t.Fatalf("decode v2 proof: %v", err)
	}

	// 3. The reconstructed VK is missing the precomputed `e = e(α, β)` and
	//    deltaNeg/gammaNeg (those are computed at gnark Setup time and are
	//    unexported). Reproduce them via the public Precompute() method.
	if err := roundVK.Precompute(); err != nil {
		t.Fatalf("roundVK.Precompute: %v", err)
	}

	// 4. Run native gnark verify on the round-tripped values.
	if err := groth16.Verify(roundProof, roundVK, pubW); err != nil {
		t.Fatalf("v2 round-trip verify FAILED: %v\n\n"+
			"This means the Cardano v2 byte format does NOT contain enough information for the on-chain verifier to reproduce gnark's verification equation. Investigate before shipping.", err)
	}
}

// decodeCardanoVKV2 reverses EncodeCardanoVK. Intentionally hand-rolled (no
// gnark binary deserialiser) so the test exercises exactly the byte layout
// the on-chain verifier will consume.
func decodeCardanoVKV2(data []byte) (*groth16_bls12381.VerifyingKey, error) {
	r := bytes.NewReader(data)
	vk := &groth16_bls12381.VerifyingKey{}
	var err error
	if vk.G1.Alpha, err = readG1(r); err != nil {
		return nil, err
	}
	if vk.G2.Beta, err = readG2(r); err != nil {
		return nil, err
	}
	if vk.G2.Gamma, err = readG2(r); err != nil {
		return nil, err
	}
	if vk.G2.Delta, err = readG2(r); err != nil {
		return nil, err
	}
	var icCount uint32
	if err := binary.Read(r, binary.BigEndian, &icCount); err != nil {
		return nil, err
	}
	vk.G1.K = make([]bls12381.G1Affine, icCount)
	for i := range vk.G1.K {
		if vk.G1.K[i], err = readG1(r); err != nil {
			return nil, err
		}
	}
	var nC uint32
	if err := binary.Read(r, binary.BigEndian, &nC); err != nil {
		return nil, err
	}
	vk.CommitmentKeys = make([]pedersen.VerifyingKey, nC)
	vk.PublicAndCommitmentCommitted = make([][]int, nC)
	for j := range vk.CommitmentKeys {
		if vk.CommitmentKeys[j].G, err = readG2(r); err != nil {
			return nil, err
		}
		if vk.CommitmentKeys[j].GSigmaNeg, err = readG2(r); err != nil {
			return nil, err
		}
		var nIdx uint32
		if err := binary.Read(r, binary.BigEndian, &nIdx); err != nil {
			return nil, err
		}
		vk.PublicAndCommitmentCommitted[j] = make([]int, nIdx)
		for k := range vk.PublicAndCommitmentCommitted[j] {
			var idx uint32
			if err := binary.Read(r, binary.BigEndian, &idx); err != nil {
				return nil, err
			}
			vk.PublicAndCommitmentCommitted[j][k] = int(idx)
		}
	}
	return vk, nil
}

// decodeCardanoProofV2 reverses EncodeCardanoProof.
func decodeCardanoProofV2(data []byte) (*groth16_bls12381.Proof, error) {
	r := bytes.NewReader(data)
	p := &groth16_bls12381.Proof{}
	var err error
	if p.Ar, err = readG1(r); err != nil {
		return nil, err
	}
	if p.Bs, err = readG2(r); err != nil {
		return nil, err
	}
	if p.Krs, err = readG1(r); err != nil {
		return nil, err
	}
	var nC uint32
	if err := binary.Read(r, binary.BigEndian, &nC); err != nil {
		return nil, err
	}
	p.Commitments = make([]bls12381.G1Affine, nC)
	for j := range p.Commitments {
		// Compressed (48 B): canonical arithmetic form.
		if p.Commitments[j], err = readG1(r); err != nil {
			return nil, err
		}
		// Uncompressed (96 B): the verifier will hash this. The round-trip
		// test parses it to confirm it represents the same point; Aiken
		// consumes it raw without parsing.
		var uncompressed [96]byte
		if _, err := r.Read(uncompressed[:]); err != nil {
			return nil, err
		}
		var fromUnc bls12381.G1Affine
		if _, err := fromUnc.SetBytes(uncompressed[:]); err != nil {
			return nil, fmt.Errorf("commitment[%d] uncompressed: %w", j, err)
		}
		if !fromUnc.Equal(&p.Commitments[j]) {
			return nil, fmt.Errorf("commitment[%d]: compressed and uncompressed encode different points", j)
		}
	}
	if p.CommitmentPok, err = readG1(r); err != nil {
		return nil, err
	}
	return p, nil
}

// TestCardanoVKv2_Sizes is a cheap structural assertion: the v2 byte length
// for our specific outer circuit is deterministic and worth pinning.
// Skipped if RISC0 artifacts aren't present.
func TestCardanoVKv2_Sizes(t *testing.T) {
	vkPath := filepath.Join("..", "..", "out", "outer_vk.bin")
	proofPath := filepath.Join("..", "..", "out", "outer_proof.bin")
	if !haveAll(vkPath, proofPath) {
		t.Skip("artifacts not present — run `make wrap-risc0` first")
	}
	if !isRISC0OuterVKShape(t, vkPath) {
		t.Skip("outer_vk.bin not RISC0 shape — likely from `make smoke`")
	}

	nativeVK, err := readVK(vkPath)
	if err != nil {
		t.Fatalf("read native vk: %v", err)
	}
	nativeProof, err := readProof(proofPath)
	if err != nil {
		t.Fatalf("read native proof: %v", err)
	}

	var vkBuf bytes.Buffer
	if err := EncodeCardanoVK(&vkBuf, nativeVK.(*groth16_bls12381.VerifyingKey)); err != nil {
		t.Fatalf("EncodeCardanoVK: %v", err)
	}
	// 48 (α)
	//  + 96*3 (β,γ,δ)
	//  + 4 (ic_count) + 48*22 (IC[])
	//  + 4 (nC=1)
	//  + (96+96) (pedersen_G, pedersen_GSigmaNeg) for j=0
	//  + 4 (len(committed_indices_0) = 20) + 4*20 (each index)
	// = 48 + 288 + 4 + 1056 + 4 + 192 + 4 + 80 = 1676
	const wantVK = 48 + 96*3 + 4 + 48*22 + 4 + (96 + 96) + 4 + 4*20
	if got := vkBuf.Len(); got != wantVK {
		t.Errorf("vk.bin size: got %d, want %d", got, wantVK)
	}

	var proofBuf bytes.Buffer
	if err := EncodeCardanoProof(&proofBuf, nativeProof.(*groth16_bls12381.Proof)); err != nil {
		t.Fatalf("EncodeCardanoProof: %v", err)
	}
	// 48 (Ar) + 96 (Bs) + 48 (Krs)
	//  + 4 (nC=1)
	//  + (48 + 96) (commitment compressed + uncompressed)
	//  + 48 (PoK)
	// = 388
	const wantProof = 48 + 96 + 48 + 4 + (48 + 96) + 48
	if got := proofBuf.Len(); got != wantProof {
		t.Errorf("proof.bin size: got %d, want %d", got, wantProof)
	}
}
