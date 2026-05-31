package cardano_ref

import (
	"bytes"
	"encoding/hex"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
)

const (
	vkPath     = "../../out/cardano/vk.bin"
	proofPath  = "../../out/cardano/proof.bin"
	publicPath = "../../out/cardano/public.bin"
)

func haveCardanoArtifacts(t *testing.T) bool {
	t.Helper()
	for _, p := range []string{vkPath, proofPath, publicPath} {
		if _, err := os.Stat(p); err != nil {
			return false
		}
	}
	return true
}

// TestReferenceVerifierAccepts is the headline test: it runs the entire
// reference verifier against the real wrap output (`out/cardano/*.bin` after
// `make wrap-risc0`) using only the primitives the on-chain side will have.
// If this passes, an Aiken port of the same algorithm is what the on-chain
// verifier needs to implement.
func TestReferenceVerifierAccepts(t *testing.T) {
	if !haveCardanoArtifacts(t) {
		t.Skip("out/cardano/*.bin not present — run `make wrap-risc0`")
	}

	vkBytes := mustRead(t, vkPath)
	proofBytes := mustRead(t, proofPath)
	publicBytes := mustRead(t, publicPath)

	vk, err := ParseVK(vkBytes)
	if err != nil {
		t.Fatalf("ParseVK: %v", err)
	}
	proof, err := ParseProof(proofBytes)
	if err != nil {
		t.Fatalf("ParseProof: %v", err)
	}
	public, err := ParsePublic(publicBytes)
	if err != nil {
		t.Fatalf("ParsePublic: %v", err)
	}

	if err := VerifyOuter(vk, proof, public); err != nil {
		t.Fatalf("reference verifier REJECTED a wrap that gnark accepts: %v", err)
	}
}

// TestReferenceMatchesGnarkOnTamper proves the reference and gnark agree on
// rejection too: tamper the public-witness limbs, both verifiers must reject.
// If the reference accepted a tampered proof the gnark verifier rejects,
// that would be a soundness bug in the reference.
func TestReferenceMatchesGnarkOnTamper(t *testing.T) {
	if !haveCardanoArtifacts(t) {
		t.Skip("out/cardano/*.bin not present — run `make wrap-risc0`")
	}
	if _, err := os.Stat("../../out/outer_vk.bin"); err != nil {
		t.Skip("out/outer_vk.bin not present — needed for the gnark-side cross-check")
	}

	// 1. Reference path: tamper one limb byte → expect failure.
	vk, err := ParseVK(mustRead(t, vkPath))
	if err != nil {
		t.Fatalf("ParseVK: %v", err)
	}
	proof, err := ParseProof(mustRead(t, proofPath))
	if err != nil {
		t.Fatalf("ParseProof: %v", err)
	}
	public, err := ParsePublic(mustRead(t, publicPath))
	if err != nil {
		t.Fatalf("ParsePublic: %v", err)
	}

	// Flip the highest byte of limb 0 (low 64 bits of inner Fr 0). Stays a
	// valid 32-byte string; just commits to a different scalar.
	tampered := *public
	tampered.LimbsBE = append([][]byte{}, public.LimbsBE...)
	tampered.LimbsBE[0] = append([]byte{}, public.LimbsBE[0]...)
	tampered.LimbsBE[0][0] ^= 0x01

	if err := VerifyOuter(vk, proof, &tampered); err == nil {
		t.Fatal("reference verifier ACCEPTED a tampered public witness — soundness bug")
	}

	// 2. Cross-check: gnark's groth16.Verify rejects the same tamper.
	nativeVK := groth16.NewVerifyingKey(ecc.BLS12_381)
	{
		f, err := os.Open("../../out/outer_vk.bin")
		if err != nil {
			t.Fatalf("open native vk: %v", err)
		}
		defer func() { _ = f.Close() }()
		if _, err := nativeVK.ReadFrom(f); err != nil {
			t.Fatalf("read native vk: %v", err)
		}
	}
	nativeProof := groth16.NewProof(ecc.BLS12_381)
	{
		f, err := os.Open("../../out/outer_proof.bin")
		if err != nil {
			t.Fatalf("open native proof: %v", err)
		}
		defer func() { _ = f.Close() }()
		if _, err := nativeProof.ReadFrom(f); err != nil {
			t.Fatalf("read native proof: %v", err)
		}
	}
	// Build a tampered public witness that mirrors `tampered.LimbsBE`.
	// We need to feed gnark's Witness API — the gnark-native outer_public.bin
	// already has a 12-byte header (nbPublic, nbSecret, vector_len) we can
	// reuse, then splice in the tampered limb bytes after that header.
	origWitnessBin, err := os.ReadFile("../../out/outer_public.bin")
	if err != nil {
		t.Fatalf("read native public: %v", err)
	}
	tamperedWitnessBin := append([]byte{}, origWitnessBin...)
	tamperedWitnessBin[12+0] ^= 0x01 // flip same bit at the start of limb 0
	tamperedW, err := witness.New(ecc.BLS12_381.ScalarField())
	if err != nil {
		t.Fatalf("witness.New: %v", err)
	}
	if _, err := tamperedW.ReadFrom(bytes.NewReader(tamperedWitnessBin)); err != nil {
		t.Fatalf("tampered witness ReadFrom: %v", err)
	}
	if err := groth16.Verify(nativeProof, nativeVK, tamperedW); err == nil {
		t.Fatal("gnark accepted a tampered native witness — sanity check fails (test bug?)")
	}
}

// TestParseProofRejectsForgedCommitment forges the uncompressed commitment
// slot in proof.bin to a *different valid* G1 point and asserts ParseProof
// rejects it. The uncompressed copy is the hash-to-field input (h); the
// compressed copy enters the pairing. If they could differ undetected, an
// on-chain port that omits the cross-check would hash a different point than
// it pairs.
func TestParseProofRejectsForgedCommitment(t *testing.T) {
	if !haveCardanoArtifacts(t) {
		t.Skip("out/cardano/*.bin not present — run `make wrap-risc0`")
	}
	proofBytes := mustRead(t, proofPath)

	// Sanity: the unmodified proof must parse (otherwise the negative result below is vacuous).
	if _, err := ParseProof(proofBytes); err != nil {
		t.Fatalf("ParseProof on clean proof.bin: %v", err)
	}

	// proof.bin (v2, nC=1) ends with [uncompressed commitment: 96 B][commitment_pok: 48 B].
	// The uncompressed slot is the 96 bytes immediately before the trailing 48-byte PoK.
	const pokLen, uncompLen = 48, 96
	if len(proofBytes) < pokLen+uncompLen {
		t.Fatalf("proof.bin too short: %d bytes", len(proofBytes))
	}
	start := len(proofBytes) - pokLen - uncompLen

	// A different but VALID subgroup point: the curve generator. This exercises
	// the compressed/uncompressed equality branch (not the SetBytes-failure
	// branch) — the real commitment is overwhelmingly not the generator.
	_, _, g1, _ := bls12381.Generators()
	raw := g1.RawBytes() // 96-byte uncompressed IETF ("Zcash") encoding

	forged := append([]byte{}, proofBytes...)
	copy(forged[start:start+uncompLen], raw[:])

	if _, err := ParseProof(forged); err == nil {
		t.Fatal("ParseProof ACCEPTED a proof whose uncompressed commitment differs from the compressed one — cross-check missing")
	}
}

// TestParsePublicRejectsNonCanonicalLimb forges limb 0 of public.bin to the
// field modulus r (a non-canonical encoding of 0). Because ScalarMultiplication
// reduces mod r internally, v and v+r scalar-mult to the same point — so an
// un-checked verifier would accept this malleated public.bin. ParsePublic must
// reject it (see the canonicity guard in ParsePublic).
func TestParsePublicRejectsNonCanonicalLimb(t *testing.T) {
	if !haveCardanoArtifacts(t) {
		t.Skip("out/cardano/*.bin not present — run `make wrap-risc0`")
	}
	publicBytes := mustRead(t, publicPath)

	// Sanity: clean public.bin parses.
	if _, err := ParsePublic(publicBytes); err != nil {
		t.Fatalf("ParsePublic on clean public.bin: %v", err)
	}

	// Layout: [u32 n_inner_pub][u32 n_limbs][limb0: 32 B BE]... — limb 0 begins at offset 8.
	const limb0Off = 8
	if len(publicBytes) < limb0Off+32 {
		t.Fatalf("public.bin too short: %d bytes", len(publicBytes))
	}
	forged := append([]byte{}, publicBytes...)
	// Write r (the modulus) big-endian into the 32-byte limb-0 slot: r ≥ r → non-canonical.
	BLS12_381_FrModulus().FillBytes(forged[limb0Off : limb0Off+32])

	if _, err := ParsePublic(forged); err == nil {
		t.Fatal("ParsePublic ACCEPTED a non-canonical limb (value == field modulus) — malleability")
	}
}

// TestReferencePrintIntermediates dumps every intermediate value the Aiken
// verifier needs to reproduce, as a hex oracle to diff against.
//
// Run with: `go test ./internal/cardano_ref/ -v -run PrintIntermediates`
func TestReferencePrintIntermediates(t *testing.T) {
	if !haveCardanoArtifacts(t) {
		t.Skip("out/cardano/*.bin not present — run `make wrap-risc0`")
	}

	vk, err := ParseVK(mustRead(t, vkPath))
	if err != nil {
		t.Fatalf("ParseVK: %v", err)
	}
	proof, err := ParseProof(mustRead(t, proofPath))
	if err != nil {
		t.Fatalf("ParseProof: %v", err)
	}
	public, err := ParsePublic(mustRead(t, publicPath))
	if err != nil {
		t.Fatalf("ParsePublic: %v", err)
	}

	t.Logf("---- structural ----")
	t.Logf("n_inner_pub                    = %d", public.NInnerPub)
	t.Logf("n_limbs_per_scalar             = %d", public.NLimbsPerScalar)
	t.Logf("len(public.LimbsBE)            = %d", len(public.LimbsBE))
	t.Logf("vk.NC                          = %d", vk.NC)
	t.Logf("len(vk.IC)                     = %d (= 1 one-wire + %d publics + %d commitments)",
		len(vk.IC), len(public.LimbsBE), vk.NC)
	for j, idxs := range vk.CommittedIndices {
		t.Logf("vk.CommittedIndices[%d]         = %v", j, idxs)
	}

	t.Logf("---- h_0 hash-to-field (DST = %q) ----", DSTCommitment)
	for j := uint32(0); j < vk.NC; j++ {
		var committed [][]byte
		for _, idx := range vk.CommittedIndices[j] {
			committed = append(committed, public.LimbsBE[idx-1])
		}
		t.Logf("commitment[%d] uncompressed (96 B) =\n  %s", j, hex.EncodeToString(proof.CommitmentsUncompressed[j]))
		t.Logf("h_%d prehash length              = %d B (= 96 + 32·%d)", j, 96+32*len(committed), len(committed))
		// Intermediate XMD bytes — useful for debugging the SHA-256 chain.
		prehash := append([]byte{}, proof.CommitmentsUncompressed[j]...)
		for _, w := range committed {
			prehash = append(prehash, w...)
		}
		xmd, err := ExpandMessageXmdSHA256(prehash, []byte(DSTCommitment), 48)
		if err != nil {
			t.Fatalf("expand: %v", err)
		}
		t.Logf("h_%d expand_message_xmd (48 B)   = %s", j, hex.EncodeToString(xmd))
		h, err := CommitmentHashH0(proof.CommitmentsUncompressed[j], committed)
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		// Print h_j as both hex (32 B BE, padded) and decimal.
		hBytes := make([]byte, 32)
		hBytes32 := h.Bytes()
		copy(hBytes[32-len(hBytes32):], hBytes32)
		t.Logf("h_%d (mod r, 32 B BE)            = %s", j, hex.EncodeToString(hBytes))
		t.Logf("h_%d (mod r, decimal)            = %s", j, h.String())
	}

	t.Logf("---- pedersen pairing inputs ----")
	for j := uint32(0); j < vk.NC; j++ {
		gBytes := vk.PedersenG[j].Bytes()
		gsBytes := vk.PedersenGSigmaNeg[j].Bytes()
		cBytes := proof.CommitmentsCompressed[j].Bytes()
		t.Logf("pedersen_G[%d] (compressed, 96 B)         = %s", j, hex.EncodeToString(gBytes[:]))
		t.Logf("pedersen_GSigmaNeg[%d] (compressed, 96 B) = %s", j, hex.EncodeToString(gsBytes[:]))
		t.Logf("commitment[%d] compressed (48 B)          = %s", j, hex.EncodeToString(cBytes[:]))
	}
	pokBytes := proof.CommitmentPok.Bytes()
	t.Logf("commitment_pok compressed (48 B)         = %s", hex.EncodeToString(pokBytes[:]))
	t.Logf("Pedersen check:  e(commitment, GSigmaNeg) · e(pok, G) == 1")

	if err := VerifyOuter(vk, proof, public); err != nil {
		t.Fatalf("end-to-end verify: %v", err)
	}
	t.Logf("---- end-to-end VerifyOuter PASSED ----")
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}
