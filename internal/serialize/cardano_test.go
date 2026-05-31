package serialize

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/backend/witness"
)

// TestCardanoPublicLimbRoundTrip: take the known 5 BN254 Fr scalars produced
// by the risc0-dump for the test fixture, parse the matching outer_public.bin
// (gnark witness), export to Cardano public.bin, manually recombine the
// 4×64-bit limbs into BN254 Frs, and assert they match the originals byte-for-byte.
//
// This catches the limb-ordering / endianness bug class: if limb 0 isn't
// the LOWEST 64 bits, or the per-limb encoding is wrong, the recombined
// value won't equal the original.
//
// Skipped if RISC0 artifacts haven't been generated yet (run `make wrap-risc0`).
func TestCardanoPublicLimbRoundTrip(t *testing.T) {
	witnessPath := filepath.Join("..", "..", "out", "outer_public.bin")
	if _, err := os.Stat(witnessPath); err != nil {
		t.Skipf("outer_public.bin not present (%v) — run `make wrap-risc0` first", err)
		return
	}
	publicJSON := filepath.Join("..", "..", "testdata", "risc0", "public.json")
	if _, err := os.Stat(publicJSON); err != nil {
		t.Skipf("testdata/risc0/public.json not present — run tools/risc0-dump first")
		return
	}

	// Load the source-of-truth 5 BN254 Fr decimals from the dumper output.
	expected, err := readDecimalsJSON(publicJSON)
	if err != nil {
		t.Fatalf("load expected: %v", err)
	}
	if len(expected) != 5 {
		t.Fatalf("expected 5 BN254 Fr inputs, got %d", len(expected))
	}

	// Encode gnark witness → Cardano public.bin via the production path.
	witnessBin, err := os.ReadFile(witnessPath)
	if err != nil {
		t.Fatalf("read witness: %v", err)
	}
	const nInnerPub uint32 = 5
	const nLimbs uint32 = 4
	// 12-byte gnark header (nbPublic, nbSecret, vector_len) then 32 B per scalar.
	if expectedBytes := 12 + int(nInnerPub*nLimbs)*32; len(witnessBin) != expectedBytes {
		t.Skipf("outer_public.bin doesn't look like a RISC0-shape witness (got %d B, expected %d B) — likely produced by `make smoke`, not `make wrap-risc0`",
			len(witnessBin), expectedBytes)
		return
	}
	var buf bytes.Buffer
	if err := EncodeCardanoPublic(&buf, witnessBin, nInnerPub, nLimbs); err != nil {
		t.Fatalf("EncodeCardanoPublic: %v", err)
	}
	cardano := buf.Bytes()

	// Parse the Cardano header back.
	if got := binary.BigEndian.Uint32(cardano[0:4]); got != nInnerPub {
		t.Fatalf("public.bin n_inner_pub: want %d, got %d", nInnerPub, got)
	}
	if got := binary.BigEndian.Uint32(cardano[4:8]); got != nLimbs {
		t.Fatalf("public.bin n_limbs: want %d, got %d", nLimbs, got)
	}
	scalars := cardano[8:]
	if len(scalars) != int(nInnerPub*nLimbs)*32 {
		t.Fatalf("public.bin scalar count: want %d, got %d bytes", nInnerPub*nLimbs*32, len(scalars))
	}

	// Recombine each inner BN254 Fr from its 4 little-endian-ordered 64-bit
	// limbs. Each limb is a 32-byte BE BLS12-381 scalar whose value fits in
	// 64 bits. We verify limb 0 == lowest 64 bits by reconstructing as
	//     inner = Σ_{j=0..3} limb[j] · 2^{64·j}
	// and comparing to the expected BN254 Fr.
	twoTo64 := new(big.Int).Lsh(big.NewInt(1), 64)
	for i := uint32(0); i < nInnerPub; i++ {
		var reconstructed big.Int
		for j := uint32(0); j < nLimbs; j++ {
			off := (i*nLimbs + j) * 32
			limbBytes := scalars[off : off+32]
			limb := new(big.Int).SetBytes(limbBytes) // BE
			if limb.BitLen() > 64 {
				t.Fatalf("inner[%d] limb[%d] does not fit in 64 bits (BitLen=%d)", i, j, limb.BitLen())
			}
			shifted := new(big.Int).Mul(limb, new(big.Int).Exp(twoTo64, big.NewInt(int64(j)), nil))
			reconstructed.Add(&reconstructed, shifted)
		}
		exp, ok := new(big.Int).SetString(expected[i], 10)
		if !ok {
			t.Fatalf("expected[%d] not a decimal: %q", i, expected[i])
		}
		if reconstructed.Cmp(exp) != 0 {
			t.Fatalf("inner[%d]: reconstructed=%s, expected=%s", i, reconstructed.String(), exp.String())
		}
	}
}

// TestOuterVerifyFromInnerPublicInputsDirectly proves the strongest form of
// input/output equivalence: take the ORIGINAL 5 BN254 Fr public inputs (from
// testdata/risc0/public.json, the dumper's authoritative output for the
// inner Groth16-BN254 proof), decompose each into 4 × 64-bit limbs via the
// canonical lifting (limb 0 = lowest 64 bits), build a fresh BLS12-381
// public witness from those 20 limbs, and pass it to groth16.Verify against
// the outer proof and outer VK. The verify must return true.
//
// What this rules out: any scenario where outer_public.bin contains "magic"
// public inputs that don't actually correspond to the inner ones. The test
// reconstructs the verification input from first principles using only the
// 5 source-of-truth Fr decimals, so a pass here ties the outer proof to
// THOSE specific inner public inputs.
//
// Skipped if RISC0 artifacts aren't present.
func TestOuterVerifyFromInnerPublicInputsDirectly(t *testing.T) {
	vkPath := filepath.Join("..", "..", "out", "outer_vk.bin")
	proofPath := filepath.Join("..", "..", "out", "outer_proof.bin")
	publicJSON := filepath.Join("..", "..", "testdata", "risc0", "public.json")
	if !haveAll(vkPath, proofPath, publicJSON) {
		t.Skip("RISC0 artifacts not present — run `make wrap-risc0` first")
	}

	// Distinguish risc0-shape from cubic-shape artifacts: the risc0 outer VK
	// has ic_count = 1 (one-wire) + 5*4 (inner publics × limbs) + 1 (commitment)
	// = 22. The cubic outer VK has 1 + 4 + 1 = 6.
	if !isRISC0OuterVKShape(t, vkPath) {
		t.Skip("outer_vk.bin doesn't look like a RISC0-shape VK — likely from `make smoke`, not `make wrap-risc0`")
	}

	innerDecimals, err := readDecimalsJSON(publicJSON)
	if err != nil {
		t.Fatalf("read public.json: %v", err)
	}
	if len(innerDecimals) != 5 {
		t.Fatalf("expected 5 inner BN254 Fr values, got %d", len(innerDecimals))
	}

	// Lift each BN254 Fr into 4 limbs of 64 bits each, limb 0 = lowest bits.
	// This is the canonical decomposition; it matches what gnark's
	// ValueOfWitness produces internally but we compute it ourselves so the
	// test is independent of gnark's lifting implementation.
	const nInnerPub = 5
	const nLimbs = 4
	mask64 := new(big.Int).Lsh(big.NewInt(1), 64)
	mask64.Sub(mask64, big.NewInt(1)) // 2^64 - 1
	limbs := make([]big.Int, nInnerPub*nLimbs)
	for i, dec := range innerDecimals {
		fr, ok := new(big.Int).SetString(dec, 10)
		if !ok {
			t.Fatalf("inner[%d]: not a decimal: %q", i, dec)
		}
		for j := 0; j < nLimbs; j++ {
			shifted := new(big.Int).Rsh(fr, uint(64*j))
			limb := new(big.Int).And(shifted, mask64)
			limbs[i*nLimbs+j] = *limb
		}
	}

	// Build a BLS12-381 public witness with these 20 limbs.
	w, err := witness.New(ecc.BLS12_381.ScalarField())
	if err != nil {
		t.Fatalf("witness.New: %v", err)
	}
	ch := make(chan any, len(limbs))
	for i := range limbs {
		ch <- limbs[i]
	}
	close(ch)
	if err := w.Fill(len(limbs), 0, ch); err != nil {
		t.Fatalf("witness.Fill: %v", err)
	}

	vk, err := readVK(vkPath)
	if err != nil {
		t.Fatalf("read vk: %v", err)
	}
	proof, err := readProof(proofPath)
	if err != nil {
		t.Fatalf("read proof: %v", err)
	}

	if err := groth16.Verify(proof, vk, w); err != nil {
		t.Fatalf("outer verify with hand-built public witness FAILED: %v\n"+
			"  This means the outer proof's public inputs do NOT correspond\n"+
			"  to a canonical lift of testdata/risc0/public.json — the wrap is\n"+
			"  not semantically equivalent.", err)
	}
}

// TestOuterVerifyTamperedPublicFails proves the outer verifier is genuinely
// sensitive to its public-input limbs: flipping a single bit in
// `outer_public.bin` (within the limb-data region, past the 12-byte gnark
// header) must turn a valid proof into an invalid one. Without this test,
// "valid: true" on the happy path doesn't rule out a verifier that ignores
// public inputs entirely. Skipped if RISC0 artifacts aren't present.
func TestOuterVerifyTamperedPublicFails(t *testing.T) {
	vkPath := filepath.Join("..", "..", "out", "outer_vk.bin")
	proofPath := filepath.Join("..", "..", "out", "outer_proof.bin")
	publicPath := filepath.Join("..", "..", "out", "outer_public.bin")
	if !haveAll(vkPath, proofPath, publicPath) {
		t.Skip("RISC0 artifacts not present — run `make wrap-risc0` first")
	}

	vk, err := readVK(vkPath)
	if err != nil {
		t.Fatalf("read vk: %v", err)
	}
	proof, err := readProof(proofPath)
	if err != nil {
		t.Fatalf("read proof: %v", err)
	}

	// Sanity: untouched, the proof verifies.
	pub, err := readWitness(publicPath)
	if err != nil {
		t.Fatalf("read public: %v", err)
	}
	if err := groth16.Verify(proof, vk, pub); err != nil {
		t.Fatalf("baseline verify failed (cannot run tamper test): %v", err)
	}

	// Tamper: flip the last byte of the first limb (offset 12 = past the
	// gnark header [nbPublic, nbSecret, vector_len]). That's within scalar 0
	// of the witness, so verifying with this corrupted file must fail.
	corruptedPath := tempCopyFlipByte(t, publicPath, 12+31)
	defer func() { _ = os.Remove(corruptedPath) }()
	pubBad, err := readWitness(corruptedPath)
	if err != nil {
		// gnark may reject malformed scalar bytes outright; that counts
		// as "verify can't proceed", which is a stronger reject than
		// `Verify == err`. Either path is acceptable.
		t.Logf("tampered witness rejected at parse time (acceptable): %v", err)
		return
	}
	if err := groth16.Verify(proof, vk, pubBad); err == nil {
		t.Fatal("outer verify ACCEPTED a tampered public witness — outer proof is not bound to its public inputs")
	}
}

// TestOuterVerifyTamperedProofFails proves the outer verifier is sensitive
// to the proof bytes themselves: flipping a bit in `outer_proof.bin` must
// reject. Pairs with TestOuterVerifyTamperedPublicFails to bracket the two
// sides of the Groth16 pairing-equation check.
func TestOuterVerifyTamperedProofFails(t *testing.T) {
	vkPath := filepath.Join("..", "..", "out", "outer_vk.bin")
	proofPath := filepath.Join("..", "..", "out", "outer_proof.bin")
	publicPath := filepath.Join("..", "..", "out", "outer_public.bin")
	if !haveAll(vkPath, proofPath, publicPath) {
		t.Skip("RISC0 artifacts not present — run `make wrap-risc0` first")
	}

	vk, err := readVK(vkPath)
	if err != nil {
		t.Fatalf("read vk: %v", err)
	}
	pub, err := readWitness(publicPath)
	if err != nil {
		t.Fatalf("read public: %v", err)
	}

	// Tamper deterministically by replacing Ar with a DIFFERENT but still
	// valid (on-curve, in-subgroup) G1 point: Ar' = Ar + G. This guarantees
	// the altered point actually reaches groth16.Verify (vs a raw byte-flip,
	// which often just yields a parse error and proves nothing about the
	// pairing check).
	good, err := readProof(proofPath)
	if err != nil {
		t.Fatalf("read proof: %v", err)
	}
	bad, ok := good.(*groth16_bls12381.Proof)
	if !ok {
		t.Fatalf("unexpected proof type %T", good)
	}
	_, _, g1, _ := bls12381.Generators()
	bad.Ar.Add(&bad.Ar, &g1)
	if !bad.Ar.IsOnCurve() || !bad.Ar.IsInSubGroup() {
		t.Fatal("test setup: tampered Ar is not a valid G1 point")
	}

	if err := groth16.Verify(bad, vk, pub); err == nil {
		t.Fatal("outer verify ACCEPTED a tampered proof — verifier is broken")
	}
}

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

func haveAll(paths ...string) bool {
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			return false
		}
	}
	return true
}

func readVK(path string) (groth16.VerifyingKey, error) {
	vk := groth16.NewVerifyingKey(ecc.BLS12_381)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if _, err := vk.ReadFrom(f); err != nil {
		return nil, err
	}
	return vk, nil
}

// isRISC0OuterVKShape returns true if the outer VK at path has the IC layout
// of a RISC0-inner wrap (22 entries: 1 one-wire + 20 limb publics + 1
// commitment). Returns false for cubic-inner wraps (6 entries) or any other
// shape. Fails the test if the file can't be read.
func isRISC0OuterVKShape(t *testing.T, path string) bool {
	t.Helper()
	vk, err := readVK(path)
	if err != nil {
		t.Fatalf("read vk for shape probe: %v", err)
	}
	concrete, ok := vk.(*groth16_bls12381.VerifyingKey)
	if !ok {
		t.Fatalf("expected BLS12-381 VK, got %T", vk)
	}
	return len(concrete.G1.K) == 22
}

func readProof(path string) (groth16.Proof, error) {
	p := groth16.NewProof(ecc.BLS12_381)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if _, err := p.ReadFrom(f); err != nil {
		return nil, err
	}
	return p, nil
}

func readWitness(path string) (witness.Witness, error) {
	w, err := witness.New(ecc.BLS12_381.ScalarField())
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if _, err := w.ReadFrom(f); err != nil {
		return nil, err
	}
	return w, nil
}

// tempCopyFlipByte writes `src` to a temp file with the byte at `offset` XOR'd
// with 0xFF. Returns the temp path.
func tempCopyFlipByte(t *testing.T, src string, offset int) string {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	if offset < 0 || offset >= len(data) {
		t.Fatalf("flip offset %d outside file of length %d", offset, len(data))
	}
	data[offset] ^= 0xFF
	f, err := os.CreateTemp("", "tamper-*.bin")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close temp: %v", err)
	}
	return f.Name()
}

func readDecimalsJSON(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}
