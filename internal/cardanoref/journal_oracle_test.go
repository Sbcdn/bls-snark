package cardanoref

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

// snarkjsPublicPath is the canonical 5-BN254-scalar form risc0-dump emits.
// On the wrapper side it's read by internal/parser/snarkjs.go::ParsePublicInputs;
// here we read it directly to keep the oracle dependency-light.
const snarkjsPublicPath = "../../testdata/risc0/public.json"

// TestJournalToOuterPublicOracle dumps a hex/decimal transcript of the
// five BN254 Fr scalars derived from a RISC0 receipt (input form)
// alongside the twenty BLS12-381 Fr limbs they decompose into (the form
// gnark's emulated verifier ingests, and what v2 public.bin carries).
//
// The test verifies the reconstruction `inner_j = Σ limb_{j,i} · 2^{64·i}`
// for each scalar — a 1:1 contract that any downstream re-implementing the
// emulated decomposition (Cardano Aiken, Solidity, off-chain auditor) must
// reproduce byte-for-byte.
//
// Run with: `go test ./internal/cardanoref/ -v -run JournalToOuterPublicOracle`
func TestJournalToOuterPublicOracle(t *testing.T) {
	if !haveCardanoArtifacts(t) {
		t.Skip("out/cardano/*.bin not present — run `make wrap-risc0`")
	}
	if _, err := os.Stat(snarkjsPublicPath); err != nil {
		t.Skipf("%s not present — run tools/risc0-dump first", snarkjsPublicPath)
	}

	innerDecimals := parseSnarkjsPublic(t, snarkjsPublicPath)
	pub, err := ParsePublic(mustRead(t, publicPath))
	if err != nil {
		t.Fatalf("ParsePublic: %v", err)
	}

	if got := uint32(len(innerDecimals)); got != pub.NInnerPub {
		t.Fatalf("snarkjs public.json reports %d scalars but public.bin header says n_inner_pub=%d", got, pub.NInnerPub)
	}
	wantLimbs := pub.NInnerPub * pub.NLimbsPerScalar
	if got := uint32(len(pub.LimbsBE)); got != wantLimbs {
		t.Fatalf("public.bin has %d limbs but header says %d × %d = %d", got, pub.NInnerPub, pub.NLimbsPerScalar, wantLimbs)
	}

	t.Logf("---- 5 BN254 Fr scalars (from risc0-dump → public.json) ----")
	scalars := make([]*big.Int, len(innerDecimals))
	for i, s := range innerDecimals {
		bi, ok := new(big.Int).SetString(s, 10)
		if !ok {
			t.Fatalf("scalar[%d]: %q is not a decimal integer", i, s)
		}
		scalars[i] = bi
		t.Logf("scalar[%d] = %s", i, s)
		t.Logf("           = 0x%064x", bi)
	}

	t.Logf("---- 20 BLS12-381 Fr limbs (from out/cardano/public.bin) ----")
	for i, l := range pub.LimbsBE {
		bi := new(big.Int).SetBytes(l)
		t.Logf("limb[%2d]  = %-25s (hex %s)", i, bi.String(), hex.EncodeToString(l))
	}

	t.Logf("---- reconstruction check (scalar_j = Σ limb_{j,i} · 2^{64·i}, i=0..%d) ----", pub.NLimbsPerScalar-1)
	twoTo64 := new(big.Int).Lsh(big.NewInt(1), 64)
	for i := uint32(0); i < pub.NInnerPub; i++ {
		rec := new(big.Int)
		for j := uint32(0); j < pub.NLimbsPerScalar; j++ {
			limb := new(big.Int).SetBytes(pub.LimbsBE[i*pub.NLimbsPerScalar+j])
			// Bound check — every limb must fit in 64 bits or the decomposition
			// is malformed and the on-chain verifier would silently disagree.
			if limb.Cmp(twoTo64) >= 0 {
				t.Fatalf("scalar[%d] limb[%d] = %s ≥ 2^64; bad decomposition", i, j, limb.String())
			}
			shifted := new(big.Int).Lsh(limb, uint(64*j))
			rec.Add(rec, shifted)
		}
		if rec.Cmp(scalars[i]) != 0 {
			t.Fatalf("scalar[%d]: limb-reconstruction %s ≠ snarkjs public.json %s", i, rec.String(), scalars[i].String())
		}
		t.Logf("scalar[%d] OK  (reconstructed from limbs %d..%d)", i, i*pub.NLimbsPerScalar, (i+1)*pub.NLimbsPerScalar-1)
	}
	t.Logf("---- oracle PASSED ----")
}

// parseSnarkjsPublic reads a snarkjs-style public.json (top-level array of
// decimal strings) into a Go slice. The wrapper's main path goes through
// internal/parser/snarkjs.go::ParsePublicInputs; we use a local 10-LOC
// parser here so the test has no dependency on the inner-witness layer.
func parseSnarkjsPublic(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []string
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(out) == 0 {
		t.Fatalf("%s is empty", path)
	}
	return out
}
