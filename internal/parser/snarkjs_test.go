package parser

import (
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark/backend/groth16"
)

// TestRISC0VerifyAgainstTestdata is the ground-truth check for the
// `tools/risc0-dump` Rust crate. If the dumper's JSON output (or this Go
// parser) miscomputes ANY of the proof bytes, public-input scalars, or VK
// points, native gnark `groth16.Verify` will fail.
//
// Setup: a real Groth16-BN254 receipt was dumped via
//
//	./tools/risc0-dump/target/release/risc0-dump \
//	    --input  <chain_proof.bin> \
//	    --out-dir testdata/risc0
//
// Runs over every fixture directory under testdata/risc0/ (the primary
// fixture plus any sibling dirs like alt/). Multiple real fixtures guard
// against a parser/dumper bug that happens to work for one claim_digest but
// not another. Each fixture is skipped if not present (so
// plain `go test ./...` from a fresh clone doesn't fail).
func TestRISC0VerifyAgainstTestdata(t *testing.T) {
	for _, dir := range risc0FixtureDirs() {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			proofPath := filepath.Join(dir, "proof.json")
			publicPath := filepath.Join(dir, "public.json")
			vkPath := filepath.Join(dir, "verification_key.json")

			for _, p := range []string{proofPath, publicPath, vkPath} {
				if !fileExists(p) {
					t.Skipf("testdata not present (%s) — generate with tools/risc0-dump", p)
				}
			}

			vk, err := ParseVerifyingKey(vkPath)
			if err != nil {
				t.Fatalf("ParseVerifyingKey: %v", err)
			}
			proof, err := ParseProof(proofPath)
			if err != nil {
				t.Fatalf("ParseProof: %v", err)
			}
			pub, err := ParsePublicInputs(publicPath)
			if err != nil {
				t.Fatalf("ParsePublicInputs: %v", err)
			}

			if err := groth16.Verify(proof, vk, pub); err != nil {
				t.Fatalf("native BN254 Groth16 verify failed — dumper or parser is wrong: %v", err)
			}
		})
	}
}

// risc0FixtureDirs returns the testdata/risc0 fixture directories to verify:
// the primary fixture and every immediate subdirectory containing a
// verification_key.json (e.g. alt/). Returns at least the primary path so the
// test reports a skip rather than silently passing when testdata is absent.
func risc0FixtureDirs() []string {
	base := filepath.Join("..", "..", "testdata", "risc0")
	dirs := []string{base}
	entries, err := os.ReadDir(base)
	if err != nil {
		return dirs
	}
	for _, e := range entries {
		if e.IsDir() && fileExists(filepath.Join(base, e.Name(), "verification_key.json")) {
			dirs = append(dirs, filepath.Join(base, e.Name()))
		}
	}
	return dirs
}

// TestParseG2RejectsOffSubgroup feeds parseG2 an on-curve point that is NOT in
// the prime-order subgroup. BN254 G2 has a nontrivial cofactor, so such points
// exist; an off-subgroup VK G2 point baked into the outer circuit is a
// soundness hazard on the --insecure-no-vk-check path.
func TestParseG2RejectsOffSubgroup(t *testing.T) {
	// MapToCurve2 returns an on-curve point WITHOUT cofactor clearing, so its
	// output is (with overwhelming probability) off-subgroup.
	_, _, _, g2gen := curve.Generators()
	seed := g2gen.X // an fptower.E2 value; type inferred (package is internal)
	p := curve.MapToCurve2(&seed)
	if !p.IsOnCurve() {
		t.Fatal("test setup: MapToCurve2 produced an off-curve point")
	}
	if p.IsInSubGroup() {
		t.Skip("test setup: MapToCurve2 happened to land in the subgroup")
	}

	// snarkjs G2 encoding is c1-first per Fp2 coordinate.
	coords := [][]string{
		{p.X.A1.String(), p.X.A0.String()},
		{p.Y.A1.String(), p.Y.A0.String()},
		{"1", "0"},
	}
	_, err := parseG2(coords, "vk_beta_2")
	if err == nil {
		t.Fatal("parseG2 accepted an off-subgroup point; subgroup check is missing")
	}
	if !strings.Contains(err.Error(), "subgroup") {
		t.Fatalf("expected a subgroup-membership error, got: %v", err)
	}
}

// TestParseGRejectsInfinity ensures the identity (encoded as all-zero coords)
// is rejected for both G1 and G2 — snarkjs emits only finite points, and a
// degenerate IC/VK point is a malformed input.
func TestParseGRejectsInfinity(t *testing.T) {
	if _, err := parseG1([]string{"0", "0", "1"}, "IC[0]"); err == nil {
		t.Fatal("parseG1 accepted the point at infinity")
	}
	if _, err := parseG2([][]string{{"0", "0"}, {"0", "0"}, {"1", "0"}}, "vk_beta_2"); err == nil {
		t.Fatal("parseG2 accepted the point at infinity")
	}
}

// TestParseFqRejectsOutOfRange ensures a coordinate ≥ the BN254 base-field
// modulus is rejected rather than silently reduced mod q.
func TestParseFqRejectsOutOfRange(t *testing.T) {
	// modulus itself (≡ 0 mod q) must be rejected, not reduced to 0.
	mod := fp.Modulus().String()
	if _, err := parseFq(mod, "x"); err == nil {
		t.Fatalf("parseFq accepted q=%s (should reject ≥ modulus)", mod)
	}
	// modulus+1 likewise.
	modPlus := new(big.Int).Add(fp.Modulus(), big.NewInt(1)).String()
	if _, err := parseFq(modPlus, "x"); err == nil {
		t.Fatal("parseFq accepted q+1")
	}
	// a valid in-range value still parses.
	if _, err := parseFq("7", "x"); err != nil {
		t.Fatalf("parseFq rejected a valid coordinate: %v", err)
	}
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}
