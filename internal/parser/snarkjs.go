// Package parser converts snarkjs-style Groth16-BN254 JSON files (the output
// of tools/risc0-dump) into native gnark BN254 backend types.
//
// File contract (snarkjs convention, c0-first Fp2):
//
//	verification_key.json  — { protocol, curve, nPublic, vk_alpha_1, vk_beta_2,
//	                            vk_gamma_2, vk_delta_2, vk_alphabeta_12, IC }
//	proof.json             — { pi_a, pi_b, pi_c, protocol, curve }
//	public.json            — [ "decimal", "decimal", ... ]
//
// All decimal strings; Fp2 elements are [c0, c1] per coord. See
// tools/risc0-dump/src/main.rs::build_proof_json for the byte-level derivation.
package parser

import (
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
)

// ---------------------------------------------------------------------------
// snarkjs JSON shapes
// ---------------------------------------------------------------------------

type proofJSON struct {
	PiA      []string   `json:"pi_a"`
	PiB      [][]string `json:"pi_b"`
	PiC      []string   `json:"pi_c"`
	Protocol string     `json:"protocol"`
	Curve    string     `json:"curve"`
}

type verifyingKeyJSON struct {
	Protocol      string       `json:"protocol"`
	Curve         string       `json:"curve"`
	NPublic       int          `json:"nPublic"`
	VKAlpha1      []string     `json:"vk_alpha_1"`
	VKBeta2       [][]string   `json:"vk_beta_2"`
	VKGamma2      [][]string   `json:"vk_gamma_2"`
	VKDelta2      [][]string   `json:"vk_delta_2"`
	VKAlphabeta12 [][][]string `json:"vk_alphabeta_12"` // precomputed pairing, ignored — gnark recomputes
	IC            [][]string   `json:"IC"`
}

// publicInputsJSON is a bare top-level decimal-string array, e.g.
// `["1234", "5678"]`. We use json.Unmarshal directly on []string.

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// ParseProof loads a snarkjs proof.json into a native gnark BN254 Proof.
// The Commitments/CommitmentPok fields are left zero — risc0's BN254
// Groth16 doesn't use Groth16 commitments. groth16.Verify accepts that.
func ParseProof(path string) (*groth16_bn254.Proof, error) {
	var pj proofJSON
	if err := readJSON(path, &pj); err != nil {
		return nil, err
	}
	if pj.Protocol != "" && pj.Protocol != "groth16" {
		return nil, fmt.Errorf("proof.json: protocol=%q, expected groth16", pj.Protocol)
	}
	if pj.Curve != "" && pj.Curve != "bn128" && pj.Curve != "bn254" {
		return nil, fmt.Errorf("proof.json: curve=%q, expected bn128|bn254", pj.Curve)
	}

	ar, err := parseG1(pj.PiA, "pi_a")
	if err != nil {
		return nil, err
	}
	bs, err := parseG2(pj.PiB, "pi_b")
	if err != nil {
		return nil, err
	}
	krs, err := parseG1(pj.PiC, "pi_c")
	if err != nil {
		return nil, err
	}
	return &groth16_bn254.Proof{
		Ar:  ar,
		Bs:  bs,
		Krs: krs,
	}, nil
}

// ParseVerifyingKey loads a snarkjs verification_key.json and produces a
// fully-initialised native gnark BN254 VerifyingKey (including Precompute).
func ParseVerifyingKey(path string) (*groth16_bn254.VerifyingKey, error) {
	var vj verifyingKeyJSON
	if err := readJSON(path, &vj); err != nil {
		return nil, err
	}
	if vj.Protocol != "groth16" {
		return nil, fmt.Errorf("verification_key.json: protocol=%q, expected groth16", vj.Protocol)
	}
	if vj.Curve != "bn128" && vj.Curve != "bn254" {
		return nil, fmt.Errorf("verification_key.json: curve=%q, expected bn128|bn254", vj.Curve)
	}

	vk := &groth16_bn254.VerifyingKey{}
	var err error
	if vk.G1.Alpha, err = parseG1(vj.VKAlpha1, "vk_alpha_1"); err != nil {
		return nil, err
	}
	if vk.G2.Beta, err = parseG2(vj.VKBeta2, "vk_beta_2"); err != nil {
		return nil, err
	}
	if vk.G2.Gamma, err = parseG2(vj.VKGamma2, "vk_gamma_2"); err != nil {
		return nil, err
	}
	if vk.G2.Delta, err = parseG2(vj.VKDelta2, "vk_delta_2"); err != nil {
		return nil, err
	}
	if len(vj.IC) == 0 {
		return nil, fmt.Errorf("verification_key.json: empty IC")
	}
	// Sanity cap (the JSON byte cap already bounds this; explicit for clarity).
	if len(vj.IC) > 1<<20 {
		return nil, fmt.Errorf("verification_key.json: IC has %d points (max %d)", len(vj.IC), 1<<20)
	}
	if vj.NPublic != 0 && len(vj.IC) != vj.NPublic+1 {
		return nil, fmt.Errorf("verification_key.json: nPublic=%d but IC has %d points (expected %d)",
			vj.NPublic, len(vj.IC), vj.NPublic+1)
	}
	vk.G1.K = make([]curve.G1Affine, len(vj.IC))
	for i, ic := range vj.IC {
		p, err := parseG1(ic, fmt.Sprintf("IC[%d]", i))
		if err != nil {
			return nil, err
		}
		vk.G1.K[i] = p
	}
	if err := vk.Precompute(); err != nil {
		return nil, fmt.Errorf("vk.Precompute: %w", err)
	}
	return vk, nil
}

// ParsePublicInputs loads a snarkjs public.json (top-level array of decimal
// strings) into a native gnark witness over BN254. The returned witness
// contains only the public part — feed it directly to groth16.Verify.
func ParsePublicInputs(path string) (witness.Witness, error) {
	var values []string
	if err := readJSON(path, &values); err != nil {
		return nil, err
	}
	return PublicInputsFromDecimals(values)
}

// PublicInputsFromDecimals builds a BN254 public witness from N decimal-string
// values. Exposed in addition to ParsePublicInputs for use in tests and
// places where the JSON has already been decoded.
func PublicInputsFromDecimals(values []string) (witness.Witness, error) {
	w, err := witness.New(curve.ID.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("witness.New: %w", err)
	}
	ch := make(chan any, len(values))
	for i, s := range values {
		n, ok := new(big.Int).SetString(s, 10)
		if !ok {
			close(ch)
			return nil, fmt.Errorf("public input %d: %q is not a decimal integer", i, s)
		}
		ch <- *n
	}
	close(ch)
	if err := w.Fill(len(values), 0, ch); err != nil {
		return nil, fmt.Errorf("witness.Fill: %w", err)
	}
	return w, nil
}

// ---------------------------------------------------------------------------
// Field-element helpers
// ---------------------------------------------------------------------------

// parseFq parses a decimal string into a BN254 base-field element (Fq).
//
// We reject coordinates ≥ the field modulus rather than silently reducing them
// (fp.Element.SetString reduces mod q). A canonical snarkjs/risc0 VK never
// carries an out-of-range coordinate, so a value ≥ q signals a malformed or
// adversarial input — relevant on the --insecure-no-vk-check path where the
// fingerprint pin no longer guards the VK.
func parseFq(s, label string) (fp.Element, error) {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return fp.Element{}, fmt.Errorf("%s: %q is not a decimal integer", label, s)
	}
	if n.Sign() < 0 || n.Cmp(fp.Modulus()) >= 0 {
		return fp.Element{}, fmt.Errorf("%s: %q out of range for BN254 base field", label, s)
	}
	var e fp.Element
	e.SetBigInt(n)
	return e, nil
}

// parseG1 parses [x, y, "1"] (snarkjs projective with z=1) into an affine G1.
// The third coordinate is ignored — snarkjs always emits z=1 for finite points.
func parseG1(coords []string, label string) (curve.G1Affine, error) {
	if len(coords) < 2 {
		return curve.G1Affine{}, fmt.Errorf("%s: expected ≥2 coordinates, got %d", label, len(coords))
	}
	x, err := parseFq(coords[0], label+".x")
	if err != nil {
		return curve.G1Affine{}, err
	}
	y, err := parseFq(coords[1], label+".y")
	if err != nil {
		return curve.G1Affine{}, err
	}
	var p curve.G1Affine
	p.X = x
	p.Y = y
	if !p.IsOnCurve() {
		return curve.G1Affine{}, fmt.Errorf("%s: point not on G1", label)
	}
	// (0,0) is on-curve (the identity); snarkjs encodes only finite points.
	if p.IsInfinity() {
		return curve.G1Affine{}, fmt.Errorf("%s: point at infinity", label)
	}
	// BN254 G1 has cofactor 1 so on-curve ⇒ in-subgroup, but check explicitly:
	// the VK is baked into the R1CS unconditionally and gnark's native Verify
	// subgroup-checks only proof points, not VK points.
	if !p.IsInSubGroup() {
		return curve.G1Affine{}, fmt.Errorf("%s: point not in prime-order subgroup", label)
	}
	return p, nil
}

// parseG2 parses snarkjs G2 [[x.c1, x.c0], [y.c1, y.c0], ["1","0"]] into an
// affine G2.
//
// snarkjs/Ethereum convention is **c1-first** per Fp2 coordinate (verified
// against risc0-groth16's g2_from_bytes at risc0/groth16/src/lib.rs:122 —
// elem[i][1] feeds arkworks' canonical-deserialise as c0, elem[i][0] as c1).
// The trailing ["1","0"] is a snarkjs projective marker, not a meaningful
// Fp2 element, so it can't be used to disambiguate.
func parseG2(coords [][]string, label string) (curve.G2Affine, error) {
	if len(coords) < 2 {
		return curve.G2Affine{}, fmt.Errorf("%s: expected ≥2 Fp2 coordinates, got %d", label, len(coords))
	}
	if len(coords[0]) < 2 || len(coords[1]) < 2 {
		return curve.G2Affine{}, fmt.Errorf("%s: malformed Fp2", label)
	}
	xC1, err := parseFq(coords[0][0], label+".x.c1")
	if err != nil {
		return curve.G2Affine{}, err
	}
	xC0, err := parseFq(coords[0][1], label+".x.c0")
	if err != nil {
		return curve.G2Affine{}, err
	}
	yC1, err := parseFq(coords[1][0], label+".y.c1")
	if err != nil {
		return curve.G2Affine{}, err
	}
	yC0, err := parseFq(coords[1][1], label+".y.c0")
	if err != nil {
		return curve.G2Affine{}, err
	}
	var p curve.G2Affine
	p.X.A0 = xC0
	p.X.A1 = xC1
	p.Y.A0 = yC0
	p.Y.A1 = yC1
	if !p.IsOnCurve() {
		return curve.G2Affine{}, fmt.Errorf("%s: point not on G2", label)
	}
	if p.IsInfinity() {
		return curve.G2Affine{}, fmt.Errorf("%s: point at infinity", label)
	}
	// BN254 G2 has a nontrivial cofactor, so on-curve does NOT imply
	// in-subgroup. An off-subgroup VK G2 point (beta/gamma/delta) would
	// otherwise be baked into the outer R1CS unchecked.
	if !p.IsInSubGroup() {
		return curve.G2Affine{}, fmt.Errorf("%s: point not in prime-order subgroup", label)
	}
	return p, nil
}

// maxJSONBytes caps untrusted snarkjs JSON. Real VK/proof/public files are a
// few KB; the cap defends against a JSON/decimal-string bomb causing OOM or a
// CPU spike in big.Int parsing.
const maxJSONBytes = 16 << 20

func readJSON(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxJSONBytes+1))
	if err != nil {
		return fmt.Errorf("read %q: %w", path, err)
	}
	if len(data) > maxJSONBytes {
		return fmt.Errorf("%q exceeds the %d-byte JSON cap (possible bomb)", path, maxJSONBytes)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("unmarshal %q: %w", path, err)
	}
	return nil
}
