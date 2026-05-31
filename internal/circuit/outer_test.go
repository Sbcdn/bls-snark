package circuit

import (
	"bytes"
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// trivialMulCircuit mirrors upstream's std/recursion/groth16/verifier_test.go::InnerCircuit:
//
//	P * Q == N, with N public.
//
// One Mul + one AssertIsEqual = ~1 inner constraint, 1 inner public input.
// Same shape as upstream so the per-pub-input verifier cost we see here is
// directly comparable to upstream's TestBW6InBN254Constant.
type trivialMulCircuit struct {
	P, Q frontend.Variable
	N    frontend.Variable `gnark:",public"`
}

func (c *trivialMulCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.P, c.Q), c.N)
	return nil
}

// genericOuter is the upstream generic OuterCircuitConstant shape — used here
// to compile a BW6-in-BN254 reference alongside our BN254-in-BLS12-381 target.
type genericOuter[
	FR emulated.FieldParams,
	G1El algebra.G1ElementT,
	G2El algebra.G2ElementT,
	GtEl algebra.GtElementT,
] struct {
	Proof        stdgroth16.Proof[G1El, G2El]
	InnerWitness stdgroth16.Witness[FR] `gnark:",public"`

	vk stdgroth16.VerifyingKey[G1El, G2El, GtEl] `gnark:"-"`
}

func (c *genericOuter[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	return verifier.AssertProof(c.vk, c.Proof, c.InnerWitness)
}

// compileEmulated compiles an outer circuit over `outerField` that verifies
// a Groth16 proof native to `innerField`, with the VK baked as a constant.
// Returns the outer constraint count and a sample-proven outer proof byte length.
//
// Runs setup + prove (not just compile) so the constraint count and the
// proof byte size are measured on the same artifacts.
func compileEmulated[
	FR emulated.FieldParams,
	G1El algebra.G1ElementT,
	G2El algebra.G2ElementT,
	GtEl algebra.GtElementT,
](
	t *testing.T,
	label string,
	innerField, outerField *big.Int,
) (int, int) {
	t.Helper()

	// 1. Inner setup + proof using the upstream trivial circuit (P*Q==N).
	innerCcs, err := frontend.Compile(innerField, r1cs.NewBuilder, &trivialMulCircuit{})
	if err != nil {
		t.Fatalf("[%s] inner compile: %v", label, err)
	}
	innerPK, innerVK, err := groth16.Setup(innerCcs)
	if err != nil {
		t.Fatalf("[%s] inner setup: %v", label, err)
	}
	innerAssign := &trivialMulCircuit{P: 3, Q: 5, N: 15}
	innerFull, err := frontend.NewWitness(innerAssign, innerField)
	if err != nil {
		t.Fatalf("[%s] inner witness: %v", label, err)
	}
	innerProof, err := groth16.Prove(
		innerCcs, innerPK, innerFull,
		stdgroth16.GetNativeProverOptions(outerField, innerField),
	)
	if err != nil {
		t.Fatalf("[%s] inner prove: %v", label, err)
	}
	innerPub, err := innerFull.Public()
	if err != nil {
		t.Fatalf("[%s] inner public: %v", label, err)
	}
	if err := groth16.Verify(
		innerProof, innerVK, innerPub,
		stdgroth16.GetNativeVerifierOptions(outerField, innerField),
	); err != nil {
		t.Fatalf("[%s] inner verify: %v", label, err)
	}

	// 2. Outer placeholder with baked VK.
	fixedVK, err := stdgroth16.ValueOfVerifyingKeyFixed[G1El, G2El, GtEl](innerVK)
	if err != nil {
		t.Fatalf("[%s] bake VK: %v", label, err)
	}
	outerPlaceholder := &genericOuter[FR, G1El, G2El, GtEl]{
		Proof:        stdgroth16.PlaceholderProof[G1El, G2El](innerCcs),
		InnerWitness: stdgroth16.PlaceholderWitness[FR](innerCcs),
		vk:           fixedVK,
	}
	outerCcs, err := frontend.Compile(outerField, r1cs.NewBuilder, outerPlaceholder)
	if err != nil {
		t.Fatalf("[%s] outer compile: %v", label, err)
	}
	nC := outerCcs.GetNbConstraints()
	t.Logf("[%s] outer constraints: %d", label, nC)

	// 3. Outer setup + prove to measure proof size.
	outerPK, _, err := groth16.Setup(outerCcs)
	if err != nil {
		t.Fatalf("[%s] outer setup: %v", label, err)
	}
	circuitProof, err := stdgroth16.ValueOfProof[G1El, G2El](innerProof)
	if err != nil {
		t.Fatalf("[%s] convert inner proof: %v", label, err)
	}
	circuitWitness, err := stdgroth16.ValueOfWitness[FR](innerPub)
	if err != nil {
		t.Fatalf("[%s] convert inner witness: %v", label, err)
	}
	outerAssign := &genericOuter[FR, G1El, G2El, GtEl]{
		Proof:        circuitProof,
		InnerWitness: circuitWitness,
	}
	outerFull, err := frontend.NewWitness(outerAssign, outerField)
	if err != nil {
		t.Fatalf("[%s] outer witness: %v", label, err)
	}
	outerProof, err := groth16.Prove(outerCcs, outerPK, outerFull)
	if err != nil {
		t.Fatalf("[%s] outer prove: %v", label, err)
	}
	var buf bytes.Buffer
	if _, err := outerProof.WriteTo(&buf); err != nil {
		t.Fatalf("[%s] outer proof write: %v", label, err)
	}
	nB := buf.Len()
	t.Logf("[%s] outer proof bytes: %d", label, nB)
	return nC, nB
}

// TestInnerWitnessIsPublic is the soundness regression for the production
// OuterCircuit type (not the genericOuter test copy): InnerWitness MUST carry
// `gnark:",public"`. If the tag is dropped, the outer proof
// commits to no inner statement. We build a public-only witness from the real
// circuit.OuterCircuit and assert the inner public inputs landed in the public
// segment as emulated limbs. Cheap — no outer compile, only a tiny BN254 inner.
func TestInnerWitnessIsPublic(t *testing.T) {
	const innerField = ecc.BN254
	innerCcs, err := frontend.Compile(innerField.ScalarField(), r1cs.NewBuilder, &trivialMulCircuit{})
	if err != nil {
		t.Fatalf("inner compile: %v", err)
	}
	innerPK, _, err := groth16.Setup(innerCcs)
	if err != nil {
		t.Fatalf("inner setup: %v", err)
	}
	innerFull, err := frontend.NewWitness(&trivialMulCircuit{P: 3, Q: 5, N: 15}, innerField.ScalarField())
	if err != nil {
		t.Fatalf("inner witness: %v", err)
	}
	innerProof, err := groth16.Prove(innerCcs, innerPK, innerFull,
		stdgroth16.GetNativeProverOptions(ecc.BLS12_381.ScalarField(), innerField.ScalarField()))
	if err != nil {
		t.Fatalf("inner prove: %v", err)
	}
	innerPub, err := innerFull.Public()
	if err != nil {
		t.Fatalf("inner public: %v", err)
	}

	outerAssign, err := NewOuterCircuitForProve(innerProof, innerPub)
	if err != nil {
		t.Fatalf("build outer assignment: %v", err)
	}
	pubWit, err := frontend.NewWitness(outerAssign, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatalf("public witness: %v", err)
	}

	nPublic := reflect.ValueOf(pubWit.Vector()).Len()
	var sf sw_bn254.ScalarField
	const nInnerPub = 1 // trivialMulCircuit exposes exactly N
	want := nInnerPub * int(sf.NbLimbs())
	if nPublic == 0 {
		t.Fatal("OuterCircuit produced ZERO public inputs — InnerWitness lost its `gnark:\",public\"` tag (soundness regression)")
	}
	if nPublic != want {
		t.Fatalf("public witness has %d scalars; expected %d (= %d inner public × %d limbs)",
			nPublic, want, nInnerPub, sf.NbLimbs())
	}
}

// TestCanonicalEmulatedConstantCounts compiles two reference shapes —
// BW6-in-BN254 (upstream's TestBW6InBN254Constant pattern) and our target
// BN254-in-BLS12-381 — and reports constraint count + proof byte size for
// each. Purpose: establish that our 766K / 292B numbers are canonical for
// gnark v0.15.0's std/recursion/groth16, not a construction error.
//
// Skipped under -short because each leg runs a full prove.
func TestCanonicalEmulatedConstantCounts(t *testing.T) {
	if testing.Short() {
		t.Skip("expensive — runs two full Groth16 setup+prove cycles")
	}

	type row struct {
		label                  string
		constraintCount, bytes int
	}
	var rows []row

	// Reference: BW6_761 inner inside BN254 outer (upstream's canonical
	// emulated-constant test).
	c, b := compileEmulated[
		sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl,
	](t, "BW6_761→BN254", ecc.BW6_761.ScalarField(), ecc.BN254.ScalarField())
	rows = append(rows, row{"BW6_761→BN254", c, b})

	// Our target: BN254 inner inside BLS12-381 outer.
	c, b = compileEmulated[
		sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl,
	](t, "BN254→BLS12_381", ecc.BN254.ScalarField(), ecc.BLS12_381.ScalarField())
	rows = append(rows, row{"BN254→BLS12_381", c, b})

	t.Logf("=========================================================")
	t.Logf("canonical emulated-constant pattern — gnark v0.15.0")
	t.Logf("=========================================================")
	for _, r := range rows {
		t.Logf("%-18s  constraints=%d  proof_bytes=%d", r.label, r.constraintCount, r.bytes)
	}
	t.Logf("(inner: P*Q==N, 1 public input)")
}
