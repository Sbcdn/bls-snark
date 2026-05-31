// Package circuit defines OuterCircuit — a BLS12-381-hosted Groth16 verifier
// for a BN254 Groth16 proof. The pattern is a faithful adaptation of gnark
// v0.15.0's std/recursion/groth16/verifier_test.go::OuterCircuitConstant.
package circuit

import (
	"fmt"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// OuterCircuit verifies a BN254 Groth16 proof in-circuit, compiled over BLS12-381.
//
// Field shape:
//   - Proof: private witness.
//   - InnerWitness: PUBLIC witness (gnark:",public"). Soundness-critical:
//     without it, the outer proof commits to no inner statement.
//   - vk: unexported AND gnark:"-". Baked into the R1CS at compile time
//     via ValueOfVerifyingKeyFixed; the unexported + tag combination keeps
//     it out of the witness collection.
type OuterCircuit struct {
	Proof        stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	InnerWitness stdgroth16.Witness[sw_bn254.ScalarField] `gnark:",public"`

	vk stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl] `gnark:"-"`
}

// Compile-time assertion that OuterCircuit satisfies frontend.Circuit.
var _ frontend.Circuit = (*OuterCircuit)(nil)

// Define wires the Groth16 verifier. Complete EC arithmetic is the
// unconditional default in gnark v0.15.0 so no options are needed.
func (c *OuterCircuit) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[
		sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl,
	](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	return verifier.AssertProof(c.vk, c.Proof, c.InnerWitness)
}

// NewOuterCircuitForCompile builds an instance with placeholder Proof and
// InnerWitness sized from the inner ccs, and the inner VK baked as a constant.
// Pass the result to frontend.Compile.
func NewOuterCircuitForCompile(
	innerCcs constraint.ConstraintSystem,
	innerVK groth16.VerifyingKey,
) (*OuterCircuit, error) {
	fixedVK, err := stdgroth16.ValueOfVerifyingKeyFixed[
		sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl,
	](innerVK)
	if err != nil {
		return nil, fmt.Errorf("bake inner vk: %w", err)
	}
	return &OuterCircuit{
		Proof:        stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs),
		InnerWitness: stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs),
		vk:           fixedVK,
	}, nil
}

// NewOuterCircuitForProve builds an instance with concrete proof + witness.
// vk is zero-valued — it was baked into the ccs at compile time and is not
// part of the witness.
func NewOuterCircuitForProve(
	innerProof groth16.Proof,
	innerPubWitness witness.Witness,
) (*OuterCircuit, error) {
	circuitProof, err := stdgroth16.ValueOfProof[
		sw_bn254.G1Affine, sw_bn254.G2Affine,
	](innerProof)
	if err != nil {
		return nil, fmt.Errorf("convert inner proof: %w", err)
	}
	circuitWitness, err := stdgroth16.ValueOfWitness[sw_bn254.ScalarField](innerPubWitness)
	if err != nil {
		return nil, fmt.Errorf("convert inner witness: %w", err)
	}
	return &OuterCircuit{
		Proof:        circuitProof,
		InnerWitness: circuitWitness,
	}, nil
}
