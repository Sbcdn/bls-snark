// Package keycheck validates an externally-produced Groth16 proving and
// verifying key against the constraint system they are meant to belong to.
//
// gnark exposes no primitive for "verify (pk, vk) against ccs", so when keys
// arrive from an MPC ceremony the setup path would otherwise accept them
// verbatim. This package performs every consistency check that is possible
// without a satisfying witness:
//
//   - structural: matching wire, public-input and commitment counts, and a
//     matching evaluation-domain size;
//   - pairing-element: the [α]₁, [β]₂ and [δ]₂ elements shared between a valid
//     proving/verifying key pair must be identical, which detects a pk and vk
//     taken from two different setups.
//
// These checks fail closed on any mismatch. They do not, on their own, prove
// the keys encode this exact circuit's QAP — that guarantee comes from a full
// prove-and-verify round trip, which the normal prove → verify flow performs.
// They also cannot constrain [γ]₂, which appears only in the verifying key
// (there is nothing in the proving key to compare it against); the round trip
// is what covers it.
package keycheck

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/constraint"
)

// Verify reports whether pk and vk are mutually consistent and structurally
// match ccs. It returns a descriptive error on the first inconsistency.
//
// pk and vk must be BLS12-381 keys; ccs is the outer constraint system the
// keys claim to belong to.
func Verify(ccs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey) error {
	bpk, ok := pk.(*groth16bls12381.ProvingKey)
	if !ok {
		return fmt.Errorf("proving key is not a BLS12-381 key (%T)", pk)
	}
	bvk, ok := vk.(*groth16bls12381.VerifyingKey)
	if !ok {
		return fmt.Errorf("verifying key is not a BLS12-381 key (%T)", vk)
	}

	nbWires := ccs.GetNbInternalVariables() + ccs.GetNbPublicVariables() + ccs.GetNbSecretVariables()
	nbCommitments := len(ccs.GetCommitments().CommitmentIndexes())
	nbPublicWires := ccs.GetNbPublicVariables() + nbCommitments

	// Domain size: the proving key's FFT domain must be the one Setup derives
	// from the constraint count (the next power of two ≥ the constraint count).
	wantCardinality := ecc.NextPowerOfTwo(uint64(ccs.GetNbConstraints()))
	if bpk.Domain.Cardinality != wantCardinality {
		return fmt.Errorf("proving key domain cardinality %d does not match ccs (%d constraints → %d)",
			bpk.Domain.Cardinality, ccs.GetNbConstraints(), wantCardinality)
	}

	// Wire count. The A query drops wires whose A polynomial is zero (counted
	// in NbInfinityA), so the full wire count is the stored elements plus those
	// dropped infinities.
	if got := len(bpk.G1.A) + int(bpk.NbInfinityA); got != nbWires {
		return fmt.Errorf("proving key encodes %d wires, ccs has %d", got, nbWires)
	}
	if got := len(bvk.G1.K); got != nbPublicWires {
		return fmt.Errorf("verifying key has %d public-input elements, ccs has %d public wires (%d public + %d commitments)",
			got, nbPublicWires, ccs.GetNbPublicVariables(), nbCommitments)
	}

	// Commitment counts must agree across ccs, pk and vk.
	if len(bpk.CommitmentKeys) != nbCommitments || len(bvk.CommitmentKeys) != nbCommitments {
		return fmt.Errorf("commitment-key count mismatch: ccs=%d pk=%d vk=%d",
			nbCommitments, len(bpk.CommitmentKeys), len(bvk.CommitmentKeys))
	}

	// The shared setup elements must be non-degenerate. An honest gnark setup
	// never samples a zero scalar, but an adversarial or non-gnark ceremony
	// could supply the point at infinity, which would then pass the equality
	// checks below (∞ == ∞) and slip a degenerate key through.
	if bpk.G1.Alpha.IsInfinity() || bpk.G2.Beta.IsInfinity() || bpk.G2.Delta.IsInfinity() {
		return fmt.Errorf("degenerate key: [α]₁, [β]₂ or [δ]₂ is the point at infinity")
	}

	// Shared setup elements: in a valid pair these are copied from pk into vk,
	// so inequality means the two keys come from different setups.
	if !bvk.G1.Alpha.Equal(&bpk.G1.Alpha) {
		return fmt.Errorf("pk/vk mismatch: [α]₁ differs — keys are from different setups")
	}
	if !bvk.G2.Beta.Equal(&bpk.G2.Beta) {
		return fmt.Errorf("pk/vk mismatch: [β]₂ differs — keys are from different setups")
	}
	if !bvk.G2.Delta.Equal(&bpk.G2.Delta) {
		return fmt.Errorf("pk/vk mismatch: [δ]₂ differs — keys are from different setups")
	}

	return nil
}
