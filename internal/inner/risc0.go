package inner

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/sbcdn/bls-snark/internal/parser"
)

// risc0StubCircuit is a synthetic BN254 circuit with N public inputs and no
// commitments. The outer-circuit placeholder needs a constraint.ConstraintSystem
// to size Proof / Witness, but RISC0 ships only the VK + proof + public-input
// scalars, not the inner R1CS itself. The placeholder factories only ever
// query GetNbPublicVariables() and GetCommitments(), so a circuit with the
// right public-input count and zero commitments is a sufficient size-only proxy.
type risc0StubCircuit struct {
	Pub []frontend.Variable `gnark:",public"`
}

func (c *risc0StubCircuit) Define(api frontend.API) error {
	// Need at least one constraint; assert each public var equals itself.
	for i := range c.Pub {
		api.AssertIsEqual(c.Pub[i], c.Pub[i])
	}
	return nil
}

// RISC0SetupOptions controls optional validation behaviour for the inner VK.
//
// Default (zero value): require the inner VK's fingerprint to match
// [CanonicalRISC0VKFingerprint] — i.e. the canonical risc0 ceremony output.
// Production callers should NOT override unless they know what they're doing.
type RISC0SetupOptions struct {
	// AcceptVKFingerprint, if non-empty, replaces the canonical fingerprint
	// for the duration of this call. Use only when validating against a
	// known-good non-default VK (e.g. a future risc0 ceremony rotation
	// before this repo is updated; or a non-risc0 BN254 Groth16 input).
	// The value is a 64-char lowercase hex SHA-256 of the gnark-native
	// binary form of the VK (see inner.FingerprintVK).
	AcceptVKFingerprint string

	// SkipVKFingerprintCheck disables the canonical-VK check entirely.
	// INSECURE — only set for debugging or local experimentation. The wrap
	// will still produce a valid Groth16 proof, but the outer circuit will
	// commit to whatever VK was passed in; downstream consumers have no
	// guarantee it's the canonical risc0 VK.
	SkipVKFingerprintCheck bool
}

// LoadRISC0InnerSetup parses a snarkjs-style verification_key.json (as
// produced by `tools/risc0-dump`) and returns:
//   - a stub BN254 R1CS whose GetNbPublicVariables() / GetCommitments() match
//     RISC0's actual inner verifier shape (5 public + 1 "one" wire, 0 commitments)
//   - the native gnark BN254 VerifyingKey reconstructed from the JSON
//
// The stub ccs is only used to size the outer-circuit placeholders — it never
// gets used as a real prover input.
//
// Validation:
//   - The VK must have at least 2 IC points (i.e. ≥ 1 public input).
//   - The VK must declare zero Groth16 Pedersen commitments. RISC0's BN254
//     Groth16 doesn't use them today; if a future risc0 release adds them,
//     the stub-circuit sizing here would be silently wrong, so we abort.
//   - The VK fingerprint must equal [CanonicalRISC0VKFingerprint], unless
//     overridden via opts.AcceptVKFingerprint or opts.SkipVKFingerprintCheck.
func LoadRISC0InnerSetup(vkJSONPath string, opts RISC0SetupOptions) (constraint.ConstraintSystem, groth16.VerifyingKey, error) {
	vk, err := parser.ParseVerifyingKey(vkJSONPath)
	if err != nil {
		return nil, nil, fmt.Errorf("parse inner VK: %w", err)
	}
	nPublic := len(vk.G1.K) - 1
	if nPublic <= 0 {
		return nil, nil, fmt.Errorf("inner VK has %d IC points; expected ≥ 2", len(vk.G1.K))
	}
	if len(vk.CommitmentKeys) != 0 {
		// The stub circuit below has zero commitments. RISC0's BN254 Groth16
		// historically doesn't ship any — if that ever changes upstream, the
		// placeholder sizing here would silently mis-size, so we abort.
		return nil, nil, fmt.Errorf("inner VK declares %d commitment keys; risc0 path requires 0 (extension would need a new wrapper version)", len(vk.CommitmentKeys))
	}

	if err := checkInnerVKFingerprint(vk, opts); err != nil {
		return nil, nil, err
	}

	stub := &risc0StubCircuit{Pub: make([]frontend.Variable, nPublic)}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, stub)
	if err != nil {
		return nil, nil, fmt.Errorf("compile risc0 stub circuit: %w", err)
	}
	return ccs, vk, nil
}

// checkInnerVKFingerprint compares the parsed VK against the canonical
// RISC0 VK fingerprint, with two opt-out paths per RISC0SetupOptions.
func checkInnerVKFingerprint(vk groth16.VerifyingKey, opts RISC0SetupOptions) error {
	if opts.SkipVKFingerprintCheck {
		return nil
	}
	expected := CanonicalRISC0VKFingerprint
	if opts.AcceptVKFingerprint != "" {
		expected = opts.AcceptVKFingerprint
	}
	got, err := FingerprintVK(vk)
	if err != nil {
		return fmt.Errorf("compute VK fingerprint: %w", err)
	}
	if got != expected {
		return fmt.Errorf(
			"inner VK fingerprint mismatch: expected %s, got %s. "+
				"If you're wrapping the canonical risc0 ceremony output, the --inner-vk JSON has been modified or corrupted. "+
				"If you're intentionally wrapping a different VK (a new risc0 ceremony, or a non-risc0 BN254 Groth16 input), "+
				"either pass --inner-vk-fingerprint %s to lock in the new VK, "+
				"or pass --insecure-no-vk-check to disable the check (INSECURE — dev only)",
			expected, got, got,
		)
	}
	return nil
}

// LoadRISC0Proof parses the snarkjs proof.json + public.json pair into native
// gnark BN254 types. The returned witness is the public-witness only.
func LoadRISC0Proof(proofJSONPath, publicJSONPath string) (groth16.Proof, witness.Witness, error) {
	proof, err := parser.ParseProof(proofJSONPath)
	if err != nil {
		return nil, nil, fmt.Errorf("parse proof: %w", err)
	}
	pub, err := parser.ParsePublicInputs(publicJSONPath)
	if err != nil {
		return nil, nil, fmt.Errorf("parse public inputs: %w", err)
	}
	return proof, pub, nil
}
