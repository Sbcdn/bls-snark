package keycheck

import (
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// cubicCircuit: Y == X³ + X + 5. A small stand-in for any BLS12-381 Groth16
// circuit — keycheck is curve- and circuit-agnostic in what it validates.
type cubicCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *cubicCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.Y, api.Add(api.Mul(c.X, c.X, c.X), c.X, 5))
	return nil
}

// cubicVariant: Y == X³ + X + 7. Same wire/public/constraint shape as
// cubicCircuit but a different relation — used to document the QAP-binding gap.
type cubicVariant struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *cubicVariant) Define(api frontend.API) error {
	api.AssertIsEqual(c.Y, api.Add(api.Mul(c.X, c.X, c.X), c.X, 7))
	return nil
}

// wideCircuit has an extra wire, so a key built for cubicCircuit is
// structurally inconsistent with it.
type wideCircuit struct {
	X, Z frontend.Variable
	Y    frontend.Variable `gnark:",public"`
}

func (c *wideCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.Y, api.Add(api.Mul(c.X, c.X), api.Mul(c.Z, c.Z)))
	return nil
}

// commitCircuit exercises the commitment-count checks (nbCommitments == 1).
type commitCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *commitCircuit) Define(api frontend.API) error {
	committer, ok := api.(frontend.Committer)
	if !ok {
		return errors.New("api does not implement frontend.Committer")
	}
	x2 := api.Mul(c.X, c.X)
	cm, err := committer.Commit(x2)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(cm, 0)
	api.AssertIsEqual(c.Y, x2)
	return nil
}

func compile(t *testing.T, field *big.Int, c frontend.Circuit) constraint.ConstraintSystem {
	t.Helper()
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, c)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return ccs
}

func setup(t *testing.T, ccs constraint.ConstraintSystem) (groth16.ProvingKey, groth16.VerifyingKey) {
	t.Helper()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	return pk, vk
}

func TestVerifyAcceptsMatchingKeys(t *testing.T) {
	for _, c := range []frontend.Circuit{&cubicCircuit{}, &commitCircuit{}} {
		ccs := compile(t, ecc.BLS12_381.ScalarField(), c)
		pk, vk := setup(t, ccs)
		if err := Verify(ccs, pk, vk); err != nil {
			t.Fatalf("Verify rejected a matching (ccs, pk, vk) for %T: %v", c, err)
		}
	}
}

func TestVerifyRejects(t *testing.T) {
	tests := []struct {
		name        string
		build       func(t *testing.T) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey)
		wantErrPart string
	}{
		{
			name: "wrong circuit shape",
			build: func(t *testing.T) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey) {
				pk, vk := setup(t, compile(t, ecc.BLS12_381.ScalarField(), &cubicCircuit{}))
				return compile(t, ecc.BLS12_381.ScalarField(), &wideCircuit{}), pk, vk
			},
			wantErrPart: "wires",
		},
		{
			name: "mismatched pk/vk pair",
			build: func(t *testing.T) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey) {
				ccs := compile(t, ecc.BLS12_381.ScalarField(), &cubicCircuit{})
				pk, _ := setup(t, ccs)
				_, vk2 := setup(t, ccs) // independent setup → different toxic waste
				return ccs, pk, vk2
			},
			wantErrPart: "different setups",
		},
		{
			name: "non-BLS12-381 proving key",
			build: func(t *testing.T) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey) {
				ccs := compile(t, ecc.BLS12_381.ScalarField(), &cubicCircuit{})
				_, vk := setup(t, ccs)
				pkBN, _ := setup(t, compile(t, ecc.BN254.ScalarField(), &cubicCircuit{}))
				return ccs, pkBN, vk
			},
			wantErrPart: "proving key is not a BLS12-381 key",
		},
		{
			name: "non-BLS12-381 verifying key",
			build: func(t *testing.T) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey) {
				ccs := compile(t, ecc.BLS12_381.ScalarField(), &cubicCircuit{})
				pk, _ := setup(t, ccs)
				_, vkBN := setup(t, compile(t, ecc.BN254.ScalarField(), &cubicCircuit{}))
				return ccs, pk, vkBN
			},
			wantErrPart: "verifying key is not a BLS12-381 key",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ccs, pk, vk := tc.build(t)
			err := Verify(ccs, pk, vk)
			if err == nil {
				t.Fatalf("Verify accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErrPart) {
				t.Fatalf("error %q does not mention %q", err, tc.wantErrPart)
			}
		})
	}
}

// TestVerifyKnownLimitationSameShape pins the documented QAP-binding gap: keys
// from a different circuit with an identical wire/public/commitment shape and
// constraint count pass the witness-free checks. The real guarantee against
// this is the prove → verify round trip, not keycheck.
func TestVerifyKnownLimitationSameShape(t *testing.T) {
	ccsCubic := compile(t, ecc.BLS12_381.ScalarField(), &cubicCircuit{})
	pk, vk := setup(t, ccsCubic)
	ccsVariant := compile(t, ecc.BLS12_381.ScalarField(), &cubicVariant{})
	if err := Verify(ccsVariant, pk, vk); err != nil {
		t.Fatalf("expected the same-shape limitation to pass keycheck, got: %v", err)
	}
}
