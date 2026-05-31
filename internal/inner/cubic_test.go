package inner

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
)

// TestCubicSetupProveVerify exercises GenerateCubicSetup + ProveCubic +
// VerifyCubicNative end-to-end.
//
// We use BLS12-381 as the outer field — it's the value the wrapper passes at
// prove time. Verifying with the same outer field is what matters; the proof
// must round-trip native verify.
func TestCubicSetupProveVerify(t *testing.T) {
	ccs, pk, vk, err := GenerateCubicSetup()
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if got := ccs.GetNbConstraints(); got == 0 {
		t.Fatalf("expected non-zero inner constraints, got %d", got)
	}

	outer := ecc.BLS12_381.ScalarField()
	proof, pub, err := ProveCubic(ccs, pk, big.NewInt(3), big.NewInt(35), outer)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if err := VerifyCubicNative(proof, vk, pub, outer); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestCubicWrongWitness ensures a bad assignment fails to prove — guards
// against accidentally accepting an unsatisfied circuit.
func TestCubicWrongWitness(t *testing.T) {
	ccs, pk, _, err := GenerateCubicSetup()
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	// 3^3 + 3 + 5 = 35, not 36.
	_, _, err = ProveCubic(ccs, pk, big.NewInt(3), big.NewInt(36), ecc.BLS12_381.ScalarField())
	if err == nil {
		t.Fatal("expected prove to fail on unsatisfied cubic; got nil")
	}
}
