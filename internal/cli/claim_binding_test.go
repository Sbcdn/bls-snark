package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/sbcdn/bls-snark/internal/parser"
)

// Committed-fixture (testdata/risc0) risc0 values.
const (
	fixtureClaimDigest    = "3a01ada1d6df0f884426559b9902b1c03a9a348a58397e11c7e45470fadd1b11"
	fixtureControlRoot    = "a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56"
	fixtureBN254ControlID = "c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404"
)

// TestProveExpectFlagsRequireRISC0 covers the CLI wiring (not just the helper):
// the --expect-* flags must hard-fail on a non-risc0 source, before any proving.
func TestProveExpectFlagsRequireRISC0(t *testing.T) {
	cmd := newProveCmd(zerolog.Nop())
	cmd.SetArgs([]string{"--inner-source", "cubic", "--expect-claim-digest", fixtureClaimDigest})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "risc0 only") {
		t.Fatalf("expected a 'risc0 only' error, got %v", err)
	}
}

func TestVerifyExpectedClaimBindings(t *testing.T) {
	pubPath := filepath.Join("..", "..", "testdata", "risc0", "public.json")
	if _, err := os.Stat(pubPath); err != nil {
		t.Skipf("fixture public.json missing (%s)", pubPath)
	}
	innerPub, err := parser.ParsePublicInputs(pubPath)
	if err != nil {
		t.Fatalf("ParsePublicInputs: %v", err)
	}

	t.Run("all correct passes", func(t *testing.T) {
		if err := verifyExpectedClaimBindings(innerPub, fixtureClaimDigest, fixtureControlRoot, fixtureBN254ControlID); err != nil {
			t.Fatalf("expected match, got error: %v", err)
		}
	})

	t.Run("0x prefix accepted", func(t *testing.T) {
		if err := verifyExpectedClaimBindings(innerPub, "0x"+fixtureClaimDigest, "", ""); err != nil {
			t.Fatalf("0x-prefixed claim_digest should match: %v", err)
		}
	})

	t.Run("empty skips", func(t *testing.T) {
		if err := verifyExpectedClaimBindings(innerPub, "", "", ""); err != nil {
			t.Fatalf("no pins should be a no-op: %v", err)
		}
	})

	// Each wrong value must be rejected, naming the right field.
	wrong := "00" + fixtureClaimDigest[2:] // flip first byte
	for _, tc := range []struct {
		name, claim, ctrl, bn254, wantSub string
	}{
		{"wrong claim_digest", "00" + fixtureClaimDigest[2:], "", "", "claim_digest"},
		{"wrong control_root", "", "00" + fixtureControlRoot[2:], "", "control_root"},
		{"wrong bn254_control_id", "", "", "00" + fixtureBN254ControlID[2:], "bn254_control_id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyExpectedClaimBindings(innerPub, tc.claim, tc.ctrl, tc.bn254)
			if err == nil {
				t.Fatal("expected a mismatch error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not mention %q", err.Error(), tc.wantSub)
			}
		})
	}

	t.Run("malformed hex rejected", func(t *testing.T) {
		if err := verifyExpectedClaimBindings(innerPub, "nothex", "", ""); err == nil {
			t.Fatal("expected hex parse error")
		}
		if err := verifyExpectedClaimBindings(innerPub, wrong[:10], "", ""); err == nil {
			t.Fatal("expected wrong-length error")
		}
	})
}
