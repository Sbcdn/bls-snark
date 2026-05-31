package inner

import (
	"path/filepath"
	"testing"

	"github.com/sbcdn/bls-snark/internal/parser"
)

// TestPrintCanonicalRISC0VKFingerprint runs once (or on demand) to print
// the SHA-256 fingerprint of the canonical risc0 BN254 VK. Use the output
// to update `CanonicalRISC0VKFingerprint` in vk_fingerprint.go when risc0
// rotates its ceremony.
//
// Skipped automatically when testdata/risc0/verification_key.json is missing.
func TestPrintCanonicalRISC0VKFingerprint(t *testing.T) {
	vkPath := filepath.Join("..", "..", "testdata", "risc0", "verification_key.json")
	vk, err := parser.ParseVerifyingKey(vkPath)
	if err != nil {
		t.Skipf("testdata/risc0/verification_key.json missing: %v", err)
		return
	}
	fp, err := FingerprintVK(vk)
	if err != nil {
		t.Fatalf("FingerprintVK: %v", err)
	}
	t.Logf("canonical risc0 VK fingerprint: %s", fp)
}

// TestCanonicalFingerprintMatchesEmbeddedConst is the regression: if the
// constant `CanonicalRISC0VKFingerprint` ever drifts from what the testdata
// produces, this test fails LOUDLY. Either the constant or the testdata
// is wrong — investigate before silently updating.
func TestCanonicalFingerprintMatchesEmbeddedConst(t *testing.T) {
	vkPath := filepath.Join("..", "..", "testdata", "risc0", "verification_key.json")
	vk, err := parser.ParseVerifyingKey(vkPath)
	if err != nil {
		t.Skipf("testdata/risc0/verification_key.json missing: %v", err)
		return
	}
	fp, err := FingerprintVK(vk)
	if err != nil {
		t.Fatalf("FingerprintVK: %v", err)
	}
	if fp != CanonicalRISC0VKFingerprint {
		t.Fatalf("canonical risc0 VK fingerprint drifted:\n  embedded: %s\n  computed: %s\n  Update vk_fingerprint.go ONLY after confirming the testdata change is intentional (risc0 ceremony rotation).",
			CanonicalRISC0VKFingerprint, fp)
	}
}
