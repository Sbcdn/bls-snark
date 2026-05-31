package inner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// vkPathForTest returns the canonical risc0 VK JSON path, or skips the test
// if the testdata isn't there.
func vkPathForTest(t *testing.T) string {
	t.Helper()
	p := filepath.Join("..", "..", "testdata", "risc0", "verification_key.json")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("testdata/risc0/verification_key.json missing: %v", err)
	}
	return p
}

// TestLoadRISC0_AcceptsCanonical confirms the default (no overrides) loads
// the canonical risc0 VK successfully.
func TestLoadRISC0_AcceptsCanonical(t *testing.T) {
	_, _, err := LoadRISC0InnerSetup(vkPathForTest(t), RISC0SetupOptions{})
	if err != nil {
		t.Fatalf("canonical VK should load with default options, got: %v", err)
	}
}

// TestLoadRISC0_RejectsTamperedVK proves the fingerprint check actually
// blocks a hand-crafted VK. We swap two IC points in the JSON and expect
// LoadRISC0InnerSetup to refuse.
func TestLoadRISC0_RejectsTamperedVK(t *testing.T) {
	canonical := vkPathForTest(t)
	tampered := writeTamperedVK(t, canonical)
	defer func() { _ = os.Remove(tampered) }()

	_, _, err := LoadRISC0InnerSetup(tampered, RISC0SetupOptions{})
	if err == nil {
		t.Fatal("expected fingerprint mismatch on tampered VK, got nil")
	}
	if !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("error should mention 'fingerprint mismatch'; got: %v", err)
	}
}

// TestLoadRISC0_AcceptVKFingerprintOverride proves the explicit-override
// path: when the user passes --inner-vk-fingerprint with the correct value
// for their non-canonical VK, the load proceeds.
func TestLoadRISC0_AcceptVKFingerprintOverride(t *testing.T) {
	canonical := vkPathForTest(t)
	tampered := writeTamperedVK(t, canonical)
	defer func() { _ = os.Remove(tampered) }()

	// Compute the actual fingerprint of the tampered file.
	// We can't reach for the parser here (would be a cycle); cheat by going
	// through the public LoadRISC0InnerSetup path with skip-check first to
	// get the VK, then FingerprintVK.
	_, vk, err := LoadRISC0InnerSetup(tampered, RISC0SetupOptions{SkipVKFingerprintCheck: true})
	if err != nil {
		t.Fatalf("skip-check load: %v", err)
	}
	fp, err := FingerprintVK(vk)
	if err != nil {
		t.Fatalf("FingerprintVK: %v", err)
	}

	// Now load with the explicit accept-fingerprint set to the tampered value.
	_, _, err = LoadRISC0InnerSetup(tampered, RISC0SetupOptions{AcceptVKFingerprint: fp})
	if err != nil {
		t.Fatalf("explicit-accept load should succeed; got: %v", err)
	}
}

// TestLoadRISC0_InsecureSkipDisablesCheck proves --insecure-no-vk-check
// disables the check entirely.
func TestLoadRISC0_InsecureSkipDisablesCheck(t *testing.T) {
	canonical := vkPathForTest(t)
	tampered := writeTamperedVK(t, canonical)
	defer func() { _ = os.Remove(tampered) }()

	_, _, err := LoadRISC0InnerSetup(tampered, RISC0SetupOptions{SkipVKFingerprintCheck: true})
	if err != nil {
		t.Fatalf("skip-check load should succeed; got: %v", err)
	}
}

// writeTamperedVK reads a canonical snarkjs VK JSON and writes a tampered
// copy with two IC points swapped (so the curve check still passes but the
// VK is structurally different). Returns the path to the temp file.
func writeTamperedVK(t *testing.T, canonicalPath string) string {
	t.Helper()
	data, err := os.ReadFile(canonicalPath)
	if err != nil {
		t.Fatalf("read canonical: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	ic, ok := doc["IC"].([]any)
	if !ok || len(ic) < 3 {
		t.Fatalf("VK has unexpected IC shape")
	}
	// Swap IC[1] and IC[2]: both still on-curve, but the VK fingerprint
	// changes.
	ic[1], ic[2] = ic[2], ic[1]
	doc["IC"] = ic

	f, err := os.CreateTemp("", "vk-tampered-*.json")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close temp: %v", err)
	}
	return f.Name()
}
