package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

// canonicalRISC0VK is the committed throwaway risc0 dev VK whose fingerprint
// matches the embedded CanonicalRISC0VKFingerprint (the same file `make
// wrap-risc0` consumes).
func canonicalRISC0VK() string {
	return filepath.Join("..", "..", "testdata", "risc0", "verification_key.json")
}

// runSetupArgs executes the setup command with the given args and a silent
// logger, returning the RunE error. Output is discarded. Only exercises code
// paths that return BEFORE the (expensive) outer compile.
func runSetupArgs(t *testing.T, args ...string) error {
	t.Helper()
	cmd := newSetupCmd(zerolog.Nop())
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	return cmd.Execute()
}

// TestSetupFlagValidation locks the pre-compile guard rails: these must reject
// before any setup work happens, so a malformed invocation can't silently fall
// through to an insecure or inconsistent run.
func TestSetupFlagValidation(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantSub string
	}{
		{"pk without vk", []string{"--pk-input", "x.bin"}, "must be supplied together"},
		{"vk without pk", []string{"--vk-input", "x.bin"}, "must be supplied together"},
		{"bad inner-source", []string{"--inner-source", "bogus"}, "inner-source"},
		{"emit-ccs-only with passthrough", []string{"--emit-ccs-only", "--pk-input", "p.bin", "--vk-input", "v.bin"}, "incompatible"},
		{"single-party setup needs explicit opt-in", []string{"--inner-source", "cubic"}, "refusing"},
	}
	t.Setenv("BLS_SNARK_INSECURE_DEV_SETUP", "") // ensure the env opt-in isn't set
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := runSetupArgs(t, tc.args...)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// TestSetupSecurityFlagDefaults guards against an "accidentally always-on"
// regression: the VK-check opt-out must default OFF and the fingerprint
// override must default empty, so the code default is always "verify".
func TestSetupSecurityFlagDefaults(t *testing.T) {
	cmd := newSetupCmd(zerolog.Nop())
	if v, err := cmd.Flags().GetBool("insecure-no-vk-check"); err != nil || v {
		t.Fatalf("--insecure-no-vk-check default = %v (err %v); want false", v, err)
	}
	if v, err := cmd.Flags().GetString("inner-vk-fingerprint"); err != nil || v != "" {
		t.Fatalf("--inner-vk-fingerprint default = %q (err %v); want empty", v, err)
	}
}

// TestLoadOrGenerateInnerRISC0VKCheckWiring confirms the setup CLI's
// --insecure-no-vk-check / --inner-vk-fingerprint flags are actually threaded
// into the fingerprint gate: the default verifies, an override is
// honoured, and the skip flag takes precedence over a wrong override.
func TestLoadOrGenerateInnerRISC0VKCheckWiring(t *testing.T) {
	vkPath := canonicalRISC0VK()
	if _, err := os.Stat(vkPath); err != nil {
		t.Skipf("canonical risc0 VK testdata missing (%s)", vkPath)
	}
	const wrongFP = "0000000000000000000000000000000000000000000000000000000000000000"

	tests := []struct {
		name        string
		fingerprint string
		skip        bool
		wantErr     bool
	}{
		{"default verifies canonical VK", "", false, false},
		{"wrong override rejects", wrongFP, false, true},
		{"skip bypasses wrong override", wrongFP, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			_, _, err := loadOrGenerateInner(
				zerolog.Nop(), innerRISC0, vkPath,
				filepath.Join(dir, "inner_vk.bin"),
				filepath.Join(dir, "inner_pk.bin"),
				filepath.Join(dir, "inner.ccs"),
				tc.fingerprint, tc.skip,
			)
			if tc.wantErr && err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr && err != nil && !strings.Contains(err.Error(), "fingerprint mismatch") {
				t.Fatalf("expected a fingerprint-mismatch error, got: %v", err)
			}
		})
	}
}

// TestLoadOrGenerateInnerRISC0RequiresVK ensures risc0 mode without --inner-vk
// is rejected rather than silently producing an empty inner setup.
func TestLoadOrGenerateInnerRISC0RequiresVK(t *testing.T) {
	dir := t.TempDir()
	_, _, err := loadOrGenerateInner(
		zerolog.Nop(), innerRISC0, "",
		filepath.Join(dir, "inner_vk.bin"), "", "", "", false,
	)
	if err == nil {
		t.Fatal("expected error for risc0 source without --inner-vk")
	}
}
