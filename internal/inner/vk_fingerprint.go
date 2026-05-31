package inner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/consensys/gnark/backend/groth16"
)

// CanonicalRISC0VKFingerprint is the SHA-256 hex digest of the canonical
// RISC0 BN254 Groth16 verifying key as written by gnark's
// `groth16_bn254.VerifyingKey.WriteTo` (binary, compressed-point form).
//
// The canonical VK is the one risc0 ships in `risc0_groth16::verifying_key()`
// — i.e. the post-ceremony BN254 Groth16 verifier from the risc0-ethereum
// repository (`contracts/src/groth16/Groth16Verifier.sol`). Decimal-string
// values for α, β, γ, δ, and IC[0..5] are baked into both the dumper
// (`tools/risc0-dump/src/main.rs::build_vk_json`) and risc0's own code.
//
// Update this constant ONLY when risc0 rotates its ceremony (i.e. issues a
// new Groth16Verifier.sol). Procedure:
//
//  1. Bump the pinned risc0 crates in tools/risc0-dump/Cargo.toml and re-build
//     the dumper.
//  2. Regenerate testdata/risc0/verification_key.json from the new dumper.
//  3. Run `go test ./internal/inner -run TestPrintCanonicalRISC0VKFingerprint -v`
//     to print the new fingerprint, then paste it here.
//  4. TestCanonicalFingerprintMatchesEmbeddedConst will go from failing to
//     passing — that's your signal the update is consistent.
//
// CLI overrides at setup time: --inner-vk-fingerprint <hex> to lock in a
// non-canonical VK; --insecure-no-vk-check to bypass entirely (dev only).
const CanonicalRISC0VKFingerprint = "80c0b797b1db763af8f9c96befb7c79a778fef16817a56778f54c5cf8074b1ab"

// FingerprintVK returns the SHA-256 hex digest of vk's gnark-native binary
// form. Use this to compare a parsed snarkjs verification_key.json against
// a known-good ceremony output. Whitespace-independent (we hash the binary,
// not the JSON).
func FingerprintVK(vk groth16.VerifyingKey) (string, error) {
	var buf bytes.Buffer
	if _, err := vk.WriteTo(&buf); err != nil {
		return "", fmt.Errorf("vk.WriteTo: %w", err)
	}
	h := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(h[:]), nil
}
