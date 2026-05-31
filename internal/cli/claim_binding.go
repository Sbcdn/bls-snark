package cli

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/witness"
)

// This file implements the optional `prove --expect-*` pins: an operator can
// assert that the inner proof being wrapped commits to specific risc0 values
// (claim_digest = a specific execution; control_root / bn254_control_id = a
// specific risc0 platform release). The wrap is refused if the bound public
// inputs don't match, before the outer proof is built. The on-chain validator
// is the load-bearing binding; these pins are an operator-side safeguard. The
// split and derivation mirror tools/risc0-dump exactly (only byte reversal and
// field reduction), so the two stay in step.

// parseDigestHex decodes a 64-char hex digest (optional 0x prefix, case
// insensitive) into 32 raw bytes in risc0 `as_bytes()` order.
func parseDigestHex(s string) ([]byte, error) {
	n := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(s, "0X"), "0x"))
	b, err := hex.DecodeString(n)
	if err != nil {
		return nil, fmt.Errorf("not valid hex: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("must be 32 bytes (64 hex chars), got %d", len(b))
	}
	return b, nil
}

// splitDigestHalves reproduces tools/risc0-dump split_digest: reverse the
// 32-byte digest (as_bytes order) to big-endian, split into high‖low 16-byte
// halves, reduce each mod the BN254 scalar field. Returns (low, high) matching
// public-input pairs control_root→[0],[1] and claim_digest→[2],[3].
func splitDigestHalves(asBytes []byte) (low, high *big.Int) {
	be := make([]byte, len(asBytes))
	for i := range asBytes {
		be[i] = asBytes[len(asBytes)-1-i]
	}
	mid := len(be) / 2
	high = new(big.Int).SetBytes(be[:mid])
	low = new(big.Int).SetBytes(be[mid:])
	r := fr.Modulus()
	return low.Mod(low, r), high.Mod(high, r)
}

// bn254IDToFr reproduces the dumper's bn254_control_id_fr derivation:
// from_be_bytes_mod_order(reverse(id.as_bytes())). Matches public input [4].
func bn254IDToFr(asBytes []byte) *big.Int {
	be := make([]byte, len(asBytes))
	for i := range asBytes {
		be[i] = asBytes[len(asBytes)-1-i]
	}
	v := new(big.Int).SetBytes(be)
	return v.Mod(v, fr.Modulus())
}

// innerPublicScalars returns the BN254 public-input scalars as big.Ints.
func innerPublicScalars(innerPub witness.Witness) ([]*big.Int, error) {
	vec, ok := innerPub.Vector().(fr.Vector)
	if !ok {
		return nil, fmt.Errorf("inner public witness is not a BN254 vector (%T)", innerPub.Vector())
	}
	out := make([]*big.Int, len(vec))
	for i := range vec {
		out[i] = new(big.Int)
		vec[i].BigInt(out[i])
	}
	return out, nil
}

// verifyExpectedClaimBindings checks the operator's --expect-* pins against the
// inner public-input scalars. Empty args are skipped. Returns an error on the
// first mismatch (or malformed hex). risc0 public-input order:
// [control_root_low, control_root_high, claim_digest_low, claim_digest_high, bn254_control_id_fr].
func verifyExpectedClaimBindings(innerPub witness.Witness, expectClaimDigest, expectControlRoot, expectBN254ID string) error {
	if expectClaimDigest == "" && expectControlRoot == "" && expectBN254ID == "" {
		return nil
	}
	scalars, err := innerPublicScalars(innerPub)
	if err != nil {
		return err
	}
	if len(scalars) < 5 {
		return fmt.Errorf("--expect-* pins need 5 risc0 public inputs, got %d — is this a risc0 inner proof?", len(scalars))
	}

	pair := func(flag, hexStr, label string, idxLow, idxHigh int) error {
		b, err := parseDigestHex(hexStr)
		if err != nil {
			return fmt.Errorf("%s: %w", flag, err)
		}
		wantLow, wantHigh := splitDigestHalves(b)
		if scalars[idxLow].Cmp(wantLow) != 0 || scalars[idxHigh].Cmp(wantHigh) != 0 {
			return fmt.Errorf(
				"%s mismatch: proof commits to (low=%s, high=%s) but %s=%s splits to (low=%s, high=%s)",
				label, scalars[idxLow], scalars[idxHigh], flag, hexStr, wantLow, wantHigh)
		}
		return nil
	}

	if expectClaimDigest != "" {
		if err := pair("--expect-claim-digest", expectClaimDigest, "claim_digest", 2, 3); err != nil {
			return err
		}
	}
	if expectControlRoot != "" {
		if err := pair("--expect-control-root", expectControlRoot, "control_root", 0, 1); err != nil {
			return err
		}
	}
	if expectBN254ID != "" {
		b, err := parseDigestHex(expectBN254ID)
		if err != nil {
			return fmt.Errorf("--expect-bn254-control-id: %w", err)
		}
		want := bn254IDToFr(b)
		if scalars[4].Cmp(want) != 0 {
			return fmt.Errorf("bn254_control_id mismatch: proof commits to %s but --expect-bn254-control-id=%s derives %s",
				scalars[4], expectBN254ID, want)
		}
	}
	return nil
}
