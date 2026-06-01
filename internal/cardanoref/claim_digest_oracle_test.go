package cardanoref

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

// This file is the canonical, runnable oracle for the on-chain `claim_digest`
// reproduction. A downstream verifier
// (Aiken/Plutus, or any re-implementer) recomputes risc0's
// `ReceiptClaim::digest` from the journal + the hardcoded image_id, splits it,
// and checks the halves against the proof's public-input limbs 8–15. This test
// reproduces that derivation in Go and asserts it byte-for-byte against the real
// committed Mainnet fixtures. Run with `-v` to print every intermediate to diff
// against your implementation:
//
//	go test ./internal/cardanoref/ -v -run ClaimDigestOracle

// taggedStruct reproduces risc0-binfmt's tagged_struct (hash.rs):
//
//	sha256( sha256(tag) ‖ down[0] ‖ … ‖ word_le_u32… ‖ u16_le(len(down)) )
//
// Note the trailing count is len(down) (the digest count), NOT len(words).
func taggedStruct(tag string, down [][]byte, words []uint32) []byte {
	tagDigest := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(tagDigest[:])
	for _, d := range down {
		h.Write(d)
	}
	for _, w := range words {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], w)
		h.Write(b[:])
	}
	var c [2]byte
	binary.LittleEndian.PutUint16(c[:], uint16(len(down)))
	h.Write(c[:])
	return h.Sum(nil)
}

func sha256sum(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

// reproduceClaimDigest computes risc0 `ReceiptClaim::ok(image_id, journal).digest()`
// — the on-chain reproduction. Only `sha256(journal)` is per-journal; every other
// input is constant (post={pc:0,root:0}, Halted(0), no input, empty assumptions).
func reproduceClaimDigest(imageID, journal []byte) (claim, journalD, postD, outputD []byte) {
	zero := make([]byte, 32)
	journalD = sha256sum(journal)
	postD = taggedStruct("risc0.SystemState", [][]byte{zero}, []uint32{0}) // {pc:0, merkle_root:ZERO}
	outputD = taggedStruct("risc0.Output", [][]byte{journalD, zero}, nil)  // assumptions.digest = ZERO
	claim = taggedStruct("risc0.ReceiptClaim",
		[][]byte{zero, imageID, postD, outputD}, // input, pre(=image_id), post, output
		[]uint32{0, 0})                          // sys_exit, user_exit (Halted(0))
	return
}

// splitDigestHalves reproduces tools/risc0-dump split_digest: reverse the 32-byte
// digest (as_bytes order) to big-endian, split into high‖low 16-byte halves;
// low = least-significant half. Returns (low, high).
func splitDigestHalves(d []byte) (low, high *big.Int) {
	be := make([]byte, len(d))
	for i := range d {
		be[i] = d[len(d)-1-i]
	}
	high = new(big.Int).SetBytes(be[:16])
	low = new(big.Int).SetBytes(be[16:])
	return low, high
}

// TestClaimDigestOracle proves the claim_digest reproduction is exact:
// for each committed fixture, derive claim_digest from (image_id, journal), split
// it, and require the halves equal the snarkjs public inputs [2],[3]. Also asserts
// the fixture-independent constants (tag digests, post_digest) are identical across
// fixtures — those are the values a validator hardcodes.
func TestClaimDigestOracle(t *testing.T) {
	dirs := []string{
		filepath.Join("..", "..", "testdata", "risc0"),
		filepath.Join("..", "..", "testdata", "risc0", "alt"),
	}
	var firstPost, firstImage []byte
	for _, dir := range dirs {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			journalPath := filepath.Join(dir, "journal.bin")
			paramsPath := filepath.Join(dir, "risc0_params.json")
			publicPath := filepath.Join(dir, "public.json")
			for _, p := range []string{journalPath, paramsPath, publicPath} {
				if _, err := os.Stat(p); err != nil {
					t.Skipf("fixture missing (%s) — run tools/risc0-dump", p)
				}
			}

			journal := mustRead(t, journalPath)
			var params struct {
				ImageID string `json:"image_id"`
			}
			if err := json.Unmarshal(mustRead(t, paramsPath), &params); err != nil {
				t.Fatalf("parse risc0_params.json: %v", err)
			}
			imageID, err := hex.DecodeString(params.ImageID)
			if err != nil || len(imageID) != 32 {
				t.Fatalf("image_id not 32-byte hex: %q", params.ImageID)
			}
			pubs := parseSnarkjsPublic(t, publicPath)
			if len(pubs) < 4 {
				t.Fatalf("public.json has %d scalars, need ≥4", len(pubs))
			}

			claim, journalD, postD, outputD := reproduceClaimDigest(imageID, journal)

			t.Logf("---- claim_digest reproduction intermediates (diff your impl against these) ----")
			t.Logf("image_id (pre.digest)     = %x", imageID)
			t.Logf("sha256(\"risc0.SystemState\") = %x", sha256.Sum256([]byte("risc0.SystemState")))
			t.Logf("sha256(\"risc0.Output\")      = %x", sha256.Sum256([]byte("risc0.Output")))
			t.Logf("sha256(\"risc0.ReceiptClaim\")= %x", sha256.Sum256([]byte("risc0.ReceiptClaim")))
			t.Logf("post_digest (constant)    = %x", postD)
			t.Logf("journal_digest            = %x", journalD)
			t.Logf("output_digest             = %x", outputD)
			t.Logf("claim_digest              = %x", claim)

			low, high := splitDigestHalves(claim)
			wantLow, ok1 := new(big.Int).SetString(pubs[2], 10)
			wantHigh, ok2 := new(big.Int).SetString(pubs[3], 10)
			if !ok1 || !ok2 {
				t.Fatalf("public.json[2..3] not decimal: %q %q", pubs[2], pubs[3])
			}
			if low.Cmp(wantLow) != 0 || high.Cmp(wantHigh) != 0 {
				t.Fatalf("claim_digest split mismatch:\n  got  low=%s high=%s\n  want low=%s high=%s",
					low, high, wantLow, wantHigh)
			}
			t.Logf("OK: claim_digest splits to public.json[2],[3] (claim_digest_low/high)")

			// Cross-fixture: post_digest is constant; image_id is the same launch guest.
			if firstPost == nil {
				firstPost, firstImage = postD, imageID
			} else {
				if string(postD) != string(firstPost) {
					t.Errorf("post_digest differs across fixtures — should be constant")
				}
				if string(imageID) != string(firstImage) {
					t.Errorf("image_id differs across fixtures (%x vs %x)", imageID, firstImage)
				}
			}
		})
	}
}
