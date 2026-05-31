package cardano_ref

import "testing"

// TestBoundAlloc unit-tests the allocation guard directly.
func TestBoundAlloc(t *testing.T) {
	if err := boundAlloc(0xFFFFFFFF, 48, 100, "x"); err == nil {
		t.Fatal("a hostile count must be rejected")
	}
	if err := boundAlloc(2, 48, 96, "x"); err != nil { // 2*48 == 96 fits
		t.Fatalf("count that exactly fits must pass: %v", err)
	}
	if err := boundAlloc(3, 48, 96, "x"); err == nil { // 3*48 > 96
		t.Fatal("count exceeding remaining bytes must be rejected")
	}
}

// TestParsePublicRejectsOverflowCounts feeds the n_inner_pub × n_limbs overflow
// case (both 0xFFFFFFFF) — must error, never OOM/panic on a giant allocation.
func TestParsePublicRejectsOverflowCounts(t *testing.T) {
	data := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff} // n_inner_pub, n_limbs
	if _, err := ParsePublic(data); err == nil {
		t.Fatal("ParsePublic must reject overflowing counts")
	}
}

// The byte parsers take attacker-influenceable input (the Cardano *.bin files,
// and cardano_ref is the on-chain verifier's reference). They must never panic.
func FuzzParseVK(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 48+96+96+96+4))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = ParseVK(data) })
}

func FuzzParseProof(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 48+96+48+4))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = ParseProof(data) })
}

func FuzzParsePublic(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 5, 0, 0, 0, 4})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = ParsePublic(data) })
}
