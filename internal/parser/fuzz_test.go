package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFuzzFile(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f.json")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func seedFrom(f *testing.F, rel string) {
	if b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "risc0", rel)); err == nil {
		f.Add(b)
	}
}

// The snarkjs parsers consume untrusted JSON (risc0-dump output, or any caller's
// triple). They must reject malformed input gracefully — never panic.
func FuzzParseVerifyingKey(f *testing.F) {
	seedFrom(f, "verification_key.json")
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"protocol":"groth16","curve":"bn254","IC":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = ParseVerifyingKey(writeFuzzFile(t, data)) })
}

func FuzzParseProof(f *testing.F) {
	seedFrom(f, "proof.json")
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"pi_a":["1","2","1"],"pi_b":[["1","2"],["3","4"],["1","0"]],"pi_c":["5","6","1"]}`))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = ParseProof(writeFuzzFile(t, data)) })
}

func FuzzParsePublicInputs(f *testing.F) {
	seedFrom(f, "public.json")
	f.Add([]byte(`[]`))
	f.Add([]byte(`["1","2","3"]`))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = ParsePublicInputs(writeFuzzFile(t, data)) })
}
