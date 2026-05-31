package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadRISC0ParamsV1AndV2(t *testing.T) {
	const img = "50fca3d8ac3768a385ed9b56d48a2fa194496d5a25e8331151a8279ecf7a791b"
	const root = "a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56"
	const claim = "3a01ada1d6df0f884426559b9902b1c03a9a348a58397e11c7e45470fadd1b11"

	v1 := `{"version":"1","image_id":"` + img + `","control_root":"` + root + `","bn254_control_id_fr":"123"}`
	v2 := `{"version":"2","image_id":"` + img + `","control_root":"` + root + `","bn254_control_id_fr":"123","claim_digest":"` + claim + `"}`

	t.Run("v1 parses, no claim_digest", func(t *testing.T) {
		p, err := readRISC0Params(writeTemp(t, "v1.json", v1))
		if err != nil {
			t.Fatalf("v1: %v", err)
		}
		if p.ClaimDigest != "" {
			t.Fatalf("v1 should have empty claim_digest, got %q", p.ClaimDigest)
		}
	})

	t.Run("v2 parses with claim_digest", func(t *testing.T) {
		p, err := readRISC0Params(writeTemp(t, "v2.json", v2))
		if err != nil {
			t.Fatalf("v2: %v", err)
		}
		if p.ClaimDigest != claim {
			t.Fatalf("v2 claim_digest = %q, want %q", p.ClaimDigest, claim)
		}
	})

	for _, tc := range []struct{ name, json, wantSub string }{
		{"unsupported version", `{"version":"3","image_id":"` + img + `","control_root":"` + root + `","bn254_control_id_fr":"123"}`, "unsupported"},
		{"v2 missing claim_digest", `{"version":"2","image_id":"` + img + `","control_root":"` + root + `","bn254_control_id_fr":"123"}`, "claim_digest"},
		{"v2 bad claim_digest", `{"version":"2","image_id":"` + img + `","control_root":"` + root + `","bn254_control_id_fr":"123","claim_digest":"beef"}`, "claim_digest"},
		{"unknown field rejected", `{"version":"2","image_id":"` + img + `","control_root":"` + root + `","bn254_control_id_fr":"123","claim_digest":"` + claim + `","extra":1}`, "parse"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readRISC0Params(writeTemp(t, "p.json", tc.json))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q lacks %q", err.Error(), tc.wantSub)
			}
		})
	}
}
