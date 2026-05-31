package logging

import (
	"testing"

	"github.com/rs/zerolog"
)

// TestNewLevelFromEnv pins the BLS_SNARK_LOG → level mapping (and the default).
func TestNewLevelFromEnv(t *testing.T) {
	for _, tc := range []struct {
		env  string
		want zerolog.Level
	}{
		{"", zerolog.InfoLevel},
		{"debug", zerolog.DebugLevel},
		{"warn", zerolog.WarnLevel},
		{"error", zerolog.ErrorLevel},
		{"bogus", zerolog.InfoLevel}, // unknown → default info
	} {
		t.Run("BLS_SNARK_LOG="+tc.env, func(t *testing.T) {
			if tc.env == "" {
				t.Setenv("BLS_SNARK_LOG", "") // ensure unset/empty
			} else {
				t.Setenv("BLS_SNARK_LOG", tc.env)
			}
			if got := New().GetLevel(); got != tc.want {
				t.Fatalf("level = %v, want %v", got, tc.want)
			}
		})
	}
}
