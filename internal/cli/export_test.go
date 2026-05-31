package cli

import (
	"io"
	"testing"

	"github.com/rs/zerolog"
)

func TestRejectTraversal(t *testing.T) {
	for _, d := range []string{"../x", "out/../../etc", "a/../../b", "../../"} {
		if rejectTraversal(d) == nil {
			t.Errorf("%q should be rejected as path traversal", d)
		}
	}
	for _, d := range []string{"out/cardano", "./out", "/abs/path", "a/b/c", "out/../x"} {
		if err := rejectTraversal(d); err != nil {
			t.Errorf("%q should be allowed: %v", d, err)
		}
	}
}

// TestExportRejectsTraversalCLI covers the wiring: a `..` --out-dir fails fast.
func TestExportRejectsTraversalCLI(t *testing.T) {
	cmd := newExportCmd(zerolog.Nop())
	cmd.SetArgs([]string{"--out-dir", "../escape", "--vk", "", "--proof", "", "--public", ""})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected a path-traversal error for --out-dir ../escape")
	}
}
