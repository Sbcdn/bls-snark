package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// innerSource enumerates the supported inner-proof origins:
// "cubic" (dev fixture, generated in-process) and "risc0" (snarkjs JSON
// triple, typically produced by tools/risc0-dump from a RISC0 receipt).
type innerSource string

const (
	innerCubic innerSource = "cubic"
	innerRISC0 innerSource = "risc0"
)

func parseInnerSource(s string) (innerSource, error) {
	switch innerSource(s) {
	case innerCubic, innerRISC0:
		return innerSource(s), nil
	default:
		return "", fmt.Errorf("--inner-source must be 'cubic' or 'risc0', got %q", s)
	}
}

// ensureDir creates the directory containing path if it doesn't exist.
func ensureDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		return nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("mkdir %q: %w", dir, err)
	}
	return nil
}

// fileSize returns the size of the file at path in bytes.
func fileSize(path string) (int64, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("stat %q: %w", path, err)
	}
	return st.Size(), nil
}

// encodeJSON writes v as indented JSON to stdout.
func encodeJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
