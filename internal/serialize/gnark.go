// Package serialize centralizes gnark binary I/O. All gnark-native types
// (pk, vk, proof, ccs, witness) go through their own WriteTo/ReadFrom —
// never a hand-rolled JSON or text format.
package serialize

import (
	"fmt"
	"io"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

// writeToFile writes via io.WriterTo to a file path, creating parent dirs.
func writeToFile(path string, w io.WriterTo) (n int64, err error) {
	if err = os.MkdirAll(parentDir(path), 0o750); err != nil {
		return 0, fmt.Errorf("mkdir %q: %w", parentDir(path), err)
	}
	f, err := os.Create(path)
	if err != nil {
		return 0, fmt.Errorf("create %q: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	n, err = w.WriteTo(f)
	if err != nil {
		return n, fmt.Errorf("write %q: %w", path, err)
	}
	return n, nil
}

// readFromFile reads via io.ReaderFrom from a file path.
func readFromFile(path string, r io.ReaderFrom) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	n, err := r.ReadFrom(f)
	if err != nil {
		return n, fmt.Errorf("read %q: %w", path, err)
	}
	return n, nil
}

func parentDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}

// WriteCCS writes a compiled constraint system to disk.
func WriteCCS(path string, ccs constraint.ConstraintSystem) error {
	_, err := writeToFile(path, ccs)
	return err
}

// ReadCCS loads a compiled constraint system from disk for the given curve.
// gnark's groth16 backend is R1CS-only, so we always allocate via NewCS.
func ReadCCS(path string, curve ecc.ID) (constraint.ConstraintSystem, error) {
	cs := groth16.NewCS(curve)
	if _, err := readFromFile(path, cs); err != nil {
		return nil, err
	}
	return cs, nil
}

// WritePK writes a Groth16 proving key.
func WritePK(path string, pk groth16.ProvingKey) error {
	_, err := writeToFile(path, pk)
	return err
}

// ReadPK loads a Groth16 proving key for the given curve.
func ReadPK(path string, curve ecc.ID) (groth16.ProvingKey, error) {
	pk := groth16.NewProvingKey(curve)
	if _, err := readFromFile(path, pk); err != nil {
		return nil, err
	}
	return pk, nil
}

// WriteVK writes a Groth16 verifying key.
func WriteVK(path string, vk groth16.VerifyingKey) error {
	_, err := writeToFile(path, vk)
	return err
}

// ReadVK loads a Groth16 verifying key for the given curve.
func ReadVK(path string, curve ecc.ID) (groth16.VerifyingKey, error) {
	vk := groth16.NewVerifyingKey(curve)
	if _, err := readFromFile(path, vk); err != nil {
		return nil, err
	}
	return vk, nil
}

// WriteProof writes a Groth16 proof.
func WriteProof(path string, p groth16.Proof) (int64, error) {
	return writeToFile(path, p)
}

// ReadProof loads a Groth16 proof for the given curve.
func ReadProof(path string, curve ecc.ID) (groth16.Proof, error) {
	p := groth16.NewProof(curve)
	if _, err := readFromFile(path, p); err != nil {
		return nil, err
	}
	return p, nil
}

// WriteWitness writes a gnark witness (typically the public-only slice).
func WriteWitness(path string, w witness.Witness) error {
	_, err := writeToFile(path, w)
	return err
}

// ReadWitness loads a gnark witness for the given field.
func ReadWitness(path string, curve ecc.ID) (witness.Witness, error) {
	w, err := witness.New(curve.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("new witness: %w", err)
	}
	if _, err := readFromFile(path, w); err != nil {
		return nil, err
	}
	return w, nil
}
