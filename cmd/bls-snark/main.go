// Command bls-snark wraps a Groth16-BN254 proof into a Groth16-BLS12-381
// proof that Cardano L1 can verify natively via its BLS12-381 builtins.
package main

import (
	"fmt"
	"os"

	"github.com/sbcdn/bls-snark/internal/cli"
)

func main() {
	if err := cli.NewRoot().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
