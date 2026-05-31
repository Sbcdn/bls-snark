// Package cli implements the bls-snark subcommands: setup, prove, verify, export.
package cli

import (
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/sbcdn/bls-snark/internal/logging"
)

// version is set at build time via -ldflags='-X ...Version=...'. Default is "dev".
var version = "dev"

// NewRoot returns the configured cobra root command, with all subcommands
// attached. main.go calls this and Execute()s it.
func NewRoot() *cobra.Command {
	log := logging.New()

	root := &cobra.Command{
		Use:           "bls-snark",
		Short:         "Wrap a Groth16-BN254 proof into a Groth16-BLS12-381 proof verifiable on Cardano L1.",
		Version:       version,
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	root.AddCommand(newSetupCmd(log))
	root.AddCommand(newProveCmd(log))
	root.AddCommand(newVerifyCmd(log))
	root.AddCommand(newExportCmd(log))

	return root
}

// emitJSON prints a single JSON object to stdout. Logs go to stderr (zerolog);
// machine-readable per-command results go to stdout.
func emitJSON(log zerolog.Logger, v any) {
	if err := encodeJSON(v); err != nil {
		log.Error().Err(err).Msg("failed to encode stdout JSON")
	}
}
