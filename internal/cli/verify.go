package cli

import (
	"fmt"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/sbcdn/bls-snark/internal/serialize"
)

type verifyResult struct {
	Valid      bool    `json:"valid"`
	ElapsedSec float64 `json:"elapsed_seconds"`
}

func newVerifyCmd(log zerolog.Logger) *cobra.Command {
	var (
		flagVK     string
		flagProof  string
		flagPublic string
	)

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Native Go verification of an outer Groth16-BLS12-381 proof.",
		Long:  "Exit 0 on success, non-zero on failure. The native verify is a sanity check that the outer artifact is well-formed before Cardano sees it.",
		RunE: func(cmd *cobra.Command, args []string) error {
			start := time.Now()

			log.Info().Str("vk", flagVK).Msg("loading outer VK")
			vk, err := serialize.ReadVK(flagVK, ecc.BLS12_381)
			if err != nil {
				return err
			}
			log.Info().Str("proof", flagProof).Msg("loading outer proof")
			proof, err := serialize.ReadProof(flagProof, ecc.BLS12_381)
			if err != nil {
				return err
			}
			log.Info().Str("public", flagPublic).Msg("loading outer public witness")
			pub, err := serialize.ReadWitness(flagPublic, ecc.BLS12_381)
			if err != nil {
				return err
			}

			err = groth16.Verify(proof, vk, pub)
			elapsed := time.Since(start).Seconds()
			res := verifyResult{Valid: err == nil, ElapsedSec: elapsed}
			emitJSON(log, res)
			if err != nil {
				// emit JSON above first, then propagate as non-zero exit
				return fmt.Errorf("outer verify failed: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&flagVK, "vk", "./out/outer_vk.bin", "outer verifying key path")
	cmd.Flags().StringVar(&flagProof, "proof", "./out/outer_proof.bin", "outer proof path")
	cmd.Flags().StringVar(&flagPublic, "public", "./out/outer_public.bin", "outer public-witness binary path")
	return cmd
}
