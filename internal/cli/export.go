package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	groth16_bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/sbcdn/bls-snark/internal/serialize"
)

type exportResult struct {
	VKPath           string `json:"vk_path,omitempty"`
	VKBytes          int64  `json:"vk_bytes,omitempty"`
	ProofPath        string `json:"proof_path,omitempty"`
	ProofBytes       int64  `json:"proof_bytes,omitempty"`
	PublicPath       string `json:"public_path,omitempty"`
	PublicBytes      int64  `json:"public_bytes,omitempty"`
	JournalPath      string `json:"journal_path,omitempty"`
	JournalBytes     int64  `json:"journal_bytes,omitempty"`
	RISC0ParamsPath  string `json:"risc0_params_path,omitempty"`
	RISC0ParamsBytes int64  `json:"risc0_params_bytes,omitempty"`
	NInnerPub        uint32 `json:"n_inner_pub,omitempty"`
	NLimbsPerScalar  uint32 `json:"n_limbs_per_scalar,omitempty"`
	NCommitments     uint32 `json:"n_commitments"`    // Pedersen commitments in proof.bin / vk.bin (v2). Required field — explicit zero matters.
	Format           string `json:"format,omitempty"` // "cardano-minimal-v2"
}

func newExportCmd(log zerolog.Logger) *cobra.Command {
	var (
		flagVK          string
		flagProof       string
		flagPublic      string
		flagJournal     string
		flagRISC0Params string
		flagOutDir      string
		flagNInnerPub   uint32
		flagNLimbs      uint32
	)
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Re-serialize outer VK / proof / public-witness into Cardano-friendly bytes (v2).",
		Long: `Writes Cardano-minimal v2 byte files for the BLS12-381 builtins:
  vk.bin       alpha_g1 || beta_g2 || gamma_g2 || delta_g2 || uint32(ic_count) || ic[]
                                                           || uint32(nC) || (pedersen_G, pedersen_GSigmaNeg) × nC
  proof.bin    a_g1 || b_g2 || c_g1 || uint32(nC) || commitment_g1 × nC || commitment_pok_g1
  public.bin   uint32(n_inner_pub) || uint32(n_limbs_per_scalar) || limb_values...

v2 carries the Pedersen commitment fields the on-chain verifier needs to
reproduce gnark's full verification equation.

By default n_inner_pub is inferred from the outer VK as (ic_count - 1 - nC)
/ n_limbs_per_scalar. n_limbs_per_scalar defaults to 4 (BN254-in-BLS12-381).
Override with --n-inner-pub / --n-limbs if you compiled with a non-default
emulation setup.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := rejectTraversal(flagOutDir); err != nil {
				return err
			}
			if err := ensureDir(filepath.Join(flagOutDir, ".keep")); err != nil {
				return fmt.Errorf("prepare --out-dir: %w", err)
			}

			var (
				vk        *groth16_bls12381.VerifyingKey
				res       exportResult
				nInnerPub = flagNInnerPub
				nLimbs    = flagNLimbs
			)
			if nLimbs == 0 {
				// gnark's emulated BN254 scalar uses 4 × 64-bit limbs by default.
				nLimbs = 4
			}

			if flagVK != "" {
				log.Info().Str("vk", flagVK).Msg("loading outer VK")
				raw, err := serialize.ReadVK(flagVK, ecc.BLS12_381)
				if err != nil {
					return err
				}
				v, ok := raw.(*groth16_bls12381.VerifyingKey)
				if !ok {
					return fmt.Errorf("outer VK is not a BLS12-381 verifying key (%T)", raw)
				}
				vk = v

				outPath := filepath.Join(flagOutDir, "vk.bin")
				n, err := serialize.WriteCardanoVK(outPath, vk)
				if err != nil {
					return err
				}
				res.VKPath, res.VKBytes = outPath, n
				res.NCommitments = uint32(len(vk.CommitmentKeys))
				// The Cardano contract and reference verifier only support a single
				// bsb22 commitment (nC == 1). A VK with a different count would
				// serialise to a vk.bin the on-chain verifier silently can't handle.
				if res.NCommitments != 1 {
					return fmt.Errorf("outer VK has %d commitment keys; the Cardano export requires exactly 1", res.NCommitments)
				}
				log.Info().Str("path", outPath).Int64("bytes", n).Uint32("n_commitments", res.NCommitments).Msg("wrote Cardano vk.bin (v2)")

				if nInnerPub == 0 {
					// ic_count - 1 = nbPublicWires_outer + nbCommitments.
					// nbPublicWires_outer = nInnerPub × nLimbs.
					outerPub := uint32(len(vk.G1.K)) - 1 - res.NCommitments
					if outerPub%nLimbs != 0 {
						return fmt.Errorf("cannot infer n_inner_pub from VK: outer public-wires=%d not divisible by n_limbs=%d (specify --n-inner-pub)", outerPub, nLimbs)
					}
					nInnerPub = outerPub / nLimbs
				}
			}

			if flagProof != "" {
				log.Info().Str("proof", flagProof).Msg("loading outer proof")
				raw, err := serialize.ReadProof(flagProof, ecc.BLS12_381)
				if err != nil {
					return err
				}
				p, ok := raw.(*groth16_bls12381.Proof)
				if !ok {
					return fmt.Errorf("outer proof is not a BLS12-381 proof (%T)", raw)
				}
				// Cross-check the commitment count against the VK if both are supplied:
				// the on-chain verifier expects them to agree.
				if vk != nil && len(p.Commitments) != len(vk.CommitmentKeys) {
					return fmt.Errorf("proof has %d commitments but VK has %d commitment keys", len(p.Commitments), len(vk.CommitmentKeys))
				}
				outPath := filepath.Join(flagOutDir, "proof.bin")
				n, err := serialize.WriteCardanoProof(outPath, p)
				if err != nil {
					return err
				}
				res.ProofPath, res.ProofBytes = outPath, n
				if vk == nil {
					res.NCommitments = uint32(len(p.Commitments))
				}
				log.Info().Str("path", outPath).Int64("bytes", n).Uint32("n_commitments", uint32(len(p.Commitments))).Msg("wrote Cardano proof.bin (v2)")
			}

			if flagPublic != "" {
				if nInnerPub == 0 {
					return fmt.Errorf("--n-inner-pub required when exporting public.bin without --vk")
				}
				outPath := filepath.Join(flagOutDir, "public.bin")
				n, err := serialize.WriteCardanoPublic(outPath, flagPublic, nInnerPub, nLimbs)
				if err != nil {
					return err
				}
				res.PublicPath, res.PublicBytes = outPath, n
				res.NInnerPub = nInnerPub
				res.NLimbsPerScalar = nLimbs
				log.Info().
					Str("path", outPath).
					Int64("bytes", n).
					Uint32("n_inner_pub", nInnerPub).
					Uint32("n_limbs", nLimbs).
					Msg("wrote Cardano public.bin")
			}

			if flagJournal != "" {
				outPath := filepath.Join(flagOutDir, "journal.bin")
				n, err := copyFile(flagJournal, outPath, 100<<20) // journals are tiny; 100 MB is a generous DoS cap
				if err != nil {
					return fmt.Errorf("copy journal: %w", err)
				}
				res.JournalPath, res.JournalBytes = outPath, n
				log.Info().Str("path", outPath).Int64("bytes", n).Msg("copied journal to Cardano output")
			}

			if flagRISC0Params != "" {
				outPath := filepath.Join(flagOutDir, "risc0_params.json")
				n, err := copyFile(flagRISC0Params, outPath, 1<<20) // sidecar is < 1 KB; 1 MB cap
				if err != nil {
					return fmt.Errorf("copy risc0_params: %w", err)
				}
				res.RISC0ParamsPath, res.RISC0ParamsBytes = outPath, n
				log.Info().Str("path", outPath).Int64("bytes", n).Msg("copied risc0 params sidecar")
			}

			res.Format = "cardano-minimal-v2"
			emitJSON(log, res)
			return nil
		},
	}
	cmd.Flags().StringVar(&flagVK, "vk", "./out/outer_vk.bin", "outer verifying key path")
	cmd.Flags().StringVar(&flagProof, "proof", "./out/outer_proof.bin", "outer proof path")
	cmd.Flags().StringVar(&flagPublic, "public", "./out/outer_public.bin", "outer public-witness binary path")
	cmd.Flags().StringVar(&flagJournal, "journal", "", "path to journal.bin (from tools/risc0-dump) to copy into Cardano output. The outer proof commits to claim_digest only; the downstream verifier needs the journal to recompute it and confirm the claim.")
	cmd.Flags().StringVar(&flagRISC0Params, "risc0-params", "", "path to risc0_params.json (from tools/risc0-dump) to copy into Cardano output. Sidecar carrying image_id, control_root, bn254_control_id_fr; consumed by downstream verifier scripts to bake the canonical constants.")
	cmd.Flags().StringVar(&flagOutDir, "out-dir", "./out/cardano/", "Cardano output directory")
	cmd.Flags().Uint32Var(&flagNInnerPub, "n-inner-pub", 0, "count of inner-circuit public scalars (default: ic_count-1 from outer VK)")
	cmd.Flags().Uint32Var(&flagNLimbs, "n-limbs", 0, "limbs per inner scalar (default: 4 for BN254)")
	return cmd
}

// rejectTraversal refuses an --out-dir containing a ".." segment. The threat
// model is local-CLI (operator-attacks-self is out of scope), but a CI/pipeline
// script that takes out_dir from an external parameter would otherwise have a
// path-stomping primitive. Defence-in-depth.
func rejectTraversal(dir string) error {
	for _, seg := range strings.Split(filepath.Clean(dir), string(filepath.Separator)) {
		if seg == ".." {
			return fmt.Errorf("--out-dir %q contains a '..' segment (path traversal)", dir)
		}
	}
	return nil
}

// copyFile copies src to dst and returns the number of bytes written. It
// refuses inputs larger than maxBytes (a hostile/huge --journal or
// --risc0-params would otherwise exhaust disk/memory).
func copyFile(src, dst string, maxBytes int64) (n int64, err error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, fmt.Errorf("open %q: %w", src, err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.Create(dst)
	if err != nil {
		return 0, fmt.Errorf("create %q: %w", dst, err)
	}
	defer func() {
		if cerr := out.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	// LimitReader to maxBytes+1 so an over-cap file is detected, not silently truncated.
	n, err = io.Copy(out, io.LimitReader(in, maxBytes+1))
	if err != nil {
		return n, err
	}
	if n > maxBytes {
		return n, fmt.Errorf("%q exceeds the %d-byte cap", src, maxBytes)
	}
	return n, nil
}
