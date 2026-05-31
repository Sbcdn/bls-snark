package cli

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/sbcdn/bls-snark/internal/circuit"
	"github.com/sbcdn/bls-snark/internal/inner"
	"github.com/sbcdn/bls-snark/internal/keycheck"
	"github.com/sbcdn/bls-snark/internal/serialize"
)

// setupResult is the stdout JSON shape for `setup`.
type setupResult struct {
	PKPath       string `json:"pk_path,omitempty"`
	VKPath       string `json:"vk_path,omitempty"`
	CCSPath      string `json:"ccs_path"`
	InnerVKPath  string `json:"inner_vk_path"`
	InnerPKPath  string `json:"inner_pk_path,omitempty"`
	InnerCCSPath string `json:"inner_ccs_path,omitempty"`
	// InnerVKFingerprint is the SHA-256 hex of the gnark-native binary
	// form of the inner VK that was baked into the compiled R1CS. Downstream
	// auditors can grep this from the JSON to confirm the wrap was built
	// against the expected inner VK without re-running setup.
	InnerVKFingerprint string  `json:"inner_vk_fingerprint,omitempty"`
	NConstraints       int     `json:"n_constraints"`
	ElapsedSec         float64 `json:"elapsed_seconds"`
	Mode               string  `json:"mode,omitempty"` // insecure-dev-setup | passthrough | emit-ccs-only
	Warning            string  `json:"warning,omitempty"`
}

func newSetupCmd(log zerolog.Logger) *cobra.Command {
	var (
		flagInnerSource        string
		flagInnerVK            string
		flagOutPK              string
		flagOutVK              string
		flagOutCCS             string
		flagOutInnerVK         string
		flagOutInnerPK         string
		flagOutInnerCCS        string
		flagInnerVKFingerprint string
		flagInsecureNoVKCheck  bool
		flagPKInput            string
		flagVKInput            string
		flagEmitCCSOnly        bool
		flagInsecureDevSetup   bool
	)

	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Compile the outer circuit and run a single-party (INSECURE) Groth16-BLS12-381 setup.",
		Long: `Compiles the outer circuit with the inner verifying key baked as a
compile-time constant, then runs a single-party Groth16 trusted setup over
BLS12-381. The proving key produced is toxic-waste-equivalent and must not
leave the build machine. For production, an MPC ceremony is required.

Examples:
  bls-snark setup --inner-source cubic
  bls-snark setup --inner-source risc0 --inner-vk testdata/risc0/verification_key.json
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			src, err := parseInnerSource(flagInnerSource)
			if err != nil {
				return err
			}
			if (flagPKInput == "") != (flagVKInput == "") {
				return errors.New("--pk-input and --vk-input must be supplied together (or neither)")
			}
			passthrough := flagPKInput != ""
			if flagEmitCCSOnly && passthrough {
				return errors.New("--emit-ccs-only is incompatible with --pk-input/--vk-input")
			}
			// The default single-party groth16.Setup produces toxic-waste-equivalent
			// keys (anyone holding the pk can forge wrapper proofs); it must never run
			// unflagged in CI, scheduled, or production contexts. Require explicit
			// opt-in and fail fast, before the expensive outer compile.
			singleParty := !passthrough && !flagEmitCCSOnly
			if singleParty && !flagInsecureDevSetup && os.Getenv("BLS_SNARK_INSECURE_DEV_SETUP") != "1" {
				return errors.New("refusing to run the single-party (INSECURE, toxic-waste-equivalent) groth16.Setup. " +
					"Pass --insecure-dev-setup (or set BLS_SNARK_INSECURE_DEV_SETUP=1) to confirm dev/test use, " +
					"or use an MPC ceremony via --pk-input/--vk-input (and --emit-ccs-only to produce the ccs first)")
			}
			start := time.Now()

			innerCcs, innerVK, err := loadOrGenerateInner(log, src, flagInnerVK, flagOutInnerVK, flagOutInnerPK, flagOutInnerCCS, flagInnerVKFingerprint, flagInsecureNoVKCheck)
			if err != nil {
				return fmt.Errorf("load inner: %w", err)
			}

			log.Info().Msg("compiling outer circuit (BLS12-381 host, BN254 emulated)")
			outerCircuit, err := circuit.NewOuterCircuitForCompile(innerCcs, innerVK)
			if err != nil {
				return fmt.Errorf("build outer placeholder: %w", err)
			}
			ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, outerCircuit)
			if err != nil {
				return fmt.Errorf("compile outer: %w", err)
			}
			nConstraints := ccs.GetNbConstraints()
			log.Info().Int("n_constraints", nConstraints).Msg("outer R1CS compiled")
			// Sanity range for BN254-in-BLS12-381 outer R1CS, verified against
			// gnark v0.15.0. Outside this window suggests an upstream change
			// in std/recursion/groth16 that warrants investigation.
			if nConstraints < 500_000 || nConstraints > 5_000_000 {
				log.Warn().Int("n_constraints", nConstraints).Msg("constraint count outside expected [500K, 5M] window")
			}

			if err := serialize.WriteCCS(flagOutCCS, ccs); err != nil {
				return err
			}

			innerVKFingerprint, err := inner.FingerprintVK(innerVK)
			if err != nil {
				return fmt.Errorf("fingerprint inner vk: %w", err)
			}
			res := setupResult{
				CCSPath:            flagOutCCS,
				InnerVKPath:        flagOutInnerVK,
				InnerPKPath:        flagOutInnerPK,
				InnerCCSPath:       flagOutInnerCCS,
				InnerVKFingerprint: innerVKFingerprint,
				NConstraints:       nConstraints,
				ElapsedSec:         time.Since(start).Seconds(),
			}
			if src != innerCubic {
				res.InnerPKPath = ""
				res.InnerCCSPath = ""
			}

			if flagEmitCCSOnly {
				log.Info().Str("ccs", flagOutCCS).Msg("--emit-ccs-only set; skipping groth16.Setup. Hand this ccs off to your MPC ceremony.")
				res.Mode = "emit-ccs-only"
				emitJSON(log, res)
				return nil
			}

			var pk groth16.ProvingKey
			var vk groth16.VerifyingKey
			if passthrough {
				log.Info().Str("pk", flagPKInput).Str("vk", flagVKInput).Msg("loading externally-produced pk/vk (passthrough; ceremony output)")
				pk, err = serialize.ReadPK(flagPKInput, ecc.BLS12_381)
				if err != nil {
					return fmt.Errorf("load external pk: %w", err)
				}
				vk, err = serialize.ReadVK(flagVKInput, ecc.BLS12_381)
				if err != nil {
					return fmt.Errorf("load external vk: %w", err)
				}
				// Cross-check the supplied keys against the freshly compiled
				// circuit before trusting them. This catches mismatched key
				// pairs and wrong-circuit keys; the definitive guarantee is the
				// prove → verify round trip the operator runs next.
				if err := keycheck.Verify(ccs, pk, vk); err != nil {
					return fmt.Errorf("supplied pk/vk are inconsistent with the compiled circuit: %w", err)
				}
				log.Info().Msg("supplied pk/vk passed consistency checks against the compiled circuit")
				res.Mode = "passthrough"
			} else {
				log.Warn().Msg("══════════════════════════════════════════════════════════════════")
				log.Warn().Msg(" INSECURE single-party Groth16 setup (--insecure-dev-setup).")
				log.Warn().Msg(" The proving key is TOXIC-WASTE-EQUIVALENT — anyone holding it can")
				log.Warn().Msg(" FORGE wrapper proofs for any statement. DEV/TEST ONLY.")
				log.Warn().Msg(" NEVER deploy mainnet on this key. Production requires an MPC")
				log.Warn().Msg(" ceremony fed back in via --pk-input/--vk-input.")
				log.Warn().Msg("══════════════════════════════════════════════════════════════════")
				pk, vk, err = groth16.Setup(ccs)
				if err != nil {
					return fmt.Errorf("outer groth16.Setup: %w", err)
				}
				res.Mode = "insecure-dev-setup"
				res.Warning = "INSECURE single-party setup"
			}

			if err := serialize.WritePK(flagOutPK, pk); err != nil {
				return err
			}
			if err := serialize.WriteVK(flagOutVK, vk); err != nil {
				return err
			}
			res.PKPath = flagOutPK
			res.VKPath = flagOutVK
			res.ElapsedSec = time.Since(start).Seconds()
			emitJSON(log, res)
			return nil
		},
	}

	cmd.Flags().StringVar(&flagInnerSource, "inner-source", "cubic", "inner-proof source (cubic|risc0)")
	cmd.Flags().StringVar(&flagInnerVK, "inner-vk", "", "snarkjs verification_key.json (risc0 mode only)")
	cmd.Flags().StringVar(&flagOutPK, "out-pk", "./out/outer_pk.bin", "outer proving key path")
	cmd.Flags().StringVar(&flagOutVK, "out-vk", "./out/outer_vk.bin", "outer verifying key path")
	cmd.Flags().StringVar(&flagOutCCS, "out-ccs", "./out/outer.ccs", "outer R1CS path")
	cmd.Flags().StringVar(&flagOutInnerVK, "out-inner-vk", "./out/inner_vk.bin", "inner VK (gnark-native) path")
	cmd.Flags().StringVar(&flagOutInnerPK, "out-inner-pk", "./out/inner_pk.bin", "inner PK path (cubic mode only)")
	cmd.Flags().StringVar(&flagOutInnerCCS, "out-inner-ccs", "./out/inner.ccs", "inner CCS path (cubic mode only)")

	cmd.Flags().StringVar(&flagInnerVKFingerprint, "inner-vk-fingerprint", "",
		"override the embedded canonical risc0 VK fingerprint (64-char lowercase hex SHA-256 of vk.WriteTo bytes). "+
			"Use only when wrapping a non-canonical inner VK (e.g. a new risc0 ceremony before this repo is updated, "+
			"or a non-risc0 BN254 Groth16 input). To obtain the value, run `go test ./internal/inner -run TestPrintCanonical` "+
			"against your testdata/risc0/verification_key.json.")
	cmd.Flags().BoolVar(&flagInsecureNoVKCheck, "insecure-no-vk-check", false,
		"INSECURE — disable the canonical-inner-VK fingerprint check entirely. The wrap will still produce a "+
			"valid Groth16 proof, but the outer circuit will commit to whatever VK was passed in; downstream "+
			"consumers have no guarantee it's the canonical risc0 VK.")
	cmd.Flags().StringVar(&flagPKInput, "pk-input", "",
		"externally-produced outer proving key (e.g. from an MPC ceremony). When set, `groth16.Setup` is "+
			"skipped and this key is used verbatim. Must be paired with --vk-input.")
	cmd.Flags().StringVar(&flagVKInput, "vk-input", "",
		"externally-produced outer verifying key (paired with --pk-input).")
	cmd.Flags().BoolVar(&flagEmitCCSOnly, "emit-ccs-only", false,
		"compile the outer circuit, persist the ccs to --out-ccs, and exit without running setup. "+
			"Hand the ccs off to your MPC ceremony, then re-run setup with --pk-input/--vk-input to "+
			"wire the ceremony output back in.")
	cmd.Flags().BoolVar(&flagInsecureDevSetup, "insecure-dev-setup", false,
		"INSECURE — explicitly opt in to the single-party groth16.Setup (toxic-waste-equivalent keys). "+
			"Required to run the default setup; without it (and without --pk-input/--emit-ccs-only) the "+
			"command refuses. DEV/TEST ONLY — never deploy mainnet on these keys. (env: BLS_SNARK_INSECURE_DEV_SETUP=1)")

	return cmd
}

// loadOrGenerateInner produces the inner ccs + VK needed by the outer
// placeholder. Cubic mode generates fresh; risc0 mode parses snarkjs JSON
// emitted by tools/risc0-dump.
func loadOrGenerateInner(
	log zerolog.Logger,
	src innerSource,
	innerVKJSON, outInnerVK, outInnerPK, outInnerCCS string,
	innerVKFingerprintOverride string,
	insecureNoVKCheck bool,
) (constraint.ConstraintSystem, groth16.VerifyingKey, error) {
	switch src {
	case innerCubic:
		log.Info().Msg("generating cubic inner Groth16-BN254 setup (dev fixture)")
		ccs, pk, vk, err := inner.GenerateCubicSetup()
		if err != nil {
			return nil, nil, fmt.Errorf("cubic setup: %w", err)
		}
		log.Info().Int("inner_n_constraints", ccs.GetNbConstraints()).Msg("inner R1CS compiled")
		if err := serialize.WriteCCS(outInnerCCS, ccs); err != nil {
			return nil, nil, err
		}
		if err := serialize.WritePK(outInnerPK, pk); err != nil {
			return nil, nil, err
		}
		if err := serialize.WriteVK(outInnerVK, vk); err != nil {
			return nil, nil, err
		}
		return ccs, vk, nil
	case innerRISC0:
		if innerVKJSON == "" {
			return nil, nil, errors.New("risc0 inner-source requires --inner-vk <snarkjs verification_key.json>")
		}
		log.Info().Str("inner_vk", innerVKJSON).Msg("loading RISC0 inner VK (snarkjs JSON)")
		if insecureNoVKCheck {
			log.Warn().Msg("INSECURE — --insecure-no-vk-check set; skipping canonical risc0 VK fingerprint check")
		} else if innerVKFingerprintOverride != "" {
			log.Warn().Str("override", innerVKFingerprintOverride).Msg("using --inner-vk-fingerprint override instead of embedded canonical risc0 VK fingerprint")
		}
		ccs, vk, err := inner.LoadRISC0InnerSetup(innerVKJSON, inner.RISC0SetupOptions{
			AcceptVKFingerprint:    innerVKFingerprintOverride,
			SkipVKFingerprintCheck: insecureNoVKCheck,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("risc0 inner setup: %w", err)
		}
		log.Info().Int("inner_n_public_vars", ccs.GetNbPublicVariables()).Msg("RISC0 stub inner ccs compiled")
		// Persist the native VK so `prove` can read it the same way both modes do.
		if err := serialize.WriteVK(outInnerVK, vk); err != nil {
			return nil, nil, err
		}
		return ccs, vk, nil
	default:
		return nil, nil, fmt.Errorf("unhandled inner-source %q", src)
	}
}
