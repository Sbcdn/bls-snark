package cli

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/sbcdn/bls-snark/internal/circuit"
	"github.com/sbcdn/bls-snark/internal/inner"
	"github.com/sbcdn/bls-snark/internal/serialize"
)

// risc0Params mirrors tools/risc0-dump's risc0_params.json sidecar. Schema v1
// has no claim_digest; v2 adds it (the journal-bound value). Both are accepted.
type risc0Params struct {
	Version          string `json:"version"`
	ImageID          string `json:"image_id"`
	ControlRoot      string `json:"control_root"`
	BN254ControlIDFr string `json:"bn254_control_id_fr"`
	ClaimDigest      string `json:"claim_digest,omitempty"` // schema v2 only
}

// readRISC0Params parses and validates a risc0_params.json sidecar. Rejects
// extra fields (so future schema versions can't silently downgrade) and
// validates every field shape so a tampered or malformed sidecar fails
// here rather than producing a misleading image_id comparison later.
func readRISC0Params(path string) (*risc0Params, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var p risc0Params
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse %q: %w", path, err)
	}
	switch p.Version {
	case "1":
		// no claim_digest field
	case "2":
		if err := validateHex32(p.ClaimDigest); err != nil {
			return nil, fmt.Errorf("%q: claim_digest %w", path, err)
		}
	default:
		return nil, fmt.Errorf("%q: unsupported risc0_params schema version %q (want \"1\" or \"2\")", path, p.Version)
	}
	if err := validateHex32(p.ImageID); err != nil {
		return nil, fmt.Errorf("%q: image_id %w", path, err)
	}
	if err := validateHex32(p.ControlRoot); err != nil {
		return nil, fmt.Errorf("%q: control_root %w", path, err)
	}
	if _, ok := new(big.Int).SetString(p.BN254ControlIDFr, 10); !ok {
		return nil, fmt.Errorf("%q: bn254_control_id_fr %q is not a decimal integer", path, p.BN254ControlIDFr)
	}
	return &p, nil
}

// validateHex32 enforces 64 lowercase-hex characters (i.e. a 32-byte BE
// digest). Callers should pre-normalise (lowercase, strip 0x) before
// calling, OR rely on this to reject anything not already canonical.
func validateHex32(s string) error {
	if len(s) != 64 {
		return fmt.Errorf("length %d, expected 64 hex chars", len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		return fmt.Errorf("not valid hex: %w", err)
	}
	return nil
}

// normaliseImageIDHex lower-cases, strips an optional 0x prefix, and
// validates the result is canonical 64-char hex. Returns an error so
// `--require-image-id garbage` fails fast with a clear message rather
// than silently miscomparing against the sidecar.
func normaliseImageIDHex(s string) (string, error) {
	n := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(s, "0X"), "0x"))
	if err := validateHex32(n); err != nil {
		return "", err
	}
	return n, nil
}

type proveResult struct {
	ProofPath          string  `json:"proof_path"`
	PublicPath         string  `json:"public_path"`
	ProofBytes         int64   `json:"proof_bytes"`
	PublicBytes        int64   `json:"public_bytes"`
	ElapsedSec         float64 `json:"elapsed_seconds"`
	InnerSource        string  `json:"inner_source"`
	InnerVKFingerprint string  `json:"inner_vk_fingerprint,omitempty"` // SHA-256 of the native-verified inner VK; auditable post-hoc.
	ImageIDPinned      bool    `json:"image_id_pinned"`                // true iff --require-image-id was supplied and matched.
	ImageID            string  `json:"image_id,omitempty"`
}

func newProveCmd(log zerolog.Logger) *cobra.Command {
	var (
		flagInnerSource    string
		flagPK             string
		flagCCS            string
		flagInnerVK        string
		flagInnerPK        string
		flagInnerCCS       string
		flagInnerProof     string
		flagInnerPublic    string
		flagOutProof       string
		flagOutPublic      string
		flagRISC0Params    string
		flagRequireImageID string
		flagExpectClaim    string
		flagExpectCtrlRoot string
		flagExpectBN254ID  string
	)

	cmd := &cobra.Command{
		Use:   "prove",
		Short: "Build an outer Groth16-BLS12-381 proof wrapping an inner BN254 Groth16 proof.",
		Long: `Loads the outer proving key + R1CS and the inner verifying key, obtains
an inner proof (cubic: generated fresh from the persisted inner pk/ccs;
risc0: parsed from snarkjs JSON), native-verifies the inner proof, then
runs Groth16.Prove on the outer circuit to produce the wrapping proof.

Examples:
  bls-snark prove --inner-source cubic --pk out/outer_pk.bin --ccs out/outer.ccs --inner-vk out/inner_vk.bin
  bls-snark prove --inner-source risc0 --pk out/outer_pk.bin --ccs out/outer.ccs --inner-vk out/inner_vk.bin \
      --inner-proof testdata/risc0/proof.json --inner-public testdata/risc0/public.json
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			src, err := parseInnerSource(flagInnerSource)
			if err != nil {
				return err
			}

			// Configuration-drift gate. Runs before any cryptographic work so
			// a mismatched sidecar fails fast. The actual proof↔image_id
			// binding is enforced by the outer circuit's claim_digest wires
			// regardless of this flag.
			var (
				imageIDPinned   bool
				resolvedImageID string
			)
			if flagRequireImageID != "" {
				if src != innerRISC0 {
					return errors.New("--require-image-id only applies to --inner-source risc0")
				}
				if flagRISC0Params == "" {
					return errors.New("--require-image-id requires --risc0-params (sidecar carrying the actual image_id)")
				}
				params, err := readRISC0Params(flagRISC0Params)
				if err != nil {
					return fmt.Errorf("read risc0_params: %w", err)
				}
				want, err := normaliseImageIDHex(flagRequireImageID)
				if err != nil {
					return fmt.Errorf("--require-image-id: %w", err)
				}
				got := strings.ToLower(params.ImageID) // already validated 64-hex by readRISC0Params
				if want != got {
					return fmt.Errorf("image_id mismatch: sidecar %s reports %s, but --require-image-id=%s",
						flagRISC0Params, got, want)
				}
				imageIDPinned = true
				resolvedImageID = got
				log.Info().Str("sidecar", flagRISC0Params).Msg("image_id pinning check passed")
			}

			// --expect-* pins are risc0-only (the 5-scalar public-input layout);
			// fail fast before any proving work.
			if (flagExpectClaim != "" || flagExpectCtrlRoot != "" || flagExpectBN254ID != "") && src != innerRISC0 {
				return errors.New("--expect-claim-digest / --expect-control-root / --expect-bn254-control-id apply to --inner-source risc0 only")
			}

			start := time.Now()

			log.Info().Str("pk", flagPK).Str("ccs", flagCCS).Msg("loading outer pk + ccs")
			outerCcs, err := serialize.ReadCCS(flagCCS, ecc.BLS12_381)
			if err != nil {
				return err
			}
			outerPK, err := serialize.ReadPK(flagPK, ecc.BLS12_381)
			if err != nil {
				return err
			}

			log.Info().Str("inner_vk", flagInnerVK).Msg("loading inner VK")
			innerVK, err := serialize.ReadVK(flagInnerVK, ecc.BN254)
			if err != nil {
				return err
			}
			innerVKFingerprint, err := inner.FingerprintVK(innerVK)
			if err != nil {
				return fmt.Errorf("fingerprint inner vk: %w", err)
			}

			var (
				innerProof groth16.Proof
				innerPub   witness.Witness
			)
			switch src {
			case innerCubic:
				log.Info().Msg("generating fresh cubic inner proof")
				innerCcs, err := serialize.ReadCCS(flagInnerCCS, ecc.BN254)
				if err != nil {
					return err
				}
				innerPK, err := serialize.ReadPK(flagInnerPK, ecc.BN254)
				if err != nil {
					return err
				}
				innerProof, innerPub, err = inner.ProveCubic(
					innerCcs, innerPK, big.NewInt(3), big.NewInt(35),
					ecc.BLS12_381.ScalarField(),
				)
				if err != nil {
					return fmt.Errorf("prove cubic: %w", err)
				}
			case innerRISC0:
				if flagInnerProof == "" || flagInnerPublic == "" {
					return errors.New("risc0 inner-source requires --inner-proof and --inner-public")
				}
				log.Info().Str("proof", flagInnerProof).Str("public", flagInnerPublic).Msg("loading RISC0 inner proof + public inputs (snarkjs JSON)")
				innerProof, innerPub, err = inner.LoadRISC0Proof(flagInnerProof, flagInnerPublic)
				if err != nil {
					return fmt.Errorf("load risc0 inner: %w", err)
				}
			default:
				return fmt.Errorf("unhandled inner-source %q", src)
			}

			// Never wrap an inner proof we haven't first verified natively —
			// an invalid inner proof must abort here, not surface as a confusing
			// outer-circuit constraint failure later.
			log.Info().Msg("native-verifying inner proof before outer prove")
			if err := groth16.Verify(
				innerProof, innerVK, innerPub,
				stdgroth16.GetNativeVerifierOptions(ecc.BLS12_381.ScalarField(), ecc.BN254.ScalarField()),
			); err != nil {
				return fmt.Errorf("inner proof failed native verify: %w", err)
			}

			// Optional operator pins: refuse to wrap a proof whose bound risc0
			// public inputs don't match the expected execution/platform values
			// (the risc0-only gate above already validated --inner-source).
			if flagExpectClaim != "" || flagExpectCtrlRoot != "" || flagExpectBN254ID != "" {
				if err := verifyExpectedClaimBindings(innerPub, flagExpectClaim, flagExpectCtrlRoot, flagExpectBN254ID); err != nil {
					return fmt.Errorf("expected-binding check failed: %w", err)
				}
				log.Info().Msg("expected-binding pins matched the proof's public inputs")
			}

			log.Info().Msg("building outer witness")
			outerAssign, err := circuit.NewOuterCircuitForProve(innerProof, innerPub)
			if err != nil {
				return err
			}
			outerWitness, err := frontend.NewWitness(outerAssign, ecc.BLS12_381.ScalarField())
			if err != nil {
				return fmt.Errorf("new outer witness: %w", err)
			}

			log.Info().Msg("running outer Groth16.Prove (BLS12-381)")
			outerProof, err := groth16.Prove(outerCcs, outerPK, outerWitness)
			if err != nil {
				return fmt.Errorf("outer prove: %w", err)
			}

			pubOnly, err := outerWitness.Public()
			if err != nil {
				return fmt.Errorf("extract outer public witness: %w", err)
			}

			if err := ensureDir(flagOutProof); err != nil {
				return err
			}
			if err := ensureDir(flagOutPublic); err != nil {
				return err
			}
			if _, err := serialize.WriteProof(flagOutProof, outerProof); err != nil {
				return err
			}
			if err := serialize.WriteWitness(flagOutPublic, pubOnly); err != nil {
				return err
			}

			// We just wrote both files; a stat failure here is a real I/O fault,
			// not a missing artifact — surface it rather than reporting 0 bytes.
			proofSize, err := fileSize(flagOutProof)
			if err != nil {
				return fmt.Errorf("stat outer proof %q: %w", flagOutProof, err)
			}
			pubSize, err := fileSize(flagOutPublic)
			if err != nil {
				return fmt.Errorf("stat outer public %q: %w", flagOutPublic, err)
			}

			emitJSON(log, proveResult{
				ProofPath:          flagOutProof,
				PublicPath:         flagOutPublic,
				ProofBytes:         proofSize,
				PublicBytes:        pubSize,
				ElapsedSec:         time.Since(start).Seconds(),
				InnerSource:        string(src),
				InnerVKFingerprint: innerVKFingerprint,
				ImageIDPinned:      imageIDPinned,
				ImageID:            resolvedImageID,
			})
			return nil
		},
	}

	cmd.Flags().StringVar(&flagInnerSource, "inner-source", "cubic", "inner-proof source (cubic|risc0)")
	cmd.Flags().StringVar(&flagPK, "pk", "./out/outer_pk.bin", "outer proving key path")
	cmd.Flags().StringVar(&flagCCS, "ccs", "./out/outer.ccs", "outer R1CS path")
	cmd.Flags().StringVar(&flagInnerVK, "inner-vk", "./out/inner_vk.bin", "inner verifying key path (gnark-native binary)")
	cmd.Flags().StringVar(&flagInnerPK, "inner-pk", "./out/inner_pk.bin", "inner proving key path (cubic mode)")
	cmd.Flags().StringVar(&flagInnerCCS, "inner-ccs", "./out/inner.ccs", "inner R1CS path (cubic mode)")
	cmd.Flags().StringVar(&flagInnerProof, "inner-proof", "", "snarkjs proof.json (risc0 mode)")
	cmd.Flags().StringVar(&flagInnerPublic, "inner-public", "", "snarkjs public.json (risc0 mode)")
	cmd.Flags().StringVar(&flagRISC0Params, "risc0-params", "", "path to risc0_params.json sidecar (from tools/risc0-dump). Required when --require-image-id is set.")
	cmd.Flags().StringVar(&flagRequireImageID, "require-image-id", "", "preflight configuration-drift check (NOT a cryptographic gate): fail if --risc0-params reports a different image_id than this 64-char hex (optional 0x prefix). The wrap's actual binding to image_id is via the outer circuit's claim_digest wires regardless of this flag.")
	cmd.Flags().StringVar(&flagOutProof, "out-proof", "./out/outer_proof.bin", "outer proof output path")
	cmd.Flags().StringVar(&flagOutPublic, "out-public", "./out/outer_public.bin", "outer public-witness binary path")
	cmd.Flags().StringVar(&flagExpectClaim, "expect-claim-digest", "",
		"risc0 only: refuse to wrap unless the proof's claim_digest matches this 64-char hex (pins the specific execution)")
	cmd.Flags().StringVar(&flagExpectCtrlRoot, "expect-control-root", "",
		"risc0 only: refuse to wrap unless the proof's control_root matches this 64-char hex (pins the risc0 platform release)")
	cmd.Flags().StringVar(&flagExpectBN254ID, "expect-bn254-control-id", "",
		"risc0 only: refuse to wrap unless the proof's bn254_control_id matches this 64-char hex (pins the risc0 platform release)")
	return cmd
}
