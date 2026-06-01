// v2 byte-format parsers (hand-rolled — no gnark binary deserialisers) plus the
// tiny byte-stream reader they share. The verification equation lives in ref.go.
package cardano_ref

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// VK is the parsed Cardano vk.bin (v2). Field names follow Aiken-side naming.
type VK struct {
	AlphaG1           bls12381.G1Affine
	BetaG2            bls12381.G2Affine
	GammaG2           bls12381.G2Affine
	DeltaG2           bls12381.G2Affine
	IC                []bls12381.G1Affine // length = ic_count
	NC                uint32              // number of Pedersen commitment slots
	PedersenG         []bls12381.G2Affine // length = nC
	PedersenGSigmaNeg []bls12381.G2Affine // length = nC
	CommittedIndices  [][]uint32          // CommittedIndices[j] = public-witness indices (1-indexed) committed by commitment j
}

// Proof is the parsed Cardano proof.bin (v2).
type Proof struct {
	Ar                      bls12381.G1Affine
	Bs                      bls12381.G2Affine
	Krs                     bls12381.G1Affine
	NC                      uint32
	CommitmentsCompressed   []bls12381.G1Affine // length = nC; decompressed for arithmetic
	CommitmentsUncompressed [][]byte            // length = nC; each 96 B; passed to HashToField VERBATIM
	CommitmentPok           bls12381.G1Affine   // single (unfolded) PoK when nC=1
}

// Public is the parsed Cardano public.bin. `LimbsBE` is the flat list of
// outer-circuit public witnesses (n_inner_pub × n_limbs_per_scalar entries),
// each as a 32-byte big-endian BLS12-381 fr element.
type Public struct {
	NInnerPub       uint32
	NLimbsPerScalar uint32
	LimbsBE         [][]byte
}

// boundAlloc rejects a length field that cannot possibly be backed by the
// bytes remaining — a hostile/corrupt count (e.g. 0xFFFFFFFF) would otherwise
// trigger a huge make() and OOM before the per-element reads fail at EOF.
// elemSize is the minimum bytes each element consumes.
func boundAlloc(n uint32, elemSize, remaining int, label string) error {
	if uint64(n)*uint64(elemSize) > uint64(remaining) {
		return fmt.Errorf("cardano_ref: %s count %d exceeds %d remaining bytes (≥%d each)", label, n, remaining, elemSize)
	}
	return nil
}

// ParseVK consumes a Cardano vk.bin (v2) byte slice.
func ParseVK(data []byte) (*VK, error) {
	r := newReader(data)
	vk := &VK{}
	if err := r.g1(&vk.AlphaG1, "alpha_g1"); err != nil {
		return nil, err
	}
	if err := r.g2(&vk.BetaG2, "beta_g2"); err != nil {
		return nil, err
	}
	if err := r.g2(&vk.GammaG2, "gamma_g2"); err != nil {
		return nil, err
	}
	if err := r.g2(&vk.DeltaG2, "delta_g2"); err != nil {
		return nil, err
	}
	icCount, err := r.u32("ic_count")
	if err != nil {
		return nil, err
	}
	if err := boundAlloc(icCount, 48, r.left(), "ic_count"); err != nil { // each IC is a compressed G1 (48 B)
		return nil, err
	}
	vk.IC = make([]bls12381.G1Affine, icCount)
	for i := range vk.IC {
		if err := r.g1(&vk.IC[i], fmt.Sprintf("IC[%d]", i)); err != nil {
			return nil, err
		}
	}
	nC, err := r.u32("nC")
	if err != nil {
		return nil, err
	}
	if err := boundAlloc(nC, 96+96+4, r.left(), "nC"); err != nil { // each slot ≥ pedersen_G(96)+GSigmaNeg(96)+count(4)
		return nil, err
	}
	vk.NC = nC
	vk.PedersenG = make([]bls12381.G2Affine, nC)
	vk.PedersenGSigmaNeg = make([]bls12381.G2Affine, nC)
	vk.CommittedIndices = make([][]uint32, nC)
	for j := uint32(0); j < nC; j++ {
		if err := r.g2(&vk.PedersenG[j], fmt.Sprintf("pedersen_G[%d]", j)); err != nil {
			return nil, err
		}
		if err := r.g2(&vk.PedersenGSigmaNeg[j], fmt.Sprintf("pedersen_GSigmaNeg[%d]", j)); err != nil {
			return nil, err
		}
		nIdx, err := r.u32(fmt.Sprintf("committed_count[%d]", j))
		if err != nil {
			return nil, err
		}
		if err := boundAlloc(nIdx, 4, r.left(), "committed_count"); err != nil { // each index is u32 (4 B)
			return nil, err
		}
		vk.CommittedIndices[j] = make([]uint32, nIdx)
		for k := range vk.CommittedIndices[j] {
			idx, err := r.u32(fmt.Sprintf("committed_index[%d][%d]", j, k))
			if err != nil {
				return nil, err
			}
			vk.CommittedIndices[j][k] = idx
		}
	}
	if r.left() != 0 {
		return nil, fmt.Errorf("cardano_ref: vk.bin: %d trailing bytes", r.left())
	}
	return vk, nil
}

// ParseProof consumes a Cardano proof.bin (v2) byte slice.
func ParseProof(data []byte) (*Proof, error) {
	r := newReader(data)
	p := &Proof{}
	if err := r.g1(&p.Ar, "a_g1"); err != nil {
		return nil, err
	}
	if err := r.g2(&p.Bs, "b_g2"); err != nil {
		return nil, err
	}
	if err := r.g1(&p.Krs, "c_g1"); err != nil {
		return nil, err
	}
	// Reject the point at infinity for A/B/C — a degenerate proof point makes
	// the pairing equation trivial and ill-defined.
	if p.Ar.IsInfinity() || p.Bs.IsInfinity() || p.Krs.IsInfinity() {
		return nil, fmt.Errorf("cardano_ref: proof A/B/C must not be the point at infinity")
	}
	nC, err := r.u32("nC")
	if err != nil {
		return nil, err
	}
	if err := boundAlloc(nC, 48+96, r.left(), "nC"); err != nil { // each ≥ compressed(48)+uncompressed(96)
		return nil, err
	}
	p.NC = nC
	p.CommitmentsCompressed = make([]bls12381.G1Affine, nC)
	p.CommitmentsUncompressed = make([][]byte, nC)
	for j := uint32(0); j < nC; j++ {
		if err := r.g1(&p.CommitmentsCompressed[j], fmt.Sprintf("commitment[%d] compressed", j)); err != nil {
			return nil, err
		}
		raw := make([]byte, 96)
		if _, err := io.ReadFull(r.r, raw); err != nil {
			return nil, fmt.Errorf("cardano_ref: commitment[%d] uncompressed: %w", j, err)
		}
		// The uncompressed copy is the hash-to-field input; the compressed copy
		// enters the pairing. They are supplied independently in the wire format,
		// so the verifier must confirm the uncompressed bytes are a valid point
		// and equal the compressed commitment. Relying instead on "a mismatch
		// breaks the pairing" is collision-resistance-dependent and easy for an
		// on-chain port to omit. The on-chain validator must perform the same check.
		var uncompressed bls12381.G1Affine
		if _, err := uncompressed.SetBytes(raw); err != nil {
			return nil, fmt.Errorf("cardano_ref: commitment[%d] uncompressed: invalid point: %w", j, err)
		}
		if !uncompressed.Equal(&p.CommitmentsCompressed[j]) {
			return nil, fmt.Errorf("cardano_ref: commitment[%d] compressed/uncompressed copies are different points", j)
		}
		p.CommitmentsUncompressed[j] = raw
	}
	if err := r.g1(&p.CommitmentPok, "commitment_pok"); err != nil {
		return nil, err
	}
	if r.left() != 0 {
		return nil, fmt.Errorf("cardano_ref: proof.bin: %d trailing bytes", r.left())
	}
	return p, nil
}

// ParsePublic consumes a Cardano public.bin byte slice.
func ParsePublic(data []byte) (*Public, error) {
	r := newReader(data)
	nInner, err := r.u32("n_inner_pub")
	if err != nil {
		return nil, err
	}
	nLimbs, err := r.u32("n_limbs_per_scalar")
	if err != nil {
		return nil, err
	}
	// Bound by the bytes remaining (each limb is 32 B) before allocating. The
	// product of two u32 fits in u64 (max (2^32-1)^2 < 2^64), so compare against
	// remaining/32 — do NOT multiply by 32 (that itself overflows u64).
	if uint64(nInner)*uint64(nLimbs) > uint64(r.left())/32 {
		return nil, fmt.Errorf("cardano_ref: public.bin: n_inner_pub=%d × n_limbs=%d exceeds %d remaining 32-byte slots", nInner, nLimbs, r.left()/32)
	}
	total := int(nInner) * int(nLimbs)
	p := &Public{
		NInnerPub:       nInner,
		NLimbsPerScalar: nLimbs,
		LimbsBE:         make([][]byte, total),
	}
	for i := 0; i < total; i++ {
		limb := make([]byte, 32)
		if _, err := io.ReadFull(r.r, limb); err != nil {
			return nil, fmt.Errorf("cardano_ref: limb[%d]: %w", i, err)
		}
		// Reject non-canonical limbs (value ≥ r). ScalarMultiplication reduces mod
		// r internally, so v and v+r would scalar-mult to the same point and the
		// pairing would still pass — accepting a malleated public.bin that encodes
		// the same statement with different bytes. gnark's witness deserialiser
		// enforces canonical reduction; a faithful on-chain mirror must too.
		if v := new(big.Int).SetBytes(limb); v.Cmp(BLS12_381_FrModulus()) >= 0 {
			return nil, fmt.Errorf("cardano_ref: limb[%d] not canonical: value ≥ BLS12-381 Fr modulus", i)
		}
		p.LimbsBE[i] = limb
	}
	if r.left() != 0 {
		return nil, fmt.Errorf("cardano_ref: public.bin: %d trailing bytes", r.left())
	}
	return p, nil
}

// =============================================================================
// Tiny byte-stream reader (internal — keeps parsers terse).
// =============================================================================

type reader struct {
	r *bytesReader
}

func newReader(data []byte) *reader {
	return &reader{r: &bytesReader{buf: data}}
}

func (r *reader) u32(label string) (uint32, error) {
	var v uint32
	if err := binary.Read(r.r, binary.BigEndian, &v); err != nil {
		return 0, fmt.Errorf("cardano_ref: %s: %w", label, err)
	}
	return v, nil
}

func (r *reader) g1(p *bls12381.G1Affine, label string) error {
	var buf [48]byte
	if _, err := io.ReadFull(r.r, buf[:]); err != nil {
		return fmt.Errorf("cardano_ref: %s read: %w", label, err)
	}
	if _, err := p.SetBytes(buf[:]); err != nil {
		return fmt.Errorf("cardano_ref: %s decompress: %w", label, err)
	}
	return nil
}

func (r *reader) g2(p *bls12381.G2Affine, label string) error {
	var buf [96]byte
	if _, err := io.ReadFull(r.r, buf[:]); err != nil {
		return fmt.Errorf("cardano_ref: %s read: %w", label, err)
	}
	if _, err := p.SetBytes(buf[:]); err != nil {
		return fmt.Errorf("cardano_ref: %s decompress: %w", label, err)
	}
	return nil
}

func (r *reader) left() int { return r.r.left() }

// bytesReader is a minimal in-memory io.Reader with a `left()` query.
// bytes.Reader is avoided: its Read returns io.EOF mid-decode in cases the
// parser needs to treat as hard errors with a deterministic trailing-bytes
// check.
type bytesReader struct {
	buf []byte
	off int
}

func (b *bytesReader) Read(p []byte) (int, error) {
	if b.off >= len(b.buf) {
		return 0, io.EOF
	}
	n := copy(p, b.buf[b.off:])
	b.off += n
	return n, nil
}

func (b *bytesReader) left() int { return len(b.buf) - b.off }
