package vche_2

import (
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/utils"
	"veritas/vche/vche"
	"golang.org/x/crypto/blake2b"
	"log"
	"math/big"
)

var VERBOSE = false

type Encoder interface {
	EncodeUint(coeffs []uint64, tags []vche.Tag, pt *Plaintext)
	EncodeUintNew(coeffs []uint64, tags []vche.Tag) (pt *Plaintext)
	EncodeUintMul(coeffs []uint64, tags []vche.Tag, pt *PlaintextMul)
	EncodeUintMulNew(coeffs []uint64, tags []vche.Tag) (pt *PlaintextMul)
	EncodeInt(coeffs []int64, tags []vche.Tag, pt *Plaintext)
	EncodeIntNew(coeffs []int64, tags []vche.Tag) (pt *Plaintext)
	EncodeIntMul(coeffs []int64, tags []vche.Tag, pt *PlaintextMul)
	EncodeIntMulNew(coeffs []int64, tags []vche.Tag) (pt *PlaintextMul)
	DecodeUint(pt *Plaintext, verif *Poly, coeffs []uint64)
	DecodeUintNew(pt *Plaintext, verif *Poly) (coeffs []uint64)
	DecodeInt(pt *Plaintext, verif *Poly, coeffs []int64)
	DecodeIntNew(pt *Plaintext, verif *Poly) (coeffs []int64)
	PRF(replicationIndex int, xs ...interface{}) uint64
}

type encoder struct {
	bfv.Encoder
	params           Parameters
	K                []vche.PRFKey
	alpha            []uint64
	alphaInv         []uint64
	useClosedFormPRF bool
	xofs1, xofs2     []blake2b.XOF
}

func checkAlpha(params Parameters, alpha uint64) {
	if alpha >= params.T() {
		panic("alpha must be in Z_t")
	}
	if alpha == 0 {
		panic("alpha must be invertible")
	}
}

func NewEncoder(params Parameters, K []vche.PRFKey, alphas []uint64, useClosedFormPRF bool) Encoder {
	if len(K) != len(alphas) {
		panic(fmt.Errorf("number of provided PRF keys and alphas must be the same, got %d and %d", len(K), len(alphas)))
	}

	alphasInv := make([]uint64, len(alphas))
	for i, alpha := range alphas {
		checkAlpha(params, alpha)
		alphasInv[i] = modInv(alpha, params.T())
	}

	xofs1, xofs2 := make([]blake2b.XOF, len(K)), make([]blake2b.XOF, len(K))
	for i := range xofs1 {
		xofs1[i] = vche.NewXOF(K[i].K1)
		xofs2[i] = vche.NewXOF(K[i].K2)
	}
	return &encoder{bfv.NewEncoder(params.Parameters), params, K, alphas, alphasInv, useClosedFormPRF, xofs1, xofs2}
}

func (enc *encoder) checkLengths(cs interface{}, tags []vche.Tag) {
	var lenCoeffs int
	switch s := cs.(type) {
	case []uint64:
		lenCoeffs = len(s)
	case []int64:
		lenCoeffs = len(s)
	}
	N := enc.params.N()
	lambda := enc.params.NumReplications
	NSlots := enc.params.NSlots
	if lenCoeffs != len(tags) {
		panic(fmt.Errorf("coeffs and tags should have the same length, got %d and %d", lenCoeffs, len(tags)))
	}
	if lenCoeffs > NSlots {
		panic(fmt.Errorf("coeffs cannot be longer than N / lambda = %d / %d = %d, was %d", N, lambda, NSlots, lenCoeffs))
	}
	if lenCoeffs < NSlots {
		panic(fmt.Errorf("coeffs should have length %d, was %d", NSlots, lenCoeffs))
	}
}

func (enc *encoder) encodeUintCoeffs(coeffs []uint64, tags []vche.Tag) []uint64 {
	enc.checkLengths(coeffs, tags)

	// Build replicated message
	internalCoeffs := make([]uint64, enc.params.N())
	for i := range coeffs {
		for j := 0; j < enc.params.NumReplications; j++ {
			idx := i*enc.params.NumReplications + j
			internalCoeffs[idx] = coeffs[i]
		}
	}
	return internalCoeffs
}

func (enc *encoder) encodeIntCoeffs(coeffs []int64, tags []vche.Tag) []int64 {
	enc.checkLengths(coeffs, tags)

	// Build replicated message
	internalCoeffs := make([]int64, enc.params.N())
	for i := range coeffs {
		for j := 0; j < enc.params.NumReplications; j++ {
			idx := i*enc.params.NumReplications + j
			internalCoeffs[idx] = coeffs[i]
		}
	}
	return internalCoeffs
}

func (enc *encoder) encodeUintTags(coeffs []uint64, tags []vche.Tag) []uint64 {
	// Build replicated (PRF(tags) - message) / alpha
	ys := make([]uint64, enc.params.N())
	T := enc.params.T()
	for i := range tags {
		for j := 0; j < enc.params.NumReplications; j++ {
			idx := i*enc.params.NumReplications + j
			r := enc.PRF(j, tags[i])
			//ys[idx] = (((T + r - coeffs[i]) % T) * enc.alphaInv[j]) % T
			tmp := big.NewInt(0)
			tmp.Add(big.NewInt(int64(T)), big.NewInt(int64(r)))
			tmp.Sub(tmp, big.NewInt(int64(coeffs[i])))
			tmp.Mod(tmp, big.NewInt(int64(T)))
			tmp.Mul(tmp, big.NewInt(int64(enc.alphaInv[j])))
			tmp.Mod(tmp, big.NewInt(int64(T)))
			ys[idx] = tmp.Uint64()
		}
	}
	return ys
}

func (enc *encoder) encodeIntTags(coeffs []int64, tags []vche.Tag) []uint64 {
	// Build replicated (PRF(tags) - message) / alpha
	ys := make([]uint64, enc.params.N())
	T := enc.params.T()
	for i := range tags {
		for j := 0; j < enc.params.NumReplications; j++ {
			idx := i*enc.params.NumReplications + j
			r := enc.PRF(j, tags[i])
			var cI uint64
			if coeffs[i] < 0 {
				cI = big.NewInt(0).Add(big.NewInt(int64(T)), big.NewInt(coeffs[i])).Uint64()
			} else {
				cI = uint64(coeffs[i])
			}
			//ys[idx] = (((T + r - cI) % T) * enc.alphaInv[j]) % T
			tmp := big.NewInt(0)
			tmp.Add(big.NewInt(int64(T)), big.NewInt(int64(r)))
			tmp.Sub(tmp, big.NewInt(int64(cI)))
			tmp.Mod(tmp, big.NewInt(int64(T)))
			tmp.Mul(tmp, big.NewInt(int64(enc.alphaInv[j])))
			tmp.Mod(tmp, big.NewInt(int64(T)))
			ys[idx] = tmp.Uint64()

		}
	}
	return ys
}

func (enc *encoder) EncodeUint(coeffs []uint64, tags []vche.Tag, pt *Plaintext) {
	pt.Plaintexts = make([]*bfv.Plaintext, 2)
	for i := range pt.Plaintexts {
		pt.Plaintexts[i] = bfv.NewPlaintext(enc.params.Parameters)
	}
	enc.Encoder.EncodeUint(enc.encodeUintCoeffs(coeffs, tags), pt.Plaintexts[0])
	enc.Encoder.EncodeUint(enc.encodeUintTags(coeffs, tags), pt.Plaintexts[1])
}

func (enc *encoder) EncodeUintNew(coeffs []uint64, tags []vche.Tag) (pt *Plaintext) {
	pt = NewPlaintext(enc.params)
	enc.EncodeUint(coeffs, tags, pt)
	return pt
}

func (enc *encoder) EncodeUintMul(coeffs []uint64, tags []vche.Tag, pt *PlaintextMul) {
	pt.Plaintexts = make([]*bfv.PlaintextMul, 2)
	for i := range pt.Plaintexts {
		pt.Plaintexts[i] = bfv.NewPlaintextMul(enc.params.Parameters)
	}
	enc.Encoder.EncodeUintMul(enc.encodeUintCoeffs(coeffs, tags), pt.Plaintexts[0])
	enc.Encoder.EncodeUintMul(enc.encodeUintTags(coeffs, tags), pt.Plaintexts[1])
}

func (enc *encoder) EncodeUintMulNew(coeffs []uint64, tags []vche.Tag) (pt *PlaintextMul) {
	pt = NewPlaintextMul(enc.params)
	enc.EncodeUintMul(coeffs, tags, pt)
	return pt
}

func (enc *encoder) EncodeInt(coeffs []int64, tags []vche.Tag, pt *Plaintext) {
	pt.Plaintexts = make([]*bfv.Plaintext, 2)
	for i := range pt.Plaintexts {
		pt.Plaintexts[i] = bfv.NewPlaintext(enc.params.Parameters)
	}
	enc.Encoder.EncodeInt(enc.encodeIntCoeffs(coeffs, tags), pt.Plaintexts[0])
	enc.Encoder.EncodeUint(enc.encodeIntTags(coeffs, tags), pt.Plaintexts[1])
}

func (enc *encoder) EncodeIntNew(coeffs []int64, tags []vche.Tag) (pt *Plaintext) {
	pt = NewPlaintext(enc.params)
	enc.EncodeInt(coeffs, tags, pt)
	return pt
}

func (enc *encoder) EncodeIntMul(coeffs []int64, tags []vche.Tag, pt *PlaintextMul) {
	pt.Plaintexts = make([]*bfv.PlaintextMul, 2)
	for i := range pt.Plaintexts {
		pt.Plaintexts[i] = bfv.NewPlaintextMul(enc.params.Parameters)
	}
	enc.Encoder.EncodeIntMul(enc.encodeIntCoeffs(coeffs, tags), pt.Plaintexts[0])
	enc.Encoder.EncodeUintMul(enc.encodeIntTags(coeffs, tags), pt.Plaintexts[1])
}

func (enc *encoder) EncodeIntMulNew(coeffs []int64, tags []vche.Tag) (pt *PlaintextMul) {
	pt = NewPlaintextMul(enc.params)
	enc.EncodeIntMul(coeffs, tags, pt)
	return pt
}

func (enc *encoder) verifyUint(plaintext *Plaintext, verifPtxt *Poly) []uint64 {
	ys := make([][]uint64, len(plaintext.Plaintexts))
	for i, p := range plaintext.Plaintexts {
		p2 := bfv.NewPlaintext(enc.params.Parameters)
		p2.Plaintext.Copy(p.Plaintext)
		ys[i] = bfv.NewEncoder(enc.params.Parameters).DecodeUintNew(p2)
	}

	// Check that f(F_K(t_1), ..., F_K(t_n)) == \sum_i Dec_sk(c_i) * alpha^i
	T := enc.params.T()
	var rhosPoly *ring.Poly
	if verifPtxt.Shift == nil {
		// No Requadratization
		rhosPoly = verifPtxt.Poly
	} else {
		rhosPoly = enc.params.RingT().NewPoly()
		enc.params.RingT().Add(verifPtxt.Poly, verifPtxt.Shift, rhosPoly)
	}
	rhos := rhosPoly.Coeffs[0]

	rhosCheck := make([]uint64, len(rhos))
	rhosCheck = ys[len(ys)-1]
	for d := len(ys) - 2; d >= 0; d-- {
		for i := 0; i < enc.params.NSlots; i++ {
			for j := 0; j < enc.params.NumReplications; j++ {
				idx := i*enc.params.NumReplications + j
				tmpR := big.NewInt(0)
				tmpR.Mul(big.NewInt(int64(rhosCheck[idx])), big.NewInt(int64(enc.alpha[j])))
				tmpR.Add(tmpR, big.NewInt(int64(ys[d][idx])))
				tmpR.Mod(tmpR, big.NewInt(int64(T)))
				rhosCheck[idx] = tmpR.Uint64()
			}
		}
	}

	if !utils.EqualSliceUint64(rhos, rhosCheck) {
		panic(fmt.Errorf("verification failed due to mismatch"))
	}
	return ys[0]
}

func (enc *encoder) verifyInt(pt *Plaintext, verifPtxt *Poly) []int64 {
	cp := bfv.NewPlaintext(enc.params.Parameters)
	cp.Plaintext.Copy(pt.Plaintexts[0].Plaintext)
	enc.verifyUint(pt, verifPtxt)
	return enc.Encoder.DecodeIntNew(cp)
}

func (enc *encoder) DecodeUint(pt *Plaintext, verif *Poly, coeffs []uint64) {
	ms := enc.verifyUint(pt, verif)
	for i := 0; i < enc.params.NSlots; i++ {
		idx := i * enc.params.NumReplications
		coeffs[i] = ms[idx]
		for j := 0; j < enc.params.NumReplications; j++ {
			idx = i*enc.params.NumReplications + j
			if coeffs[i] != ms[idx] {
				panic(fmt.Errorf("verification failed on result #%d (replication slots %d and %d) this should have been caught during the decoding VC checks\n", i, i*enc.params.NumReplications, idx))
			}
		}
	}
	if VERBOSE {
		log.Println("verification successful")
	}
}

func (enc *encoder) DecodeUintNew(pt *Plaintext, verif *Poly) []uint64 {
	coeffs := make([]uint64, enc.params.N())
	enc.DecodeUint(pt, verif, coeffs)
	return coeffs
}

func (enc *encoder) DecodeInt(pt *Plaintext, verif *Poly, coeffs []int64) {
	ms := enc.verifyInt(pt, verif)
	for i := 0; i < enc.params.NSlots; i++ {
		idx := i * enc.params.NumReplications
		coeffs[i] = ms[idx]
		for j := 0; j < enc.params.NumReplications; j++ {
			idx = i*enc.params.NumReplications + j
			if coeffs[i] != ms[idx] {
				panic(fmt.Errorf("verification failed on result #%d (replication slots %d and %d) (this should have been caught during the decoding VC checks)\n", i, i*enc.params.NumReplications, idx))
			}
		}
	}
	if VERBOSE {
		log.Println("verification successful")
	}
}

func (enc *encoder) DecodeIntNew(pt *Plaintext, verif *Poly) []int64 {
	coeffs := make([]int64, enc.params.N())
	enc.DecodeInt(pt, verif, coeffs)
	return coeffs
}

func (enc *encoder) PRF(replicationIndex int, xs ...interface{}) uint64 {
	if enc.useClosedFormPRF {
		return vche.PRFEfficient(enc.xofs1[replicationIndex], enc.xofs2[replicationIndex], enc.params.T(), xs...)
	} else {
		return vche.PRF(enc.xofs1[replicationIndex], enc.params.T(), xs...)
	}
}
