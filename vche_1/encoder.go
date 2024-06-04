package vche_1

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"veritas/vche/vche"
	"golang.org/x/crypto/blake2b"
	"log"
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
	DecodeUint(pt *Plaintext, verif *TaggedPoly, coeffs []uint64)
	DecodeUintNew(pt *Plaintext, verif *TaggedPoly) (coeffs []uint64)
	DecodeInt(pt *Plaintext, verif *TaggedPoly, coeffs []int64)
	DecodeIntNew(pt *Plaintext, verif *TaggedPoly) (coeffs []int64)
	PRF(rxs ...interface{}) uint64
}

type encoder struct {
	bfv.Encoder
	params           Parameters
	K                vche.PRFKey
	S                DummySet
	useClosedFormPRF bool
	xof1, xof2       blake2b.XOF
}

func NewEncoder(params Parameters, K vche.PRFKey, S DummySet, useClosedFormPRF bool) Encoder {
	return &encoder{bfv.NewEncoder(params.Parameters), params, K, S, useClosedFormPRF, vche.NewXOF(K.K1), vche.NewXOF(K.K2)}
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

	// Set plaintext slots to duplicated coeffs or dummy values
	internalCoeffs := make([]uint64, enc.params.N())
	for i := 0; i < len(coeffs); i++ {
		for j := 0; j < enc.params.NumReplications; j++ {
			idx := i*enc.params.NumReplications + j
			if enc.S[j] {
				internalCoeffs[idx] = enc.PRF(tags[i], uint64(j))
			} else {
				internalCoeffs[idx] = coeffs[i]
			}
		}
	}
	return internalCoeffs
}

func (enc *encoder) encodeIntCoeffs(coeffs []int64, tags []vche.Tag) []int64 {
	enc.checkLengths(coeffs, tags)

	// Set plaintext slots to duplicated coeffs or dummy values
	internalCoeffs := make([]int64, enc.params.N())
	for i := 0; i < len(coeffs); i++ {
		for j := 0; j < enc.params.NumReplications; j++ {
			idx := i*enc.params.NumReplications + j
			if enc.S[j] {
				internalCoeffs[idx] = int64(enc.PRF(tags[i], uint64(j)))
			} else {
				internalCoeffs[idx] = coeffs[i]
			}
		}
	}
	return internalCoeffs
}

func (enc *encoder) encodeTags(tags []vche.Tag) [][]byte {
	// Set randomness used from the tags for each message
	vs := make([][]byte, len(tags))
	for i, tI := range tags {
		vs[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(vs[i], enc.PRF(tI))
	}
	return vs
}

func (enc *encoder) EncodeUint(coeffs []uint64, tags []vche.Tag, pt *Plaintext) {
	enc.Encoder.EncodeUint(enc.encodeUintCoeffs(coeffs, tags), pt.Plaintext)
	pt.tags = enc.encodeTags(tags)
}

func (enc *encoder) EncodeUintNew(coeffs []uint64, tags []vche.Tag) (pt *Plaintext) {
	pt = NewPlaintext(enc.params)
	enc.EncodeUint(coeffs, tags, pt)
	return pt
}

func (enc *encoder) EncodeUintMul(coeffs []uint64, tags []vche.Tag, pt *PlaintextMul) {
	enc.Encoder.EncodeUintMul(enc.encodeUintCoeffs(coeffs, tags), pt.PlaintextMul)
	pt.tags = enc.encodeTags(tags)
}

func (enc *encoder) EncodeUintMulNew(coeffs []uint64, tags []vche.Tag) (pt *PlaintextMul) {
	pt = NewPlaintextMul(enc.params)
	enc.EncodeUintMul(coeffs, tags, pt)
	return pt
}

func (enc *encoder) EncodeInt(coeffs []int64, tags []vche.Tag, pt *Plaintext) {
	enc.Encoder.EncodeInt(enc.encodeIntCoeffs(coeffs, tags), pt.Plaintext)
	pt.tags = enc.encodeTags(tags)
}

func (enc *encoder) EncodeIntNew(coeffs []int64, tags []vche.Tag) (pt *Plaintext) {
	pt = NewPlaintext(enc.params)
	enc.EncodeInt(coeffs, tags, pt)
	return pt
}

func (enc *encoder) EncodeIntMul(coeffs []int64, tags []vche.Tag, pt *PlaintextMul) {
	enc.Encoder.EncodeIntMul(enc.encodeIntCoeffs(coeffs, tags), pt.PlaintextMul)
	pt.tags = enc.encodeTags(tags)
}

func (enc *encoder) EncodeIntMulNew(coeffs []int64, tags []vche.Tag) (pt *PlaintextMul) {
	pt = NewPlaintextMul(enc.params)
	enc.EncodeIntMul(coeffs, tags, pt)
	return pt
}

func (enc *encoder) verifyUint(pt *Plaintext, verifPtxt *TaggedPoly) []uint64 {
	// Check that recomputed tags match
	if len(pt.tags) != len(verifPtxt.tags) {
		panic(fmt.Errorf("verification failed due to mismatched tags (different lengths)"))
	}
	for i := range pt.tags {
		if pt.tags[i] == nil || verifPtxt.tags[i] == nil || !bytes.Equal(pt.tags[i], verifPtxt.tags[i]) {
			panic(fmt.Errorf("verification failed due to mismatched tags"))
		}
	}

	// Decode on a copy, as BFV changes the plaintext during decoding
	cp := bfv.NewPlaintext(enc.params.Parameters)
	cp.Plaintext.Copy(pt.Plaintext.Plaintext)
	ms := enc.Encoder.DecodeUintNew(cp)
	dummies := verifPtxt.Poly.Coeffs[0]

	for i := 0; i < enc.params.NSlots; i++ {
		var expected *uint64 = nil
		for j := 0; j < enc.params.NumReplications; j++ {
			if enc.S[j] {
				idx := i*enc.params.NumReplications + j
				if ms[idx] != dummies[idx] {
					panic(fmt.Errorf("verification failed due to mismatch in %d (i=%d, j=%d)-th evaluated dummies: got %d, expected %d\n", idx, i, j, dummies[idx], ms[idx]))
				}
			} else { // Verify that duplicated messages evaluate to the same value
				idx := i*enc.params.NumReplications + j
				if expected == nil {
					expected = &ms[idx]
				} else if ms[idx] != *expected {
					panic(fmt.Errorf("verification failed due to mismatch between duplicated values"))
				}
			}
		}
	}
	if VERBOSE {
		log.Println("verification successful")
	}
	return ms
}

func (enc *encoder) verifyInt(pt *Plaintext, verifPtxt *TaggedPoly) []int64 {
	cp := bfv.NewPlaintext(enc.params.Parameters)
	cp.Plaintext.Copy(pt.Plaintext.Plaintext)
	enc.verifyUint(pt, verifPtxt)
	return enc.Encoder.DecodeIntNew(cp)
}

func (enc *encoder) DecodeUint(pt *Plaintext, verifPtxt *TaggedPoly, coeffs []uint64) {
	ms := enc.verifyUint(pt, verifPtxt)

	for i := 0; i < enc.params.NSlots; i++ {
		for j := 0; j < enc.params.NumReplications; j++ {
			if !enc.S[j] {
				idx := i*enc.params.NumReplications + j
				coeffs[i] = ms[idx]
				break
			}
		}
	}
}

func (enc *encoder) DecodeUintNew(pt *Plaintext, verifPtxt *TaggedPoly) []uint64 {
	coeffs := make([]uint64, enc.params.NSlots)
	enc.DecodeUint(pt, verifPtxt, coeffs)
	return coeffs
}

func (enc *encoder) DecodeInt(pt *Plaintext, verifPtxt *TaggedPoly, coeffs []int64) {
	ms := enc.verifyInt(pt, verifPtxt)

	for i := 0; i < enc.params.NSlots; i++ {
		for j := 0; j < enc.params.NumReplications; j++ {
			if !enc.S[j] {
				idx := i*enc.params.NumReplications + j
				coeffs[i] = ms[idx]
				break
			}
		}
	}
}

func (enc *encoder) DecodeIntNew(pt *Plaintext, verifPtxt *TaggedPoly) []int64 {
	coeffs := make([]int64, enc.params.NSlots)
	enc.DecodeInt(pt, verifPtxt, coeffs)
	return coeffs
}

func (enc *encoder) PRF(xs ...interface{}) uint64 {
	if enc.useClosedFormPRF {
		return vche.PRFEfficient(enc.xof1, enc.xof2, enc.params.T(), xs...)
	} else {
		return vche.PRF(enc.xof1, enc.params.T(), xs...)
	}
}
