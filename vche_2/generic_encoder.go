package vche_2

import (
	"fmt"
	"veritas/vche/vche"
)

type genericEncoder struct {
	Encoder
}

func NewGenericEncoder(params Parameters, K []vche.PRFKey, alphas []uint64, useClosedFormPRF bool) vche.GenericEncoder {
	return &genericEncoder{NewEncoder(params, K, alphas, useClosedFormPRF)}
}
func ptxt(x interface{}) *Plaintext {
	switch ptxt := x.(type) {
	case *Plaintext:
		return ptxt
	default:
		panic(fmt.Errorf("expected *Plaintext, got %T", ptxt))
	}
}

func ptxtMul(x interface{}) *PlaintextMul {
	switch ptxtMul := x.(type) {
	case *PlaintextMul:
		return ptxtMul
	default:
		panic(fmt.Errorf("expected *PlaintextMul, got %T", ptxtMul))
	}
}

func (enc *genericEncoder) EncodeUint(coeffs []uint64, tags []vche.Tag, pt interface{}) {
	enc.Encoder.EncodeUint(coeffs, tags, ptxt(pt))
}
func (enc *genericEncoder) EncodeUintNew(coeffs []uint64, tags []vche.Tag) (pt interface{}) {
	return enc.Encoder.EncodeUintNew(coeffs, tags)
}

func (enc *genericEncoder) EncodeUintMul(coeffs []uint64, tags []vche.Tag, pt interface{}) {
	enc.Encoder.EncodeUintMul(coeffs, tags, ptxtMul(pt))
}
func (enc *genericEncoder) EncodeUintMulNew(coeffs []uint64, tags []vche.Tag) (pt interface{}) {
	return enc.Encoder.EncodeUintMulNew(coeffs, tags)
}

func (enc *genericEncoder) EncodeInt(coeffs []int64, tags []vche.Tag, pt interface{}) {
	enc.Encoder.EncodeInt(coeffs, tags, ptxt(pt))
}

func (enc *genericEncoder) EncodeIntNew(coeffs []int64, tags []vche.Tag) (pt interface{}) {
	return enc.Encoder.EncodeIntNew(coeffs, tags)
}

func (enc *genericEncoder) EncodeIntMul(coeffs []int64, tags []vche.Tag, pt interface{}) {
	enc.Encoder.EncodeIntMul(coeffs, tags, ptxtMul(pt))
}

func (enc *genericEncoder) EncodeIntMulNew(coeffs []int64, tags []vche.Tag) (pt interface{}) {
	return enc.Encoder.EncodeIntMulNew(coeffs, tags)
}

func (enc *genericEncoder) DecodeUint(pt interface{}, verif interface{}, coeffs []uint64) {
	enc.Encoder.DecodeUint(ptxt(pt), ringPoly(verif), coeffs)
}

func (enc *genericEncoder) DecodeUintNew(pt interface{}, verif interface{}) []uint64 {
	return enc.Encoder.DecodeUintNew(ptxt(pt), ringPoly(verif))
}

func (enc *genericEncoder) DecodeInt(pt interface{}, verif interface{}, coeffs []int64) {
	enc.Encoder.DecodeInt(ptxt(pt), ringPoly(verif), coeffs)
}

func (enc *genericEncoder) DecodeIntNew(pt interface{}, verif interface{}) []int64 {
	return enc.Encoder.DecodeIntNew(ptxt(pt), ringPoly(verif))
}
