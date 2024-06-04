package bfv_generic

import (
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"veritas/vche/vche"
)

type encoder struct {
	bfv.Encoder
	params bfv.Parameters
}

func ptxt(x interface{}) *bfv.Plaintext {
	switch ptxt := x.(type) {
	case *bfv.Plaintext:
		return ptxt
	default:
		panic(fmt.Errorf("expected *Plaintext, got %T", ptxt))
	}
}

func ptxtMul(x interface{}) *bfv.PlaintextMul {
	switch ptxtMul := x.(type) {
	case *bfv.PlaintextMul:
		return ptxtMul
	default:
		panic(fmt.Errorf("expected *PlaintextMul, got %T", ptxtMul))
	}
}

func NewGenericEncoder(params bfv.Parameters) vche.GenericEncoder {
	return encoder{bfv.NewEncoder(params), params}
}

func (enc encoder) EncodeUint(coeffs []uint64, _ []vche.Tag, pt interface{}) {
	enc.Encoder.EncodeUint(coeffs, ptxt(pt))
}

func (enc encoder) EncodeUintNew(coeffs []uint64, _ []vche.Tag) (pt interface{}) {
	pt = bfv.NewPlaintext(enc.params)
	enc.Encoder.EncodeUint(coeffs, ptxt(pt))
	return pt
}

func (enc encoder) EncodeUintMul(coeffs []uint64, _ []vche.Tag, pt interface{}) {
	enc.Encoder.EncodeUintMul(coeffs, ptxtMul(pt))
}

func (enc encoder) EncodeUintMulNew(coeffs []uint64, _ []vche.Tag) (pt interface{}) {
	pt = bfv.NewPlaintextMul(enc.params)
	enc.Encoder.EncodeUintMul(coeffs, ptxtMul(pt))
	return pt
}

func (enc encoder) EncodeInt(coeffs []int64, _ []vche.Tag, pt interface{}) {
	enc.Encoder.EncodeInt(coeffs, ptxt(pt))
}

func (enc encoder) EncodeIntNew(coeffs []int64, _ []vche.Tag) (pt interface{}) {
	pt = bfv.NewPlaintext(enc.params)
	enc.Encoder.EncodeInt(coeffs, ptxt(pt))
	return pt
}

func (enc encoder) EncodeIntMul(coeffs []int64, _ []vche.Tag, pt interface{}) {
	enc.Encoder.EncodeIntMul(coeffs, ptxtMul(pt))
}

func (enc encoder) EncodeIntMulNew(coeffs []int64, _ []vche.Tag) (pt interface{}) {
	pt = bfv.NewPlaintextMul(enc.params)
	enc.Encoder.EncodeIntMul(coeffs, ptxtMul(pt))
	return pt
}

func (enc encoder) DecodeUint(pt interface{}, _ interface{}, coeffs []uint64) {
	enc.Encoder.DecodeUint(pt, coeffs)
}

func (enc encoder) DecodeUintNew(pt interface{}, _ interface{}) (coeffs []uint64) {
	return enc.Encoder.DecodeUintNew(pt)
}

func (enc encoder) DecodeInt(pt interface{}, _ interface{}, coeffs []int64) {
	enc.Encoder.DecodeInt(pt, coeffs)
}

func (enc encoder) DecodeIntNew(pt interface{}, _ interface{}) (coeffs []int64) {
	return enc.Encoder.DecodeIntNew(pt)
}
