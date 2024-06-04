package vche

type GenericEncoder interface {
	EncodeUint(coeffs []uint64, tags []Tag, pt interface{})
	EncodeUintNew(coeffs []uint64, tags []Tag) (pt interface{})
	EncodeInt(coeffs []int64, tags []Tag, pt interface{})
	EncodeIntNew(coeffs []int64, tags []Tag) (pt interface{})
	EncodeUintMul(coeffs []uint64, tags []Tag, pt interface{})
	EncodeUintMulNew(coeffs []uint64, tags []Tag) (pt interface{})
	EncodeIntMul(coeffs []int64, tags []Tag, pt interface{})
	EncodeIntMulNew(coeffs []int64, tags []Tag) (pt interface{})
	DecodeUint(pt interface{}, verif interface{}, coeffs []uint64)
	DecodeUintNew(pt interface{}, verif interface{}) (coeffs []uint64)
	DecodeInt(pt interface{}, verif interface{}, coeffs []int64)
	DecodeIntNew(pt interface{}, verif interface{}) (coeffs []int64)
}

type GenericEncoderPlaintext interface {
	Encode(tags []Tag, p interface{})
	EncodeNew(tags []Tag) interface{}
}
