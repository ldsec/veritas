package neural_network

import (
	"veritas/vche/vche"
	"math"
)

type EncodingLayer struct {
	Model
	normalizationFactor float64
	inScale             uint64
	params              vche.Parameters
	kernelSize          int
	stride              int
	paddingUp           int
}

func NewEncodingLayer(m Model, normalizationFactor float64, scale uint64, kernelSize, stride, paddingUp int) EncodingLayer {
	return EncodingLayer{
		Model:               m,
		normalizationFactor: normalizationFactor,
		inScale:             scale,
		params:              m.Parameters(),
		kernelSize:          kernelSize,
		stride:              stride,
		paddingUp:           paddingUp,
	}
}

func (e EncodingLayer) evalImg(in [][]uint64) [][]uint64 {
	// (1 x 28 x 28) -> Interleaved (25 x 169)

	// encode with upper padding = (1, 1)
	padded := make([][]uint64, len(in)+e.paddingUp)
	for i := 0; i < e.paddingUp; i++ {
		padded[i] = make([]uint64, len(in[0])+e.paddingUp)
	}

	for i := range in {
		padded[i+e.paddingUp] = make([]uint64, len(in[i])+e.paddingUp)
		for j := range in {
			scaled := uint64(float64(e.inScale) * (float64(in[i][j]) * e.normalizationFactor))
			padded[i+e.paddingUp][j+e.paddingUp] = scaled
		}
	}

	h := len(in)
	w := len(in[0])

	coeffs := make([][]uint64, e.kernelSize*e.kernelSize)
	hMsg := ((h - e.kernelSize + e.paddingUp) / e.stride) + 1
	wMsg := ((w - e.kernelSize + e.paddingUp) / e.stride) + 1
	for ki := 0; ki < e.kernelSize; ki++ {
		for kj := 0; kj < e.kernelSize; kj++ {
			kIdx := ki*e.kernelSize + kj
			coeffs[kIdx] = make([]uint64, e.params.NSlots) // N > hMsg*wMsg
			for i := 0; i < hMsg; i++ {
				for j := 0; j < wMsg; j++ {
					coeffs[kIdx][i*wMsg+j] = padded[i*e.stride+ki][j*e.stride+kj]
				}
			}
		}
	}
	//fmt.Printf("Packing 1 image into %d ctxts\n", len(coeffs))
	return coeffs
}

func (e EncodingLayer) evalTag(in [][]vche.Tag) [][]vche.Tag { //[]Convolution {
	return in
}

func (e EncodingLayer) Eval(inInterface interface{}) interface{} { //[]Convolution {
	pair := (inInterface).(struct {
		img [][]uint64
		tag [][]vche.Tag
	})
	coeffs := e.evalImg(pair.img)
	tags := e.evalTag(pair.tag)
	convs := make([]interface{}, len(coeffs))
	for i := range coeffs {
		convs[i] = e.Encoder().EncodeUintNew(coeffs[i], tags[i])
	}
	return convs
}

func (e EncodingLayer) Verif(inInterface interface{}) interface{} {
	tags := e.evalTag(inInterface.([][]vche.Tag))
	convs := make([]interface{}, len(tags))
	for i := range tags {
		convs[i] = e.EncoderPlaintext().EncodeNew(tags[i])
	}
	return convs
}

func (e EncodingLayer) OutputScale() uint64 {
	return e.inScale
}

/////////////////////////////////////////////7

type CombineDense struct {
	Model
	inScale uint64
}

func NewCombineDense(m Model, inScale uint64) CombineDense {
	return CombineDense{
		Model:   m,
		inScale: inScale,
	}
}

func (l CombineDense) Eval(inInterface interface{}) interface{} { //(in []Dense) Dense {
	in := inInterface.([]interface{})

	res := in[0]
	for i := 1; i < len(in); i++ {
		rot := l.Evaluator().RotateColumnsNew(in[i], -i*169)
		l.Evaluator().Add(res, rot, res)
	}

	return res
}

func (l CombineDense) Verif(inInterface interface{}) interface{} { //(in []Dense) Dense {
	in := inInterface.([]interface{})

	res := in[0]
	for i := 1; i < len(in); i++ {
		rot := l.EvaluatorPlaintext().RotateColumnsNew(in[i], -i*169)
		l.EvaluatorPlaintext().Add(res, rot, res)
	}

	return res
}

func (l CombineDense) OutputScale() uint64 {
	return l.inScale
}

////////////////////////////////////////////////

type Stacker struct {
	Model
	inScale uint64
}

func NewStacker(m Model, inScale uint64) Stacker {
	return Stacker{Model: m, inScale: inScale}
}

func (l Stacker) Eval(in interface{}) interface{} {
	inSize := 845
	numStacks := 8

	d := int(math.Ceil(math.Log2(float64(inSize))))
	PowD := 1 << d

	in = l.Evaluator().RelinearizeNew(in)
	stacked := l.Evaluator().CopyNew(in)
	for r := 1; r < numStacks; r++ {
		l.Evaluator().RotateColumns(in, -PowD, in)
		l.Evaluator().Add(stacked, in, stacked)
	}

	return stacked
}

func (l Stacker) Verif(in interface{}) interface{} {
	inSize := 845
	numStacks := 8

	d := int(math.Ceil(math.Log2(float64(inSize))))
	PowD := 1 << d

	stacked := l.EvaluatorPlaintext().CopyNew(in)
	for r := 1; r < numStacks; r++ {
		l.EvaluatorPlaintext().RotateColumns(in, -PowD, in)
		l.EvaluatorPlaintext().Add(stacked, in, stacked)
	}

	return stacked
}

func (l Stacker) OutputScale() uint64 {
	return l.inScale
}

/////////////////////

type CombineInterleave struct {
	Model
	inScale uint64
}

func NewCombineInterleave(m Model, inScale uint64) CombineInterleave {
	return CombineInterleave{
		Model:   m,
		inScale: inScale,
	}
}

func (l CombineInterleave) Eval(inInterface interface{}) interface{} { //Interleaved {
	in := inInterface.([]interface{})

	res := in[0]
	for i := 1; i < len(in); i++ {
		rot := l.Evaluator().RotateColumnsNew(in[i], -i)
		l.Evaluator().Add(res, rot, res)
	}

	// res = (a1, ..., a13, 0, ..., 0, b1, ..., b13, ...), with b1 at index 1024
	return res
}

func (l CombineInterleave) Verif(inInterface interface{}) interface{} { //Interleaved {
	in := inInterface.([]interface{})

	res := in[0]
	for i := 1; i < len(in); i++ {
		rot := l.EvaluatorPlaintext().RotateColumnsNew(in[i], -i)
		l.EvaluatorPlaintext().Add(res, rot, res)
	}

	// res = (a1, ..., a13, 0, ..., 0, b1, ..., b13, ...), with b1 at index 1024
	return res
}

func (l CombineInterleave) OutputScale() uint64 {
	return l.inScale
}

///////////////////////

type OutputLayer struct {
	Model
	inScale uint64
	verif   []interface{}
}

func NewOutputLayer(m Model, inScale uint64) OutputLayer {
	return OutputLayer{Model: m, inScale: inScale}
}

func (l OutputLayer) Eval(inInterface interface{}) interface{} { // []float64 {
	in := inInterface.([]interface{})
	preds := make([]float64, len(in))

	sum := 0.0
	for i := range in {
		ptxt := l.Decryptor().DecryptNew(in[i])
		vals := l.Encoder().DecodeIntNew(ptxt, l.verif[i])
		preds[i] = float64(vals[0]) / float64(l.inScale)
		sum += preds[i]
	}
	return preds
}

func (l OutputLayer) Verif(inInterface interface{}) interface{} {
	in := inInterface.([]interface{})
	return in
}

func (l OutputLayer) OutputScale() uint64 {
	return l.inScale
}

////////////////////

type EncryptLayer struct {
	Model
	inScale uint64
}

func NewEncryptLayer(m Model, inScale uint64) EncryptLayer {
	return EncryptLayer{m, inScale}
}

func (e EncryptLayer) Eval(inInterface interface{}) interface{} {
	in := inInterface.([]interface{})
	out := make([]interface{}, len(in))
	for i := range in {
		out[i] = e.Encryptor().EncryptNew(in[i])
	}
	return out
}

func (e EncryptLayer) Verif(inInterface interface{}) interface{} {
	in := inInterface.([]interface{})
	return in
}

func (e EncryptLayer) OutputScale() uint64 {
	return e.inScale
}
