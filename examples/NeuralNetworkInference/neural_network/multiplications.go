package neural_network

import (
	"veritas/vche/vche"
	"github.com/stretchr/testify/require"
	"math"
)

type MulConvolutionRowMajor struct {
	Model
	W            [][][]uint64
	b            []interface{}
	bVerif       []interface{}
	inScale      uint64
	weightsScale uint64
}

func NewMulConvolutionRowMajor(m Model, inScale uint64, weightsScale uint64, numKernelMaps, kernelSize, stride, paddingUp int, WVec []float64, bVec []float64, bTag []byte) MulConvolutionRowMajor {
	// Convert weights to uint64 with scaling
	kernelsFlat := Rescale(m.Parameters(), WVec, weightsScale)
	W := Reshape3D(kernelsFlat, numKernelMaps, kernelSize, kernelSize)

	// Convert biases
	b := Rescale(m.Parameters(), bVec, weightsScale*inScale) // bias scaled by outputScale

	h := 28
	w := 28

	bCtxt := make([]interface{}, numKernelMaps)
	bVerif := make([]interface{}, numKernelMaps)
	hMsg := ((h - kernelSize + paddingUp) / stride) + 1
	wMsg := ((w - kernelSize + paddingUp) / stride) + 1
	for mapIdx := 0; mapIdx < numKernelMaps; mapIdx++ {
		coeffs := make([]uint64, m.Parameters().NSlots)
		for i := 0; i < hMsg; i++ {
			for j := 0; j < wMsg; j++ {
				coeffs[i*wMsg+j] = b[mapIdx]
			}
		}
		tags := vche.GetIndexTags(bTag, m.Parameters().NSlots)
		bCtxt[mapIdx] = m.Encryptor().EncryptNew(m.Encoder().EncodeUintNew(coeffs, tags))
		if m.EvaluatorPlaintext() != nil {
			bVerif[mapIdx] = m.EncoderPlaintext().EncodeNew(tags)
		}
	}

	return MulConvolutionRowMajor{
		Model:        m,
		W:            W,
		b:            bCtxt,
		bVerif:       bVerif,
		inScale:      inScale,
		weightsScale: weightsScale,
	}
}

func (l MulConvolutionRowMajor) Eval(inInterface interface{}) interface{} {
	in := inInterface.([]interface{})

	kernelSize := len(l.W[0])

	resArr := make([]interface{}, len(l.W))
	for mapIdx := 0; mapIdx < len(l.W); mapIdx++ {
		resArr[mapIdx] = nil
		for i := 0; i < kernelSize; i++ {
			for j := 0; j < kernelSize; j++ {
				currCtxt := l.Evaluator().CopyNew(in[i*kernelSize+j])

				l.Evaluator().MulScalar(currCtxt, l.W[mapIdx][i][j], currCtxt)

				if resArr[mapIdx] == nil {
					resArr[mapIdx] = currCtxt
				} else {
					l.Evaluator().Add(currCtxt, resArr[mapIdx], resArr[mapIdx])
				}
			}
		}

		l.Evaluator().Add(resArr[mapIdx], l.b[mapIdx], resArr[mapIdx])
	}
	return resArr
}

func (l MulConvolutionRowMajor) Verif(inInterface interface{}) interface{} {
	in := inInterface.([]interface{})

	kernelSize := len(l.W[0])

	resArr := make([]interface{}, len(l.W))
	for mapIdx := 0; mapIdx < len(l.W); mapIdx++ {
		resArr[mapIdx] = nil
		for i := 0; i < kernelSize; i++ {
			for j := 0; j < kernelSize; j++ {
				currCtxt := l.EvaluatorPlaintext().CopyNew(in[i*kernelSize+j])

				l.EvaluatorPlaintext().MulScalar(currCtxt, l.W[mapIdx][i][j], currCtxt)

				if resArr[mapIdx] == nil {
					resArr[mapIdx] = currCtxt
				} else {
					l.EvaluatorPlaintext().Add(currCtxt, resArr[mapIdx], resArr[mapIdx])
				}
			}
		}

		l.EvaluatorPlaintext().Add(resArr[mapIdx], l.bVerif[mapIdx], resArr[mapIdx])
	}
	return resArr
}

func (l MulConvolutionRowMajor) OutputScale() uint64 {
	return l.inScale * l.weightsScale
}

////////////////////////////////////

type Square struct {
	Model
	inScale uint64
}

func NewSquareLayer(m Model, inScale uint64) Square {
	return Square{
		Model:   m,
		inScale: inScale,
	}
}

func (l Square) Eval(in interface{}) interface{} {
	return l.Evaluator().RelinearizeNew(l.Evaluator().MulNew(in, in))
}
func (l Square) Verif(in interface{}) interface{} {
	return l.EvaluatorPlaintext().RelinearizeNew(l.EvaluatorPlaintext().MulNew(in, in))
}

func (l Square) OutputScale() uint64 {
	return l.inScale * l.inScale
}

///////////////////////////////////

type MulStacked struct {
	Model
	inScale          uint64
	weightsScale     uint64
	slotSize         int
	numRowsPerVector int
	numVectors       int
	W                []interface{}
	WVerif           []interface{}
	b                []interface{}
	bVerif           []interface{}
	mask             interface{}
	maskVerif        interface{}
}

func NewMulStackedMult(m Model, inScale, weightsScale uint64, inSize, outSize int, WVec, bVec []float64, wTag, bTag, maskTag []byte) MulStacked {
	W := Reshape2D(Rescale(m.Parameters(), WVec, weightsScale), outSize, inSize)
	b := Rescale(m.Parameters(), bVec, weightsScale*inScale)

	// reshape w as 13 x (845*8) (or rather, 13 x (1024*8), with padding)
	// 13 = ceil(100 / 8)
	// Reshape a outSize x inSize matrix into numVectors x numRowsPerVector matrix (with padding)
	slotSize := nextPow2(inSize)
	numRowsPerVector := m.Parameters().NSlots / slotSize
	numVectors := outSize / numRowsPerVector

	// Weights
	WStacked := make([][]uint64, numVectors)
	idx := 0
	for i := range WStacked {
		WStacked[i] = make([]uint64, m.Parameters().NSlots)
		for j := 0; j < 8; j++ {
			if idx < len(W) {
				copy(WStacked[i][j*slotSize:j*slotSize+inSize], W[idx])
			}
			idx++
		}
	}

	WCtxt := make([]interface{}, len(WStacked))
	WVerif := make([]interface{}, len(WStacked))
	for i := range WStacked {
		tags := vche.GetIndexTags(wTag, m.Parameters().NSlots)
		WCtxt[i] = m.Encryptor().EncryptNew(m.Encoder().EncodeUintNew(WStacked[i], tags))
		if m.EvaluatorPlaintext() != nil {
			WVerif[i] = m.EncoderPlaintext().EncodeNew(tags)
		}
	}

	// Bias
	bStacked := make([][]uint64, len(WStacked))
	for stackIdx := range bStacked {
		biasStacked := make([]uint64, m.Parameters().NSlots)
		idx := 0
		for i := 0; i < 8; i++ {
			// Only need bias in first index of 1024-sized chunks, since all other indices of a chunk will contain garbage after the inner sum
			biasStacked[i*slotSize] = b[idx]
			idx++
		}
		bStacked[stackIdx] = biasStacked
	}

	bCtxt := make([]interface{}, len(bStacked))
	bVerif := make([]interface{}, len(bStacked))
	for i := range bCtxt {
		tags := vche.GetIndexTags(bTag, m.Parameters().NSlots)
		bCtxt[i] = m.Encryptor().EncryptNew(m.Encoder().EncodeUintNew(bStacked[i], tags))
		if m.EvaluatorPlaintext() != nil {
			bVerif[i] = m.EncoderPlaintext().EncodeNew(tags)
		}
	}

	// Compute mask to be applied after inner sum
	maskCoeffs := make([]uint64, m.Parameters().NSlots)
	for i := 0; i < 8; i++ {
		maskCoeffs[i*slotSize] = 1
	}
	tags := vche.GetIndexTags(maskTag, m.Parameters().NSlots)
	mask := m.Encryptor().EncryptNew(m.Encoder().EncodeUintNew(maskCoeffs, tags))
	var maskVerif interface{}
	if m.EvaluatorPlaintext() != nil {
		maskVerif = m.EncoderPlaintext().EncodeNew(tags)
	}
	return MulStacked{
		Model:            m,
		inScale:          inScale,
		weightsScale:     weightsScale,
		W:                WCtxt,
		WVerif:           WVerif,
		b:                bCtxt,
		bVerif:           bVerif,
		mask:             mask,
		maskVerif:        maskVerif,
		slotSize:         slotSize,
		numRowsPerVector: numRowsPerVector,
		numVectors:       numVectors,
	}
}

func (l MulStacked) Eval(inInterface interface{}) interface{} {
	in := inInterface.(interface{})

	res := make([]interface{}, l.numVectors)

	for i, wI := range l.W {
		res[i] = l.Evaluator().RelinearizeNew(l.Evaluator().MulNew(in, wI))

		tmp := l.Evaluator().CopyNew(res[i])      // Create new ciphertext with same degree
		for r := 1; r <= l.slotSize>>1; r <<= 1 { // rotate by 1, 2, ..., slotSize/2 (to the left)
			l.Evaluator().RotateColumns(res[i], r, tmp)
			l.Evaluator().Add(res[i], tmp, res[i])
		}
		// correct result of dot products is held in res[i][x * slotSize] for x = 0, ..., 7; all other entries hold garbage

		// Apply mask
		l.Evaluator().Mul(res[i], l.mask, res[i])

		// Add bias
		l.Evaluator().Add(res[i], l.b[i], res[i])
	}
	return res
}

func (l MulStacked) Verif(inInterface interface{}) interface{} { // []Interleaved {
	in := inInterface.(interface{})

	res := make([]interface{}, l.numVectors)

	for i, wI := range l.WVerif {
		res[i] = l.EvaluatorPlaintext().RelinearizeNew(l.EvaluatorPlaintext().MulNew(in, wI))

		tmp := l.EvaluatorPlaintext().CopyNew(res[i])
		for r := 1; r <= l.slotSize>>1; r <<= 1 { // rotate by 1, 2, ..., slotSize/2 (to the left)
			l.EvaluatorPlaintext().RotateColumns(res[i], r, tmp)
			l.EvaluatorPlaintext().Add(res[i], tmp, res[i])
		}
		// correct result of dot products is held in res[i][x * slotSize] for x = 0, ..., 7; all other entries hold garbage

		// Apply mask
		l.EvaluatorPlaintext().Mul(res[i], l.maskVerif, res[i])

		// Add bias
		l.EvaluatorPlaintext().Add(res[i], l.bVerif[i], res[i])
	}
	return res
}

func (l MulStacked) OutputScale() uint64 {
	return l.inScale * l.weightsScale
}

//////////////////////

type MulInterleaved struct {
	Model
	inScale           uint64
	weightsScale      uint64
	outSize           int
	numSlotsPerVector int
	numVectors        int
	slotSize          int
	W                 []interface{}
	WVerif            []interface{}
	b                 []interface{}
	bVerif            []interface{}
}

func NewMulInterleaved(m Model, inScale uint64, weightsScale uint64, inSize, outSize int, WVec, bVec []float64, wTag, bTag []byte) MulInterleaved {
	W := Reshape2D(Rescale(m.Parameters(), WVec, weightsScale), outSize, inSize)
	b := Rescale(m.Parameters(), bVec, weightsScale*inScale)
	if len(b) != outSize {
		panic("wrong dimensions")
	}

	numVectors := 13
	numSlotsPerVector := int(math.Ceil(float64(inSize) / float64(numVectors)))
	require.Equal(nil, numSlotsPerVector, 8)
	slotSize := 1024

	WCtxt := make([]interface{}, len(W))
	WVerif := make([]interface{}, len(W))
	for r := range W {
		idx := 0
		rowCoeffs := make([]uint64, m.Parameters().NSlots)
		for i := 0; i < numSlotsPerVector; i++ {
			for j := 0; j < numVectors; j++ {
				if idx < len(W[r]) {
					rowCoeffs[i*slotSize+j] = W[r][idx]
					idx++
				}
			}
		}

		tags := vche.GetIndexTags(wTag, m.Parameters().NSlots)
		WCtxt[r] = m.Encryptor().EncryptNew(m.Encoder().EncodeUintNew(rowCoeffs, tags))
		if m.EvaluatorPlaintext() != nil {
			WVerif[r] = m.EncoderPlaintext().EncodeNew(tags)
		}
	}

	bCtxt := make([]interface{}, len(b))
	bVerif := make([]interface{}, len(b))
	for r := range bCtxt {
		biasCoeffs := make([]uint64, m.Parameters().NSlots)
		biasCoeffs[0] = b[r]
		tags := vche.GetIndexTags(bTag, m.Parameters().NSlots)
		bCtxt[r] = m.Encryptor().EncryptNew(m.Encoder().EncodeUintNew(biasCoeffs, tags))
		if m.EvaluatorPlaintext() != nil {
			bVerif[r] = m.EncoderPlaintext().EncodeNew(tags)
		}
	}

	return MulInterleaved{
		Model:             m,
		inScale:           inScale,
		weightsScale:      weightsScale,
		W:                 WCtxt,
		WVerif:            WVerif,
		b:                 bCtxt,
		bVerif:            bVerif,
		outSize:           outSize,
		slotSize:          slotSize,
		numSlotsPerVector: numSlotsPerVector,
		numVectors:        numVectors,
	}
}

func (l MulInterleaved) Eval(inInterface interface{}) interface{} {
	var in = inInterface.(interface{})

	// shuffle the columns of the weight matrix to match the permutation of the interleaved repr.
	res := make([]interface{}, l.outSize)
	for r := range l.W {
		mult := l.Evaluator().MulNew(in, l.W[r])
		mult = l.Evaluator().RelinearizeNew(mult)

		// InnerSum

		// Add everything into (v_1, ..., v_numVectors, 0, ..., 0)
		rot := l.Evaluator().CopyNew(mult)
		for k := 1; k < l.numSlotsPerVector; k++ { // TODO: we can save some rotations here
			l.Evaluator().RotateColumns(rot, l.slotSize, rot)
			l.Evaluator().Add(mult, rot, mult)
		}

		// InnerSum on (v_1, ..., v_numVectors, 0, ..., 0) => (sum, garbage_2, ..., garbage_numVectors, 0, ..., 0)
		numVectorsPow2 := nextPow2(l.numVectors)
		for k := 1; k <= numVectorsPow2>>1; k <<= 1 {
			l.Evaluator().RotateColumns(mult, k, rot)
			l.Evaluator().Add(mult, rot, mult)
		}
		res[r] = mult

		// Add bias
		l.Evaluator().Add(res[r], l.b[r], res[r])
	}
	return res
}

func (l MulInterleaved) Verif(inInterface interface{}) interface{} { //[]Sparse {
	var in = inInterface.(interface{})

	// shuffle the columns of the weight matrix to match the permutation of the interleaved repr.
	res := make([]interface{}, l.outSize)
	for r := range l.W {
		mult := l.EvaluatorPlaintext().MulNew(in, l.WVerif[r])
		mult = l.EvaluatorPlaintext().RelinearizeNew(mult)

		// InnerSum

		// Add everything into (v_1, ..., v_numVectors, 0, ..., 0)
		rot := l.EvaluatorPlaintext().CopyNew(mult)
		for k := 1; k < l.numSlotsPerVector; k++ { // TODO: we can save some rotations here
			l.EvaluatorPlaintext().RotateColumns(rot, l.slotSize, rot)
			l.EvaluatorPlaintext().Add(mult, rot, mult)
		}

		// InnerSum on (v_1, ..., v_numVectors, 0, ..., 0) => (sum, garbage_2, ..., garbage_numVectors, 0, ..., 0)
		numVectorsPow2 := nextPow2(l.numVectors)
		for k := 1; k <= numVectorsPow2>>1; k <<= 1 {
			l.EvaluatorPlaintext().RotateColumns(mult, k, rot)
			l.EvaluatorPlaintext().Add(mult, rot, mult)
		}
		res[r] = mult

		// Add bias
		l.EvaluatorPlaintext().Add(res[r], l.bVerif[r], res[r])
	}
	return res
}

func (l MulInterleaved) OutputScale() uint64 {
	return l.inScale * l.weightsScale
}

//////////////////////////////////////

type MulDense struct {
	Model
	inScale      uint64
	weightsScale uint64
	inSize       int
	outSize      int
	W            []interface{}
	WVerif       []interface{}
	b            []interface{}
	bVerif       []interface{}
}

func NewMulDense(m Model, inScale uint64, weightsScale uint64, inSize, outSize int, WVec, bVec []float64, wTag, bTag []byte) MulDense {
	W := Reshape2D(Rescale(m.Parameters(), WVec, weightsScale), outSize, inSize)
	b := Rescale(m.Parameters(), bVec, weightsScale*inScale)
	if len(b) != outSize {
		panic("wrong dimensions")
	}

	WCtxt := make([]interface{}, len(W))
	WVerif := make([]interface{}, len(W))
	for r := range W {
		rowCoeffs := make([]uint64, m.Parameters().NSlots)
		for i := range W[r] {
			rowCoeffs[i] = W[r][i]
		}
		tags := vche.GetIndexTags(wTag, m.Parameters().NSlots)
		WCtxt[r] = m.Encryptor().EncryptNew(m.Encoder().EncodeUintNew(rowCoeffs, tags))
		if m.EvaluatorPlaintext() != nil {
			WVerif[r] = m.EncoderPlaintext().EncodeNew(tags)
		}
	}

	bCtxt := make([]interface{}, len(b))
	bVerif := make([]interface{}, len(b))
	for r := range W {
		biasCoeffs := make([]uint64, m.Parameters().NSlots)
		for i := range biasCoeffs {
			biasCoeffs[i] = b[r]
		}
		tags := vche.GetIndexTags(bTag, m.Parameters().NSlots)
		bCtxt[r] = m.Encryptor().EncryptNew(m.Encoder().EncodeUintNew(biasCoeffs, tags))
		if m.EvaluatorPlaintext() != nil {
			bVerif[r] = m.EncoderPlaintext().EncodeNew(tags)
		}
	}
	return MulDense{
		Model:        m,
		inScale:      inScale,
		weightsScale: weightsScale,
		W:            WCtxt,
		WVerif:       WVerif,
		b:            bCtxt,
		bVerif:       bVerif,
		inSize:       inSize,
		outSize:      outSize,
	}
}

func (l MulDense) Eval(in interface{}) interface{} {
	res := make([]interface{}, l.outSize)
	for r := range l.W {
		mult := l.Evaluator().MulNew(in, l.W[r])
		mult = l.Evaluator().RelinearizeNew(mult)

		// InnerSum
		rot := l.Evaluator().CopyNew(mult)

		//InnerSum on (v_1, ..., v_inSize, 0, ..., 0) => (sum, garbage, ..., garbage, 0, ..., 0)
		slotSize := nextPow2(l.inSize)
		for k := 1; k <= slotSize>>1; k <<= 1 {
			l.Evaluator().RotateColumns(mult, k, rot)
			l.Evaluator().Add(mult, rot, mult)
		}
		res[r] = mult

		// Add bias
		l.Evaluator().Add(res[r], l.b[r], res[r])
	}
	return res
}

func (l MulDense) Verif(in interface{}) interface{} {
	res := make([]interface{}, l.outSize)
	for r := range l.WVerif {
		mult := l.EvaluatorPlaintext().MulNew(in, l.WVerif[r])
		mult = l.EvaluatorPlaintext().RelinearizeNew(mult)

		// InnerSum
		rot := l.EvaluatorPlaintext().CopyNew(mult)

		//InnerSum on (v_1, ..., v_inSize, 0, ..., 0) => (sum, garbage, ..., garbage, 0, ..., 0)
		slotSize := nextPow2(l.inSize)
		for k := 1; k <= slotSize>>1; k <<= 1 {
			l.EvaluatorPlaintext().RotateColumns(mult, k, rot)
			l.EvaluatorPlaintext().Add(mult, rot, mult)
		}
		res[r] = mult

		// Add bias
		l.EvaluatorPlaintext().Add(res[r], l.bVerif[r], res[r])
	}
	return res
}

func (l MulDense) OutputScale() uint64 {
	return l.inScale * l.weightsScale
}
