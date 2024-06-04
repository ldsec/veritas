package neural_network

import (
	"veritas/vche/vche"
)

const imgScale = uint64(2)
const weightsScale = uint64(2)

type ModelMNIST struct {
	vche.GenericEncoder
	vche.GenericEncoderPlaintext

	vche.GenericEncryptor
	vche.GenericDecryptor
	evaluator          vche.GenericEvaluator
	evaluatorPlaintext vche.GenericEvaluator
	params             vche.Parameters
	encodeLayer        Layer
	evalLayers         []Layer
}

var Rots = []int{
	-1 * 169, -2 * 169, -3 * 169, -4 * 169, // CombineDense
	-1024,                                 // Stacker
	1, 2, 4, 8, 16, 32, 64, 128, 256, 512, // MulStacked
	-1, -2, -3, -4, -5, -6, -7, -8, -9, -10, -11, -12, // CombineInterleaved
	1024, 1, 2, 4, 8, // MulInterleaved
}

func NewModel(modelParams ModelParams) ModelMNIST {
	m := ModelMNIST{
		GenericEncoder:          modelParams.Encoder,
		GenericEncoderPlaintext: modelParams.EncoderVerif,
		GenericEncryptor:        modelParams.Encryptor,
		GenericDecryptor:        modelParams.Decryptor,
		evaluator:               modelParams.Evaluator,
		evaluatorPlaintext:      modelParams.EvaluatorPlaintext,
		params:                  modelParams.Parameters,
		encodeLayer:             nil,
		evalLayers:              nil}

	l1 := NewEncodingLayer(m, 1.0/float64(256), imgScale, 5, 4, 1)

	lEnc := NewEncryptLayer(m, l1.OutputScale())

	l2 := NewMulConvolutionRowMajor(m, lEnc.OutputScale(), weightsScale, 5, 5, 4, 1, weightsConv, biasConv, []byte("bias-conv1"))
	l3 := NewCombineDense(m, l2.OutputScale())

	l4 := NewSquareLayer(m, l3.OutputScale())

	l5 := NewStacker(m, l4.OutputScale())
	l6 := NewMulStackedMult(m, l5.OutputScale(), weightsScale, 845, 100, weightsLin1, biasLin1, []byte("weight-fc1"), []byte("bias-fc1"), []byte("mask-fc1"))
	l7 := NewCombineInterleave(m, l6.OutputScale())

	l8 := NewSquareLayer(m, l7.OutputScale())

	l9 := NewMulInterleaved(m, l8.OutputScale(), weightsScale, 100, 10, weightsLin2, biasLin2, []byte("weight-fc2"), []byte("bias-fc2"))

	m.encodeLayer = l1
	m.evalLayers = []Layer{l2, l3, l4, l5, l6, l7, l8, l9}

	return m
}

func (m ModelMNIST) Encryptor() vche.GenericEncryptor {
	return m.GenericEncryptor
}

func (m ModelMNIST) Decryptor() vche.GenericDecryptor {
	return m.GenericDecryptor
}

func (m ModelMNIST) Encoder() vche.GenericEncoder {
	return m.GenericEncoder
}

func (m ModelMNIST) EncoderPlaintext() vche.GenericEncoderPlaintext {
	return m.GenericEncoderPlaintext
}

func (m ModelMNIST) Evaluator() vche.GenericEvaluator {
	return m.evaluator
}

func (m ModelMNIST) EvaluatorPlaintext() vche.GenericEvaluator {
	return m.evaluatorPlaintext
}

func (m ModelMNIST) Parameters() vche.Parameters { return m.params }

func (m ModelMNIST) EncodeLayer() Layer { return m.encodeLayer }

func (m ModelMNIST) EvalLayers() []Layer { return m.evalLayers }
