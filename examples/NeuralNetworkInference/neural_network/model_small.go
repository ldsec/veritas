package neural_network

import (
	"veritas/vche/vche"
)

const imgScaleSmall = uint64(4)
const weightsScaleSmall = uint64(128)

type ModelMNISTSmall struct {
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

var RotsSmall = []int{
	-1 * 169, -2 * 169, -3 * 169, -4 * 169, // CombineDense
	1, 2, 4, 8, 16, 32, 64, 128, 256, 512, // MulDense
}

func NewModelSmall(modelParams ModelParams) ModelMNISTSmall {
	m := ModelMNISTSmall{
		GenericEncoder:          modelParams.Encoder,
		GenericEncoderPlaintext: modelParams.EncoderVerif,
		GenericEncryptor:        modelParams.Encryptor,
		GenericDecryptor:        modelParams.Decryptor,
		evaluator:               modelParams.Evaluator,
		evaluatorPlaintext:      modelParams.EvaluatorPlaintext,
		params:                  modelParams.Parameters,
		encodeLayer:             nil,
		evalLayers:              nil}

	l1 := NewEncodingLayer(m, 1.0/float64(256), imgScaleSmall, 5, 4, 1)

	lEnc := NewEncryptLayer(m, l1.OutputScale())

	l2 := NewMulConvolutionRowMajor(m, lEnc.OutputScale(), weightsScaleSmall, 5, 5, 4, 1, weightsConvSmall, biasConvSmall, []byte("bias-conv1"))
	l3 := NewCombineDense(m, l2.OutputScale())

	l4 := NewSquareLayer(m, l3.OutputScale())

	l6 := NewMulDense(m, l4.OutputScale(), weightsScaleSmall, 245, 10, weightLinSmall, biasLinSmall, []byte("weight-fc1"), []byte("bias-fc1"))

	m.encodeLayer = l1
	m.evalLayers = []Layer{l2, l3, l4, l6}

	return m
}

func (m ModelMNISTSmall) Encryptor() vche.GenericEncryptor {
	return m.GenericEncryptor
}

func (m ModelMNISTSmall) Decryptor() vche.GenericDecryptor {
	return m.GenericDecryptor
}

func (m ModelMNISTSmall) Encoder() vche.GenericEncoder {
	return m.GenericEncoder
}

func (m ModelMNISTSmall) EncoderPlaintext() vche.GenericEncoderPlaintext {
	return m.GenericEncoderPlaintext
}

func (m ModelMNISTSmall) Evaluator() vche.GenericEvaluator {
	return m.evaluator
}

func (m ModelMNISTSmall) EvaluatorPlaintext() vche.GenericEvaluator {
	return m.evaluatorPlaintext
}

func (m ModelMNISTSmall) Parameters() vche.Parameters { return m.params }

func (m ModelMNISTSmall) EncodeLayer() Layer { return m.encodeLayer }

func (m ModelMNISTSmall) EvalLayers() []Layer { return m.evalLayers }
