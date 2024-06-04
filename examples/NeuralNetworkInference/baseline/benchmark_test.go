package bfv

import (
	"github.com/DmitriyVTitov/size"
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/rlwe"
	"veritas/vche/bfv_generic"
	"veritas/vche/examples/NeuralNetworkInference"
	"veritas/vche/examples/NeuralNetworkInference/neural_network"
	"veritas/vche/vche"
	"testing"
)

func Benchmark(b *testing.B) {
	params := NeuralNetworkInference.BfvParams

	vche.PrintCryptoParams(params)

	keygen := bfv.NewKeyGenerator(params)
	sk := keygen.GenSecretKey()

	rotKeys := keygen.GenRotationKeysForRotations(neural_network.RotsSmall, true, sk)
	relinKey := keygen.GenRelinearizationKey(sk, 1)
	evk := rlwe.EvaluationKey{Rlk: relinKey, Rtks: rotKeys}

	modelParams := neural_network.ModelParams{
		Encryptor:          bfv_generic.NewGenericEncryptor(params, sk),
		Decryptor:          bfv_generic.NewGenericDecryptor(params, sk),
		Encoder:            bfv_generic.NewGenericEncoder(params),
		EncoderVerif:       nil,
		Evaluator:          bfv_generic.NewGenericEvaluator(params, evk),
		EvaluatorPlaintext: nil,
		Parameters: vche.Parameters{
			Parameters:         params,
			NumReplications:    1,
			NSlots:             params.N(),
			NumDistinctPRFKeys: 1,
		},
	}

	model := neural_network.NewModelSmall(modelParams)

	img := NeuralNetworkInference.MNISTTestImages[0]
	tags := NeuralNetworkInference.GenTags(0, NeuralNetworkInference.MNISTTestLabels[0], 25, params.N())

	x := benchEnc(model, img, tags, b)

	res := benchEval(model, x, b)

	preds := benchDec(model, res, nil, b)

	NeuralNetworkInference.CheckResult(preds, NeuralNetworkInference.MNISTTestLabels[0])
}

func benchEnc(model neural_network.Model, img [][]uint64, tags [][]vche.Tag, b *testing.B) []interface{} {
	var x []interface{}

	b.Run(benchmarkString("Encode"), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			x = neural_network.Encode(model, img, tags)
		}
	})

	ctxts := make([]interface{}, len(x))
	for i := range ctxts {
		ctxts[i] = bfv.NewCiphertext(model.Parameters().Parameters, 1)
	}
	b.Run(benchmarkString("Encrypt"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			for i := range x {
				model.Encryptor().Encrypt(x[i], ctxts[i])
			}
		}
	})

	b.Run(benchmarkString("Communication/Client->SP"), func(b *testing.B) {
		b.ReportMetric(float64(len(ctxts)), "BFV-ctxt")
		b.ReportMetric(float64(size.Of(ctxts)), "bytes")
		b.ReportMetric(0.0, "ns/op")
	})

	return ctxts
}

func benchEval(model neural_network.Model, x []interface{}, b *testing.B) []interface{} {
	var res []interface{}
	b.Run(benchmarkString("Eval"), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			res = neural_network.Eval(model, x)

		}
	})
	return res
}

func benchDec(model neural_network.Model, res []interface{}, verif []interface{}, b *testing.B) []float64 {
	b.Run(benchmarkString("Communication/SP->Client"), func(b *testing.B) {
		b.ReportMetric(float64(len(res)), "BFV-ctxt")
		b.ReportMetric(float64(size.Of(res)), "bytes")
		b.ReportMetric(0.0, "ns/op")
	})

	var ptxts = make([]*bfv.Plaintext, len(res))
	for i := range ptxts {
		ptxts[i] = bfv.NewPlaintext(model.Parameters().Parameters)
	}
	var values = make([][]int64, len(res))
	for i := range values {
		values[i] = make([]int64, model.Parameters().NSlots)
	}

	b.Run(benchmarkString("Decrypt"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			for i := range res {
				model.Decryptor().Decrypt(res[i], ptxts[i])
			}
		}
	})

	ptxtCopies := make([]*bfv.Plaintext, len(ptxts))
	for i := range ptxts {
		ptxtCopies[i] = bfv.NewPlaintext(model.Parameters().Parameters)
		ptxtCopies[i].Plaintext.Copy(ptxts[i].Plaintext)
	}

	b.Run(benchmarkString("Decode"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			for i := range res {
				model.Encoder().DecodeInt(ptxts[i], nil, values[i])
			}
		}
	})

	for i := range res {
		model.Encoder().DecodeInt(ptxtCopies[i], nil, values[i])
	}

	preds := make([]float64, len(res))
	outScale := model.EvalLayers()[len(model.EvalLayers())-1].OutputScale()

	for i := range values {
		preds[i] = float64(values[i][0]) / float64(outScale)
	}
	return preds
}

func benchmarkString(opname string) string {
	return "BFV/" + opname
}
