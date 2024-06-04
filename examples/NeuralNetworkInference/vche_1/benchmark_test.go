package vche_1

import (
	"github.com/DmitriyVTitov/size"
	"github.com/ldsec/lattigo/v2/rlwe"
	"veritas/vche/examples/NeuralNetworkInference"
	"veritas/vche/examples/NeuralNetworkInference/neural_network"
	"veritas/vche/vche"
	"veritas/vche/vche_1"
	"testing"
)

func Benchmark(b *testing.B) {
	params, err := vche_1.NewParameters(NeuralNetworkInference.BfvParams, 64)
	if err != nil {
		panic(err)
	}

	vche.PrintCryptoParams(params)

	keygen := vche_1.NewKeyGenerator(params)
	sk := keygen.GenSecretKey()

	rotKeys := keygen.GenRotationKeysForRotations(neural_network.RotsSmall, true, sk)
	relinKey := keygen.GenRelinearizationKey(sk, 1)
	evk := &vche_1.EvaluationKey{EvaluationKey: rlwe.EvaluationKey{Rlk: relinKey.RelinearizationKey, Rtks: rotKeys.RotationKeySet}, H: sk.H}

	modelParams := neural_network.ModelParams{
		Encryptor:          vche_1.NewGenericEncryptor(params, sk),
		Decryptor:          vche_1.NewGenericDecryptor(params, sk),
		Encoder:            vche_1.NewGenericEncoder(params, sk.K, sk.S, false),
		EncoderVerif:       vche_1.NewGenericEncoderPlaintext(params, sk.K),
		Evaluator:          vche_1.NewGenericEvaluator(params, evk),
		EvaluatorPlaintext: vche_1.NewGenericEvaluatorPlaintext(params, evk.H),
		Parameters:         params,
	}

	model := neural_network.NewModelSmall(modelParams)

	img := NeuralNetworkInference.MNISTTestImages[0]
	tags := NeuralNetworkInference.GenTags(0, NeuralNetworkInference.MNISTTestLabels[0], 25, params.NSlots)

	x := benchEnc(model, img, tags, b)

	res := benchEval(model, x, b)
	verif := benchVerif(model, tags, b)

	preds := benchDec(model, res, verif, b)

	NeuralNetworkInference.CheckResult(preds, NeuralNetworkInference.MNISTTestLabels[0])
}

func benchVerif(model neural_network.Model, tags [][]vche.Tag, b *testing.B) []interface{} {
	var enc interface{}
	var verif []interface{}
	enc = neural_network.EncVerif(model, tags)

	b.Run(benchmarkString("EvalVerif"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			verif = neural_network.Verif(model, enc)
		}
	})
	return verif
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
		ctxts[i] = vche_1.NewCiphertext(model.Parameters(), 1)
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

	var ptxts = make([]*vche_1.Plaintext, len(res))
	for i := range ptxts {
		ptxts[i] = vche_1.NewPlaintext(model.Parameters())
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

	b.Run(benchmarkString("Decode"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			for i := range res {
				model.Encoder().DecodeInt(ptxts[i], verif[i], values[i])
			}
		}
	})

	preds := make([]float64, len(res))
	outScale := model.EvalLayers()[len(model.EvalLayers())-1].OutputScale()

	for i := range values {
		preds[i] = float64(values[i][0]) / float64(outScale)
	}
	return preds
}

func benchmarkString(opname string) string {
	return "REP/" + opname
}
