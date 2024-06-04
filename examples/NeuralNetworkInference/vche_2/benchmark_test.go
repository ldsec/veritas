package vche_2

import (
	"fmt"
	"github.com/DmitriyVTitov/size"
	"veritas/vche/examples/NeuralNetworkInference"
	"veritas/vche/examples/NeuralNetworkInference/neural_network"
	"veritas/vche/vche"
	"veritas/vche/vche_2"
	"math"
	"testing"
)

var prover vche_2.Prover
var verifier vche_2.Verifier

func Benchmark(b *testing.B) {
	params, err := vche_2.NewParameters(NeuralNetworkInference.BfvParams)
	if err != nil {
		panic(err)
	}

	vche.PrintCryptoParams(params)

	keygen := vche_2.NewKeyGenerator(params)
	sk := keygen.GenSecretKey()

	rotKeys := keygen.GenRotationKeysForRotations(neural_network.RotsSmall, true, sk)
	relinKey := keygen.GenRelinearizationKey(sk, 1)
	evk := &vche_2.EvaluationKey{Rlk: relinKey, Rtks: rotKeys}

	modelParams := neural_network.ModelParams{
		Encryptor:          vche_2.NewGenericEncryptor(params, sk),
		Decryptor:          vche_2.NewGenericDecryptor(params, sk),
		Encoder:            vche_2.NewGenericEncoder(params, sk.K, sk.Alpha, false),
		EncoderVerif:       vche_2.NewGenericEncoderPlaintext(params, sk.K),
		Evaluator:          vche_2.NewGenericEvaluator(params, evk),
		EvaluatorPlaintext: vche_2.NewGenericEvaluatorPlaintext(params),
		Parameters:         params,
	}

	prover, verifier = vche_2.NewProverVerifier(params, sk, keygen.GenRotationKeysForInnerSum(sk))

	model := neural_network.NewModelSmall(modelParams)

	img := NeuralNetworkInference.MNISTTestImages[0]
	tags := NeuralNetworkInference.GenTags(0, NeuralNetworkInference.MNISTTestLabels[0], 25, params.NSlots)

	x := benchEnc(model, img, tags, b)

	res := benchEval(model, x, b)
	verif := benchVerif(model, tags, b)

	preds := benchDec(model, res, verif, b)

	NeuralNetworkInference.CheckResult(preds, NeuralNetworkInference.MNISTTestLabels[0])

	d := res[0].(*vche_2.Ciphertext).Len() - 1
	fmt.Printf("soundness VCHE2: %v\n", math.Log2(float64(2*d)/float64(params.T())))
	fmt.Printf("soundness  PEPP: %v\n", math.Log2(float64(3*d+2*params.NSlots)/float64(params.T())))
	fmt.Printf("d: %v\n", d)
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
		ctxts[i] = vche_2.NewCiphertext(model.Parameters(), 1)
	}
	b.Run(benchmarkString("Encrypt"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			for i := range x {
				model.Encryptor().Encrypt(x[i], ctxts[i])
			}
		}
	})

	b.Run(benchmarkString("Communication/Client->SP"), func(b *testing.B) {
		b.ReportMetric(float64(len(ctxts)*len(ctxts[0].(*vche_2.Ciphertext).Ciphertexts)), "BFV-ctxt")
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
		b.ReportMetric(float64(len(res)*len(res[0].(*vche_2.Ciphertext).Ciphertexts)), "BFV-ctxt")
		b.ReportMetric(float64(size.Of(res)), "bytes")
		b.ReportMetric(0.0, "ns/op")
	})

	b.Run(benchmarkString("Communication/SP->Client/PP"), func(b *testing.B) {
		b.ReportMetric(2, "BFV-ctxt")
		// TODO: find a way to report bytes
		b.ReportMetric(0.0, "ns/op")
	})

	var ptxts = make([]*vche_2.Plaintext, len(res))
	for i := range ptxts {
		ptxts[i] = vche_2.NewPlaintext(model.Parameters())
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

	b.Run(benchmarkString("PolyProt/Verifier"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			for i := range res {
				_ = vche_2.BenchmarkPolynomialProtocolVerifier(prover, verifier, res[i].(*vche_2.Ciphertext), verif[i].(*vche_2.Poly), b)
			}
		}
	})

	b.Run(benchmarkString("PolyProt/Prover"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			for i := range res {
				_ = vche_2.BenchmarkPolynomialProtocolProver(prover, verifier, res[i].(*vche_2.Ciphertext), verif[i].(*vche_2.Poly), b)
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
	return "PE/" + opname
}
