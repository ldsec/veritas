/* 	Basic example of disease susceptibility computation over BFV encrypted data.
Adapted from and using the computing method of Ayaday et al.'s "Protecting and Evaluating Genomic
Privacy in Medical" published at WPES'13.
VCHE_1 version
*/
package main

import (
	"github.com/DmitriyVTitov/size"
	"github.com/ldsec/lattigo/v2/rlwe"
	"veritas/vche/examples/DiseaseSusceptibilityPacked"
	"veritas/vche/vche"
	"veritas/vche/vche_1"
	"math"
	"testing"
)

var params vche_1.Parameters
var encoder vche_1.Encoder
var decryptor vche_1.Decryptor
var evaluator vche_1.Evaluator
var encryptorPk vche_1.Encryptor

var encoderPlaintext vche_1.EncoderPlaintext
var evaluatorPlaintext vche_1.EvaluatorPlaintext

func init() {
	var err interface{}
	params, err = vche_1.NewParameters(DiseaseSusceptibilityPacked.BfvParams, 64)
	if err != nil {
		panic(err)
	}
	kgen := vche_1.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()

	encoder = vche_1.NewEncoder(params, sk.K, sk.S, false)
	decryptor = vche_1.NewDecryptor(params, sk)
	encryptorPk = vche_1.NewEncryptor(params, pk)

	relk := kgen.GenRelinearizationKey(sk, 2)
	rotk := kgen.GenRotationKeysForRotations([]int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384}, true, sk)
	evaluator = vche_1.NewEvaluator(params, &vche_1.EvaluationKey{EvaluationKey: rlwe.EvaluationKey{Rlk: relk.RelinearizationKey, Rtks: rotk.RotationKeySet}, H: sk.H})

	encoderPlaintext = vche_1.NewEncoderPlaintext(params, sk.K)
	evaluatorPlaintext = vche_1.NewEvaluatorPlaintext(params, sk.H)
}

func BenchmarkDiseaseSusceptibility(b *testing.B) {
	vche.PrintCryptoParams(params)

	snpIntVec, weightIntVec, snpTags, weightTags, precision, normFactor, cnt, resExpected := DiseaseSusceptibilityPacked.GenDataAndTags(params.NSlots)

	snpCtxt, weightCtxt := benchEnc(snpIntVec, weightIntVec, snpTags, weightTags, b)
	snpVerif, weightVerif := benchEncVerif(snpTags, weightTags, b)

	resCtxt := benchEval(snpCtxt, weightCtxt, cnt, b)
	resVerif := benchVerif(snpVerif, weightVerif, cnt, b)

	res := benchDec(resCtxt, resVerif, precision, normFactor, b)

	DiseaseSusceptibilityPacked.CheckResult(res, resExpected)
}

func benchEnc(snpIntVec, weightIntVec [][]uint64, snpTags, weightTags [][]vche.Tag, b *testing.B) ([]*vche_1.Ciphertext, []*vche_1.Ciphertext) {
	numVec := len(snpIntVec)

	snpPtxt := make([]*vche_1.Plaintext, numVec)
	weightsPtxt := make([]*vche_1.Plaintext, numVec)
	snpCtxt := make([]*vche_1.Ciphertext, numVec)
	weightsCtxt := make([]*vche_1.Ciphertext, numVec)

	for i := 0; i < numVec; i++ {
		snpPtxt[i] = vche_1.NewPlaintext(params)
		weightsPtxt[i] = vche_1.NewPlaintext(params)
		snpCtxt[i] = vche_1.NewCiphertext(params, 1)
		weightsCtxt[i] = vche_1.NewCiphertext(params, 1)
	}

	b.Run(benchmarkString("Encode"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			for i := 0; i < numVec; i++ {
				encoder.EncodeUint(snpIntVec[i], snpTags[i], snpPtxt[i])
				encoder.EncodeUint(weightIntVec[i], weightTags[i], weightsPtxt[i])
			}
		}
	})

	b.Run(benchmarkString("Encrypt"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			for i := 0; i < numVec; i++ {
				encryptorPk.Encrypt(snpPtxt[i], snpCtxt[i])
				encryptorPk.Encrypt(weightsPtxt[i], weightsCtxt[i])
			}
		}
	})

	b.Run(benchmarkString("Communication/Client->SP"), func(b *testing.B) {
		b.ReportMetric(float64(len(snpCtxt)), "BFV-ctxt")
		b.ReportMetric(float64(size.Of(snpCtxt)), "bytes")
		b.ReportMetric(0.0, "ns/op")
	})

	return snpCtxt, weightsCtxt
}

func benchEncVerif(snpTags, weightsTags [][]vche.Tag, b *testing.B) ([]*vche_1.TaggedPoly, []*vche_1.TaggedPoly) {
	numVec := len(snpTags)

	snpVerif := make([]*vche_1.TaggedPoly, numVec)
	weightsVerif := make([]*vche_1.TaggedPoly, numVec)

	for i := 0; i < numVec; i++ {
		snpVerif[i] = vche_1.NewTaggedPoly(params)
		weightsVerif[i] = vche_1.NewTaggedPoly(params)
	}

	for i := 0; i < numVec; i++ {
		encoderPlaintext.Encode(snpTags[i], snpVerif[i])
		encoderPlaintext.Encode(weightsTags[i], weightsVerif[i])
	}

	return snpVerif, weightsVerif
}

func benchEval(snpCtxt, weightCtxt []*vche_1.Ciphertext, cnt int, b *testing.B) *vche_1.Ciphertext {
	numVec := len(snpCtxt)
	resCtxt := vche_1.NewCiphertext(params, 1)
	tmpCtxt2 := vche_1.NewCiphertext(params, 2)
	tmpCtxt1 := vche_1.NewCiphertext(params, 1)

	var r int
	if (numVec == 1) {
		r = int(math.Ceil(math.Log2(float64(cnt))))
	} else {
		r = int(math.Log2(float64(params.NSlots))) - 1
	}

	b.Run(benchmarkString("Eval"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			evaluator.Mul(snpCtxt[0], weightCtxt[0], tmpCtxt2)
			evaluator.Relinearize(tmpCtxt2, resCtxt)
			for i := 1; i < numVec; i++ {
				evaluator.Mul(snpCtxt[i], weightCtxt[i], tmpCtxt2)
				evaluator.Relinearize(tmpCtxt2, tmpCtxt1)
				evaluator.Add(tmpCtxt1, resCtxt, resCtxt)
			}

			for i := 0; i < r; i++ {
				evaluator.RotateColumns(resCtxt, int(math.Pow(2, float64(i))), tmpCtxt1)
				evaluator.Add(tmpCtxt1, resCtxt, resCtxt)
			}

			if numVec > 1 {
				evaluator.RotateRows(resCtxt, tmpCtxt1)
				evaluator.Add(tmpCtxt1, resCtxt, resCtxt)
			}
		}
	})

	return resCtxt
}

func benchVerif(snpVerif, weightVerif []*vche_1.TaggedPoly, cnt int, b *testing.B) *vche_1.TaggedPoly {
	numVec := len(snpVerif)
	resVerif := vche_1.NewTaggedPoly(params)
	tmpVerif2 := vche_1.NewTaggedPoly(params)
	tmpVerif1 := vche_1.NewTaggedPoly(params)

	var r int
	if (numVec == 1) {
		r = int(math.Ceil(math.Log2(float64(cnt))))
	} else {
		r = int(math.Log2(float64(params.NSlots))) - 1
	}

	b.Run(benchmarkString("EvalVerif"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			evaluatorPlaintext.Mul(snpVerif[0], weightVerif[0], tmpVerif2)
			evaluatorPlaintext.Relinearize(tmpVerif2, resVerif)
			for i := 1; i < numVec; i++ {
				evaluatorPlaintext.Mul(snpVerif[i], weightVerif[i], tmpVerif2)
				evaluatorPlaintext.Relinearize(tmpVerif2, tmpVerif1)
				evaluatorPlaintext.Add(tmpVerif1, resVerif, resVerif)
			}

			for i := 0; i < r; i++ {
				evaluatorPlaintext.RotateColumns(resVerif, int(math.Pow(2, float64(i))), tmpVerif1)
				evaluatorPlaintext.Add(tmpVerif1, resVerif, resVerif)
			}

			if numVec > 1 {
				evaluatorPlaintext.RotateRows(resVerif, tmpVerif1)
				evaluatorPlaintext.Add(tmpVerif1, resVerif, resVerif)
			}
		}
	})

	return resVerif
}

func benchDec(resCtxt *vche_1.Ciphertext, resVerif *vche_1.TaggedPoly, precision int64, normFactor float64, b *testing.B) float64 {
	b.Run(benchmarkString("Communication/SP->Client"), func(b *testing.B) {
		b.ReportMetric(1, "BFV-ctxt")
		b.ReportMetric(float64(size.Of(resCtxt)), "bytes")
		b.ReportMetric(0.0, "ns/op")
	})

	var ptxt = vche_1.NewPlaintext(params)
	var result = make([]uint64, params.NSlots)

	b.Run(benchmarkString("Decrypt"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			decryptor.Decrypt(resCtxt, ptxt)
		}
	})

	b.Run(benchmarkString("Decode"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			encoder.DecodeUint(ptxt, resVerif, result)
		}
	})

	r := int64(result[0]) / (2 * precision)
	return float64(r) / normFactor
}

func benchmarkString(opname string) string {
	return "REP/" + opname
}
