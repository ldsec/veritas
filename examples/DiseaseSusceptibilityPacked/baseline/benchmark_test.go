/* 	Basic example of disease susceptibility computation over BFV encrypted data.
Adapted from and using the computing method of Ayaday et al.'s "Protecting and Evaluating Genomic
Privacy in Medical" published at WPES'13.
*/
package main

import (
	"github.com/DmitriyVTitov/size"
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/rlwe"
	"veritas/vche/examples/DiseaseSusceptibilityPacked"
	"veritas/vche/vche"
	"math"
	"testing"
)

var params = DiseaseSusceptibilityPacked.BfvParams
var encoder bfv.Encoder
var decryptor bfv.Decryptor
var evaluator bfv.Evaluator
var encryptorPk bfv.Encryptor

func init() {
	encoder = bfv.NewEncoder(params)

	kgen := bfv.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	decryptor = bfv.NewDecryptor(params, sk)
	encryptorPk = bfv.NewEncryptor(params, pk)
	relk := kgen.GenRelinearizationKey(sk, 2)
	rotk := kgen.GenRotationKeysForRotations([]int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384}, true, sk)
	evaluator = bfv.NewEvaluator(params, rlwe.EvaluationKey{Rlk: relk, Rtks: rotk})
}

func BenchmarkDiseaseSusceptibility(b *testing.B) {
	vche.PrintCryptoParams(params)

	snpIntVec, weightIntVec, _, _, precision, normFactor, cnt, resExpected := DiseaseSusceptibilityPacked.GenDataAndTags(params.N())

	snpCtxt, weightCtxt := benchEnc(snpIntVec, weightIntVec, b)

	resCtxt := benchEval(snpCtxt, weightCtxt, cnt, b)

	res := benchDec(resCtxt, precision, normFactor, b)

	DiseaseSusceptibilityPacked.CheckResult(res, resExpected)
}

func benchEnc(snpIntVec [][]uint64, weightIntVec [][]uint64, b *testing.B) ([]*bfv.Ciphertext, []*bfv.Ciphertext) {
	numVec := len(snpIntVec)

	snpPtxt := make([]*bfv.Plaintext, numVec)
	weightPtxt := make([]*bfv.Plaintext, numVec)
	snpCtxt := make([]*bfv.Ciphertext, numVec)
	weightCtxt := make([]*bfv.Ciphertext, numVec)

	for i := 0; i < numVec; i++ {
		snpPtxt[i] = bfv.NewPlaintext(params)
		weightPtxt[i] = bfv.NewPlaintext(params)
		snpCtxt[i] = bfv.NewCiphertext(params, 1)
		weightCtxt[i] = bfv.NewCiphertext(params, 1)
	}

	b.Run(benchmarkString("Encode"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			for i := 0; i < numVec; i++ {
				encoder.EncodeUint(snpIntVec[i], snpPtxt[i])
				encoder.EncodeUint(weightIntVec[i], weightPtxt[i])
			}
		}
	})

	b.Run(benchmarkString("Encrypt"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			for i := 0; i < numVec; i++ {
				encryptorPk.Encrypt(snpPtxt[i], snpCtxt[i])
				encryptorPk.Encrypt(weightPtxt[i], weightCtxt[i])
			}
		}
	})

	b.Run(benchmarkString("Communication/Client->SP"), func(b *testing.B) {
		b.ReportMetric(float64(len(snpCtxt)), "BFV-ctxt")
		b.ReportMetric(float64(size.Of(snpCtxt)), "bytes")
		b.ReportMetric(0.0, "ns/op")
	})

	return snpCtxt, weightCtxt
}

func benchEval(snpCtxt, weightCtxt []*bfv.Ciphertext, cnt int, b *testing.B) *bfv.Ciphertext {
	numVec := len(snpCtxt)
	resCtxt := bfv.NewCiphertext(params, 1)
	tmpCtxt2 := bfv.NewCiphertext(params, 2)
	tmpCtxt1 := bfv.NewCiphertext(params, 1)

	var r int
	if (numVec == 1)&&(cnt!=params.N()) {
		r = int(math.Ceil(math.Log2(float64(cnt))))
	} else {
		r = int(math.Log2(float64(params.N()))) - 1
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

			if (numVec > 1)||(cnt==params.N()) {
				evaluator.RotateRows(resCtxt, tmpCtxt1)
				evaluator.Add(tmpCtxt1, resCtxt, resCtxt)
			}
		}
	})

	return resCtxt
}

func benchDec(resCtxt *bfv.Ciphertext, precision int64, normFactor float64, b *testing.B) float64 {
	b.Run(benchmarkString("Communication/SP->Client"), func(b *testing.B) {
		b.ReportMetric(1, "BFV-ctxt")
		b.ReportMetric(float64(size.Of(resCtxt)), "bytes")
		b.ReportMetric(0.0, "ns/op")
	})

	var ptxt = bfv.NewPlaintext(params)
	var result = make([]uint64, params.N())

	b.Run(benchmarkString("Decrypt"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			decryptor.Decrypt(resCtxt, ptxt)
		}
	})
	tmp := bfv.NewPlaintext(params)
	tmp.Plaintext.Copy(ptxt.Plaintext)

	b.Run(benchmarkString("Decode"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			encoder.DecodeUint(ptxt, result)
		}
	})

	encoder.DecodeUint(tmp, result) // Decode on a copy
	r := int64(result[0]) / (2 * precision)
	return float64(r) / normFactor
}

func benchmarkString(opname string) string {
	return "BFV/" + opname
}
