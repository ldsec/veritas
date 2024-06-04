package main

import (
	"fmt"
	"github.com/DmitriyVTitov/size"
	"veritas/vche/examples/ObliviousRiding"
	"veritas/vche/vche"
	"veritas/vche/vche_2"
	"testing"
)

var params vche_2.Parameters
var encoder vche_2.Encoder
var decryptor vche_2.Decryptor
var evaluator vche_2.Evaluator
var encryptorRiderPk vche_2.Encryptor
var encryptorRiderSk vche_2.Encryptor

var encoderPlaintext vche_2.EncoderPlaintext
var evaluatorPlaintext vche_2.EvaluatorPlaintext

var prover vche_2.Prover
var verifier vche_2.Verifier

func init() {
	var err interface{}
	params, err = vche_2.NewParameters(ObliviousRiding.BfvParams)
	if err != nil {
		panic(err)
	}
	kgen := vche_2.NewKeyGenerator(params)
	riderSk, riderPk := kgen.GenKeyPair()

	encoder = vche_2.NewEncoder(params, riderSk.K, riderSk.Alpha, false)
	decryptor = vche_2.NewDecryptor(params, riderSk)
	encryptorRiderPk = vche_2.NewEncryptor(params, riderPk)
	encryptorRiderSk = vche_2.NewEncryptor(params, riderSk)
	relinKey := kgen.GenRelinearizationKey(riderSk, 1)
	evaluator = vche_2.NewEvaluator(params, &vche_2.EvaluationKey{
		Rlk:  relinKey,
		Rtks: nil,
	})

	encoderPlaintext = vche_2.NewEncoderPlaintext(params, riderSk.K)
	evaluatorPlaintext = vche_2.NewEvaluatorPlaintext(params)

	prover, verifier = vche_2.NewProverVerifier(params, riderSk, kgen.GenRotationKeysForInnerSum(riderSk))
}

func BenchmarkObliviousRiding(b *testing.B) {
	vche.PrintCryptoParams(params)

	// Number of drivers in the area
	nbDrivers := ObliviousRiding.NDrivers

	riderData, driversData, riderTags, driversTags := ObliviousRiding.GenDataAndTags(nbDrivers, params.NSlots, params.T())

	riderCtxt, driversCtxt := benchEnc(riderData, driversData, riderTags, driversTags, b)

	riderVerif, driversVerif := benchEncVerif(riderTags, driversTags, b)

	fmt.Printf("Encrypting %d driversData (x, y) and 1 Rider (%d, %d) \n", nbDrivers, riderData[0], riderData[1])
	fmt.Println()

	resCtxt := benchEval(riderCtxt, driversCtxt, b)

	resVerif := benchVerif(riderVerif, driversVerif, b)

	result := benchDec(resCtxt, resVerif, b)

	ObliviousRiding.FindClosestAndCheck(result, riderData, driversData)
}

func benchEnc(riderData []uint64, driversData [][]uint64, riderTags []vche.Tag, driversTags [][]vche.Tag, b *testing.B) (*vche_2.Ciphertext, []*vche_2.Ciphertext) {
	riderPtxt := vche_2.NewPlaintext(params)
	riderCtxt := vche_2.NewCiphertext(params, 1)
	ptxts := make([]*vche_2.Plaintext, len(driversData))
	ctxts := make([]*vche_2.Ciphertext, len(driversData))

	for i := range ptxts {
		ptxts[i] = vche_2.NewPlaintext(params)
		ctxts[i] = vche_2.NewCiphertext(params, 1)
	}

	b.Run(benchmarkString("Encode"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			encoder.EncodeUint(riderData, riderTags, riderPtxt)
			for i := range driversData {
				encoder.EncodeUint(driversData[i], driversTags[i], ptxts[i])
			}
		}
	})

	b.Run(benchmarkString("Encrypt"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			encryptorRiderSk.Encrypt(riderPtxt, riderCtxt)
			for i := range ptxts {
				encryptorRiderPk.Encrypt(ptxts[i], ctxts[i])
			}
		}
	})

	b.Run(benchmarkString("Communication/Rider->SP"), func(b *testing.B) {
		b.ReportMetric(float64(riderCtxt.Len()), "BFV-ctxt")
		b.ReportMetric(float64(size.Of(riderCtxt)), "bytes")
		b.ReportMetric(0.0, "ns/op")
	})
	b.Run(benchmarkString("Communication/Drivers->SP"), func(b *testing.B) {
		b.ReportMetric(float64(len(ctxts)*ctxts[0].Len()), "BFV-ctxt")
		b.ReportMetric(float64(size.Of(ctxts)), "bytes")
		b.ReportMetric(0.0, "ns/op")
	})

	return riderCtxt, ctxts
}

func benchEncVerif(riderTags []vche.Tag, driversTags [][]vche.Tag, b *testing.B) (*vche_2.Poly, []*vche_2.Poly) {
	riderVerif := vche_2.NewPoly(params)
	driversVerif := make([]*vche_2.Poly, len(driversTags))
	for i := range driversVerif {
		driversVerif[i] = vche_2.NewPoly(params)
	}

	encoderPlaintext.Encode(riderTags, riderVerif)
	for i := range driversTags {
		encoderPlaintext.Encode(driversTags[i], driversVerif[i])
	}

	return riderVerif, driversVerif
}

func benchEval(riderCtxt *vche_2.Ciphertext, driversCtxt []*vche_2.Ciphertext, b *testing.B) *vche_2.Ciphertext {
	var result *vche_2.Ciphertext

	b.Run(benchmarkString("Eval"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			result = evaluator.NegNew(riderCtxt)
			for i := range driversCtxt {
				evaluator.Add(result, driversCtxt[i], result)
			}

			result = evaluator.RelinearizeNew(evaluator.MulNew(result, result))
		}
	})

	return result
}

func benchVerif(riderVerif *vche_2.Poly, driversVerif []*vche_2.Poly, b *testing.B) *vche_2.Poly {
	var result *vche_2.Poly

	b.Run(benchmarkString("EvalVerif"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			tmp := evaluatorPlaintext.NegNew(riderVerif)
			for i := range driversVerif {
				evaluatorPlaintext.Add(tmp, driversVerif[i], tmp)
			}

			result = evaluatorPlaintext.RelinearizeNew(evaluatorPlaintext.MulNew(tmp, tmp))
		}
	})
	return result
}

func benchDec(encRes *vche_2.Ciphertext, verif *vche_2.Poly, b *testing.B) []uint64 {
	var ptxt = vche_2.NewPlaintext(params)
	var result = make([]uint64, params.NSlots)

	b.Run(benchmarkString("Communication/SP->Rider"), func(b *testing.B) {
		b.ReportMetric(float64(encRes.Len()), "BFV-ctxt")
		b.ReportMetric(float64(size.Of(encRes)), "bytes")
		b.ReportMetric(0.0, "ns/op")
	})

	b.Run(benchmarkString("Decrypt"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			decryptor.Decrypt(encRes, ptxt)
		}
	})

	b.Run(benchmarkString("Decode"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			encoder.DecodeUint(ptxt, verif, result)
		}
	})

	return result
}

func benchmarkString(opname string) string {
	return "PE/" + opname
}
