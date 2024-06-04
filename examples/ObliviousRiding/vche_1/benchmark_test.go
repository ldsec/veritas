package main

import (
	"fmt"
	"github.com/DmitriyVTitov/size"
	"github.com/ldsec/lattigo/v2/rlwe"
	"veritas/vche/examples/ObliviousRiding"
	"veritas/vche/vche"
	"veritas/vche/vche_1"
	"testing"
)

var params vche_1.Parameters
var encoder vche_1.Encoder
var decryptor vche_1.Decryptor
var evaluator vche_1.Evaluator
var encryptorRiderPk vche_1.Encryptor
var encryptorRiderSk vche_1.Encryptor

var encoderPlaintext vche_1.EncoderPlaintext
var evaluatorPlaintext vche_1.EvaluatorPlaintext

func init() {
	var err interface{}
	params, err = vche_1.NewParameters(ObliviousRiding.BfvParams, 64)
	if err != nil {
		panic(err)
	}
	kgen := vche_1.NewKeyGenerator(params)
	riderSk, riderPk := kgen.GenKeyPair()

	encoder = vche_1.NewEncoder(params, riderSk.K, riderSk.S, false)
	decryptor = vche_1.NewDecryptor(params, riderSk)
	encryptorRiderPk = vche_1.NewEncryptor(params, riderPk)
	encryptorRiderSk = vche_1.NewEncryptor(params, riderSk)
	evaluator = vche_1.NewEvaluator(params, &vche_1.EvaluationKey{EvaluationKey: rlwe.EvaluationKey{Rlk: kgen.GenRelinearizationKey(riderSk, 1).RelinearizationKey, Rtks: nil}, H: riderSk.H})

	encoderPlaintext = vche_1.NewEncoderPlaintext(params, riderSk.K)
	evaluatorPlaintext = vche_1.NewEvaluatorPlaintext(params, riderSk.H)
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

func benchEnc(riderData []uint64, driversData [][]uint64, riderTags []vche.Tag, driversTags [][]vche.Tag, b *testing.B) (*vche_1.Ciphertext, []*vche_1.Ciphertext) {
	riderPtxt := vche_1.NewPlaintext(params)
	riderCtxt := vche_1.NewCiphertext(params, 1)
	ptxts := make([]*vche_1.Plaintext, len(driversData))
	ctxts := make([]*vche_1.Ciphertext, len(driversData))

	for i := range ptxts {
		ptxts[i] = vche_1.NewPlaintext(params)
		ctxts[i] = vche_1.NewCiphertext(params, 1)
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
		b.ReportMetric(1, "BFV-ctxt")
		b.ReportMetric(float64(size.Of(riderCtxt)), "bytes")
		b.ReportMetric(0.0, "ns/op")
	})
	b.Run(benchmarkString("Communication/Drivers->SP"), func(b *testing.B) {
		b.ReportMetric(float64(len(ctxts)), "BFV-ctxt")
		b.ReportMetric(float64(size.Of(ctxts)), "bytes")
		b.ReportMetric(0.0, "ns/op")
	})

	return riderCtxt, ctxts
}

func benchEncVerif(riderTags []vche.Tag, driversTags [][]vche.Tag, b *testing.B) (*vche_1.TaggedPoly, []*vche_1.TaggedPoly) {
	riderVerif := vche_1.NewTaggedPoly(params)
	driversVerif := make([]*vche_1.TaggedPoly, len(driversTags))
	for i := range driversVerif {
		driversVerif[i] = vche_1.NewTaggedPoly(params)
	}

	// Timing for encoding included in "Encode"
	encoderPlaintext.Encode(riderTags, riderVerif)
	for i := range driversTags {
		encoderPlaintext.Encode(driversTags[i], driversVerif[i])
	}

	return riderVerif, driversVerif
}

func benchEval(riderCtxt *vche_1.Ciphertext, driversCtxt []*vche_1.Ciphertext, b *testing.B) *vche_1.Ciphertext {
	var result *vche_1.Ciphertext

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

func benchVerif(riderVerif *vche_1.TaggedPoly, driversVerif []*vche_1.TaggedPoly, b *testing.B) *vche_1.TaggedPoly {
	var result *vche_1.TaggedPoly

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

func benchDec(encRes *vche_1.Ciphertext, verif *vche_1.TaggedPoly, b *testing.B) []uint64 {
	var ptxt = vche_1.NewPlaintext(params)
	var result = make([]uint64, params.NSlots)

	b.Run(benchmarkString("Communication/SP->Rider"), func(b *testing.B) {
		b.ReportMetric(1, "BFV-ctxt")
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
	return "REP/" + opname
}
