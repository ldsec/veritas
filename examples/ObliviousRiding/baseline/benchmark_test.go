package main

import (
	"fmt"
	"github.com/DmitriyVTitov/size"
	"veritas/vche/examples/ObliviousRiding"
	"veritas/vche/vche"
	"math"
	"testing"

	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/rlwe"
)

var params = ObliviousRiding.BfvParams
var encoder bfv.Encoder
var decryptor bfv.Decryptor
var evaluator bfv.Evaluator
var encryptorRiderPk bfv.Encryptor
var encryptorRiderSk bfv.Encryptor

func init() {
	encoder = bfv.NewEncoder(params)

	kgen := bfv.NewKeyGenerator(params)
	riderSk, riderPk := kgen.GenKeyPair()
	decryptor = bfv.NewDecryptor(params, riderSk)
	encryptorRiderPk = bfv.NewEncryptor(params, riderPk)
	encryptorRiderSk = bfv.NewEncryptor(params, riderSk)
	evaluator = bfv.NewEvaluator(params, rlwe.EvaluationKey{Rlk: kgen.GenRelinearizationKey(riderSk, 1), Rtks: nil})
	
	fmt.Printf("Parameters : N=%d, T=%d, logT=%d, Q = %d bits, sigma = %f \n",
	1<<params.LogN(), params.T(), int64(math.Log2(float64(params.T()))), params.LogQP(), params.Sigma())
	fmt.Println()

}

func BenchmarkObliviousRiding(b *testing.B) {
	vche.PrintCryptoParams(params)

	// Number of drivers in the area
	nbDrivers := ObliviousRiding.NDrivers //max is N/2

	riderData, driversData, _, _ := ObliviousRiding.GenDataAndTags(nbDrivers, params.N(), params.T())

	riderCtxt, driversCtxt := benchEnc(riderData, driversData, b)

	fmt.Printf("Encrypting %d driversData (x, y) and 1 Rider (%d, %d) \n", nbDrivers, riderData[0], riderData[1])
	fmt.Println()

	resCtxt := benchEval(riderCtxt, driversCtxt, b)

	result := benchDec(resCtxt, b)

	ObliviousRiding.FindClosestAndCheck(result, riderData, driversData)
}

func benchEnc(riderData []uint64, driversData [][]uint64, b *testing.B) (*bfv.Ciphertext, []*bfv.Ciphertext) {
	riderPtxt := bfv.NewPlaintext(params)
	riderCtxt := bfv.NewCiphertext(params, 1)
	ptxts := make([]*bfv.Plaintext, len(driversData))
	ctxts := make([]*bfv.Ciphertext, len(driversData))

	for i := range ptxts {
		ptxts[i] = bfv.NewPlaintext(params)
		ctxts[i] = bfv.NewCiphertext(params, 1)
	}

	b.Run(benchmarkString("Encode"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			encoder.EncodeUint(riderData, riderPtxt)
			for i := range driversData {
				encoder.EncodeUint(driversData[i], ptxts[i])
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
	b.Run(benchmarkString("Drivers->SP"), func(b *testing.B) {
		b.ReportMetric(float64(len(ctxts)), "BFV-ctxt") // CHECK
		b.ReportMetric(float64(size.Of(ctxts)), "bytes") 
		b.ReportMetric(0.0, "ns/op")
	})

	return riderCtxt, ctxts
}

func benchEval(riderCtxt *bfv.Ciphertext, driversCtxt []*bfv.Ciphertext, b *testing.B) *bfv.Ciphertext {
	var result *bfv.Ciphertext

	b.Run(benchmarkString("Eval"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			tmp := evaluator.NegNew(riderCtxt)
			for i := range driversCtxt {
				evaluator.Add(tmp, driversCtxt[i], tmp)
			}

			result = evaluator.RelinearizeNew(evaluator.MulNew(tmp, tmp))
		}
	})

	return result
}

func benchDec(encRes *bfv.Ciphertext, b *testing.B) []uint64 {
	var ptxt = bfv.NewPlaintext(params)
	var result = make([]uint64, params.N())

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
	tmp := bfv.NewPlaintext(params)
	tmp.Plaintext.Copy(ptxt.Plaintext)

	b.Run(benchmarkString("Decode"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			encoder.DecodeUint(ptxt, result)
		}
	})

	return encoder.DecodeUintNew(tmp) // Decode on a copy
}

func benchmarkString(opname string) string {
	return "BFV/" + opname
}
