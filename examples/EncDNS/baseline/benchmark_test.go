/*
Encrypted DNS A IP Lookup.
Use case initially inspired and re-implemented from HElib's code for country DB lookup
released under Apache v2.0.
The file dnsDB.csv is made from some of the top websites according to Alexa.
Sample program for education purposes only implementing a simple homomorphic encryption
based db search algorithm for demonstration purposes.

This example is adapted from code originally written by Jack Crawford for a lunch and learn
session at IBM Research (Hursley) in 2019. The original example code ships with HElib and
can be found at https://github.com/homenc/HElib/tree/master/examples/BGV_database_lookup

The original code was modify to work with Lattigo; the bit-wise ASCII representation
is used rather than the int-wise representation of char. A full packing helps reduce the
overhead. The Little Fermat Theorem is discarded in profit of a XOR equality testing.
The maximum size of the input is fixed to 16 char on 8 bits.

*/
package main

import (
	"fmt"
	"github.com/DmitriyVTitov/size"
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/rlwe"
	"veritas/vche/examples/EncDNS"
	"veritas/vche/vche"
	"math"
	"testing"
)

var params = EncDNS.BfvParams
var encoder bfv.Encoder
var decryptor bfv.Decryptor
var evaluator bfv.Evaluator
var encryptorPk bfv.Encryptor

func init() {
	kgen := bfv.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	encoder = bfv.NewEncoder(params)
	decryptor = bfv.NewDecryptor(params, sk)
	encryptorPk = bfv.NewEncryptor(params, pk)
	relk := kgen.GenRelinearizationKey(sk, 2)
	N := params.N()
	rotk := kgen.GenRotationKeysForRotations([]int{1, 2, 4, 6, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, N - 1, N - 2, N - 4, N - 8, N - 16, N - 32, N - 64, N - 128}, true, sk)
	evaluator = bfv.NewEvaluator(params, rlwe.EvaluationKey{Rlk: relk, Rtks: rotk})
}

// Encrypted search over a database
func BenchmarkEncDNS(b *testing.B) {
	vche.PrintCryptoParams(params)

	ptListKeys, ptListVals, numPacked, _ := EncDNS.LoadDB(EncDNS.DbFilename, params.N())
	queryKeyVec, _, queryKeyStr := EncDNS.GetQuery("google.com", numPacked, params.N())

	ctListKeys, ctListVals, encryptedOne, encryptedQuery, maskPlaintext := benchEnc(ptListKeys, ptListVals, queryKeyVec, b)

	resCt := benchEval(ctListKeys, ctListVals, encryptedOne, encryptedQuery, maskPlaintext, numPacked, b)

	res := benchDec(resCt, b)

	resString := EncDNS.DecodeString(res)
	fmt.Printf("The value of key [%v] is: %v\n", queryKeyStr, resString)
}

func benchEnc(ptListKeys, ptListVals [][]uint64, queryKey []uint64, b *testing.B) ([]*bfv.Ciphertext, []*bfv.Ciphertext, *bfv.Ciphertext, *bfv.Ciphertext, *bfv.Plaintext) {
	numVec := len(ptListKeys)

	keyPlaintextList := make([]*bfv.Plaintext, numVec)
	valPlaintextList := make([]*bfv.Plaintext, numVec)
	onePlaintext := bfv.NewPlaintext(params)
	queryPlaintext := bfv.NewPlaintext(params)
	maskPlaintext := bfv.NewPlaintext(params)

	ctListKeys := make([]*bfv.Ciphertext, numVec)
	ctListVals := make([]*bfv.Ciphertext, numVec)
	encryptedOne := bfv.NewCiphertext(params, 1)
	encryptedQuery := bfv.NewCiphertext(params, 1)

	oneVecPlain := make([]uint64, params.N())
	for j := 0; j < len(oneVecPlain); j++ {
		oneVecPlain[j] = 1
	}
	maskPlain := make([]uint64, params.N())
	for j := 0; j < len(maskPlain); j++ {
		if j%(EncDNS.MaxInputLen*EncDNS.NumBits) == 0 {
			maskPlain[j] = 1 // All other entries are 0
		}
	}

	for i := 0; i < numVec; i++ {
		keyPlaintextList[i] = bfv.NewPlaintext(params)
		valPlaintextList[i] = bfv.NewPlaintext(params)
		ctListKeys[i] = bfv.NewCiphertext(params, 1)
		ctListVals[i] = bfv.NewCiphertext(params, 1)
	}

	b.Run(benchmarkString("Encode"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			encoder.EncodeUint(oneVecPlain, onePlaintext)
			encoder.EncodeUint(queryKey, queryPlaintext)
			encoder.EncodeUint(maskPlain, maskPlaintext)
			for i := 0; i < numVec; i++ {
				encoder.EncodeUint(ptListKeys[i], keyPlaintextList[i])
				encoder.EncodeUint(ptListVals[i], valPlaintextList[i])
			}
		}
	})

	b.Run(benchmarkString("Encrypt"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			encryptorPk.Encrypt(onePlaintext, encryptedOne)
			encryptorPk.Encrypt(queryPlaintext, encryptedQuery)
			for i := 0; i < numVec; i++ {
				encryptorPk.Encrypt(keyPlaintextList[i], ctListKeys[i])
				encryptorPk.Encrypt(valPlaintextList[i], ctListVals[i])
			}
		}
	})

	b.Run(benchmarkString("Communication/Client->SP"), func(b *testing.B) {
		b.ReportMetric(float64(1+len(ctListKeys)+len(ctListVals)), "BFV-ctxt")
		b.ReportMetric(float64(size.Of(encryptedQuery)+size.Of(ctListKeys)+size.Of(ctListVals)), "bytes")
		b.ReportMetric(0.0, "ns/op")
	})

	return ctListKeys, ctListVals, encryptedOne, encryptedQuery, maskPlaintext
}

func benchEval(ctListKeys, ctListVals []*bfv.Ciphertext, encryptedOne, encryptedQuery *bfv.Ciphertext, maskPlaintext *bfv.Plaintext, numPacked int, b *testing.B) *bfv.Ciphertext {
	numVec := len(ctListKeys)
	var resCt *bfv.Ciphertext = nil
	var ctMask = bfv.NewCiphertext(params, 1)
	var tempCt2 = bfv.NewCiphertext(params, 2)
	var tempCt1 = bfv.NewCiphertext(params, 1)

	// Perform the search
	b.Run(benchmarkString("Eval"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			for i := 0; i < numVec; i++ {
				evaluator.Mul(ctListKeys[i], encryptedQuery, tempCt2)
				evaluator.Relinearize(tempCt2, ctMask)

				evaluator.MulScalar(ctMask, 2, ctMask)

				evaluator.Sub(ctMask, ctListKeys[i], ctMask)

				evaluator.Sub(ctMask, encryptedQuery, ctMask)

				evaluator.Add(encryptedOne, ctMask, ctMask)

				for j := 0; j < 6; j++ { // cover the numBits*maxInputSize slots: 128
					evaluator.RotateColumns(ctMask, 1<<(j+1), tempCt1)
					evaluator.Mul(ctMask, tempCt1, tempCt2)
					evaluator.Relinearize(tempCt2, ctMask)
				}

				evaluator.Mul(ctMask, maskPlaintext, ctMask)
				for j := 0; j < 7; j++ { // cover the numBits*maxInputSize slots: 128
					evaluator.RotateColumns(ctMask, params.N()-1<<j, tempCt1)
					evaluator.Add(ctMask, tempCt1, ctMask)
				}

				// Multiply mask with database to get non-zero entry only for the required value
				evaluator.Mul(ctMask, ctListVals[i], tempCt2)
				evaluator.Relinearize(tempCt2, tempCt1)

				if i == 0 {
					resCt = tempCt1.CopyNew()
				} else {
					evaluator.Add(resCt, tempCt1, resCt)
				}
			}

			if numPacked != 1 {
				// Sum over the first numbits*maxInputLen=128 slots
				for i := 0; i < int(math.Log2(float64(numPacked))-1); i++ { // Rotate up to half the vector
					evaluator.RotateColumns(resCt, 128*(1<<i), tempCt1)
					evaluator.Add(resCt, tempCt1, resCt)
				}
				// Do the final rotation (pt are represented as two N/2 vectors)
				evaluator.RotateRows(resCt, tempCt1)
				evaluator.Add(resCt, tempCt1, resCt)
			}
		}
	})

	return resCt
}

func benchDec(resCtxt *bfv.Ciphertext, b *testing.B) []uint64 {
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

	return result
}

func benchmarkString(opname string) string {
	return "BFV/" + opname
}
