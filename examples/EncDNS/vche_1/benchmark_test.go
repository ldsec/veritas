/*
Encrypted DNS A IP Lookup.
Use case initially inspired and re-implemented from HElib's code for country DB lookup
released under Apache v2.0.
The file dnsDB.csv is made from some of the top 1200 websites according to Alexa.
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
	"github.com/ldsec/lattigo/v2/rlwe"
	"veritas/vche/examples/EncDNS"
	"veritas/vche/vche"
	"veritas/vche/vche_1"
	"math"
	"strconv"
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
	params, err = vche_1.NewParameters(EncDNS.BfvParams, 64)
	if err != nil {
		panic(err)
	}
	kgen := vche_1.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	encoder = vche_1.NewEncoder(params, sk.K, sk.S, false)
	decryptor = vche_1.NewDecryptor(params, sk)
	encryptorPk = vche_1.NewEncryptor(params, pk)
	relk := kgen.GenRelinearizationKey(sk, 2)
	N := params.NSlots
	rotk := kgen.GenRotationKeysForRotations([]int{1, 2, 4, 6, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, N - 1, N - 2, N - 4, N - 8, N - 16, N - 32, N - 64, N - 128}, true, sk)
	evaluator = vche_1.NewEvaluator(params, &vche_1.EvaluationKey{EvaluationKey: rlwe.EvaluationKey{Rlk: relk.RelinearizationKey, Rtks: rotk.RotationKeySet}, H: sk.H})
	encoderPlaintext = vche_1.NewEncoderPlaintext(params, sk.K)
	evaluatorPlaintext = vche_1.NewEvaluatorPlaintext(params, sk.H)
}

// Encrypted search over a database
func BenchmarkEncDNS(b *testing.B) {
	fmt.Printf("Parameters : logN=%d, T=%d, logT=%d, logQ=%d, sigma = %f, REP.lambda=%d, REP.NSlots=%d\n",
		params.N(), params.T(), uint64(math.Log2(float64(params.T()))), params.LogQ(), params.Sigma(), params.NumReplications, params.NSlots)
	fmt.Println()

	ptListKeys, ptListVals, numPacked, _ := EncDNS.LoadDB(EncDNS.DbFilename, params.NSlots)
	queryKeyVec, _, queryKeyStr := EncDNS.GetQuery("google.com", numPacked, params.NSlots)

	ctListKeys, ctListVals, encryptedOne, encryptedQuery, indexPlaintext := benchEnc(ptListKeys, ptListVals, queryKeyVec, b)
	keyTagsVerif, valTagsVerif, oneTagVerif, queryTagsVerif, indexVerif := benchEncVerif(len(ptListKeys), b)

	resCt := benchEval(ctListKeys, ctListVals, encryptedOne, encryptedQuery, indexPlaintext, numPacked, b)

	resVerif := benchVerif(keyTagsVerif, valTagsVerif, oneTagVerif, queryTagsVerif, indexVerif, numPacked, b)

	res := benchDec(resCt, resVerif, b)

	resString := EncDNS.DecodeString(res)
	fmt.Printf("The value of key [%v] is: %v\n", queryKeyStr, resString)
}

func benchEnc(ptListKeys, ptListVals [][]uint64, queryKey []uint64, b *testing.B) ([]*vche_1.Ciphertext, []*vche_1.Ciphertext, *vche_1.Ciphertext, *vche_1.Ciphertext, *vche_1.Plaintext) {
	numVec := len(ptListKeys)
	// Create tags
	keysTags := make([][]vche.Tag, numVec)
	valsTags := make([][]vche.Tag, numVec)
	for i := 0; i < numVec; i++ {
		keysTags[i] = vche.GetIndexTags([]byte("key-"+strconv.Itoa(i)), params.NSlots)
		valsTags[i] = vche.GetIndexTags([]byte("value-"+strconv.Itoa(i)), params.NSlots)
	}
	queryTags := vche.GetIndexTags([]byte("query"), params.NSlots)
	oneTags := vche.GetIndexTags([]byte("1"), params.NSlots)
	indexTags := vche.GetIndexTags([]byte("mask"), params.NSlots)

	keyPlaintextList := make([]*vche_1.Plaintext, numVec)
	valPlaintextList := make([]*vche_1.Plaintext, numVec)
	onePlaintext := vche_1.NewPlaintext(params)
	queryPlaintext := vche_1.NewPlaintext(params)
	indexPlaintext := vche_1.NewPlaintext(params)

	ctListKeys := make([]*vche_1.Ciphertext, numVec)
	ctListVals := make([]*vche_1.Ciphertext, numVec)
	encryptedOne := vche_1.NewCiphertext(params, 1)
	encryptedQuery := vche_1.NewCiphertext(params, 1)

	oneVecPlain := make([]uint64, params.NSlots)
	for j := 0; j < len(oneVecPlain); j++ {
		oneVecPlain[j] = 1
	}
	index := make([]uint64, params.NSlots)
	for j := 0; j < len(index); j++ {
		if j%(EncDNS.MaxInputLen*EncDNS.NumBits) == 0 {
			index[j] = 1 // All other entries are 0
		}
	}

	for i := 0; i < numVec; i++ {
		keyPlaintextList[i] = vche_1.NewPlaintext(params)
		valPlaintextList[i] = vche_1.NewPlaintext(params)
		ctListKeys[i] = vche_1.NewCiphertext(params, 1)
		ctListVals[i] = vche_1.NewCiphertext(params, 1)
	}

	b.Run(benchmarkString("Encode"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			encoder.EncodeUint(oneVecPlain, oneTags, onePlaintext)
			encoder.EncodeUint(queryKey, queryTags, queryPlaintext)
			encoder.EncodeUint(index, indexTags, indexPlaintext)
			for i := 0; i < numVec; i++ {
				encoder.EncodeUint(ptListKeys[i], keysTags[i], keyPlaintextList[i])
				encoder.EncodeUint(ptListVals[i], valsTags[i], valPlaintextList[i])
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

	return ctListKeys, ctListVals, encryptedOne, encryptedQuery, indexPlaintext
}

func benchEncVerif(numVec int, b *testing.B) ([]*vche_1.TaggedPoly, []*vche_1.TaggedPoly, *vche_1.TaggedPoly, *vche_1.TaggedPoly, *vche_1.TaggedPoly) {
	keysTags := make([][]vche.Tag, numVec)
	valsTags := make([][]vche.Tag, numVec)
	for i := 0; i < numVec; i++ {
		keysTags[i] = vche.GetIndexTags([]byte("key-"+strconv.Itoa(i)), params.NSlots)
		valsTags[i] = vche.GetIndexTags([]byte("value-"+strconv.Itoa(i)), params.NSlots)
	}
	queryTags := vche.GetIndexTags([]byte("query"), params.NSlots)
	oneTags := vche.GetIndexTags([]byte("1"), params.NSlots)
	indexTags := vche.GetIndexTags([]byte("mask"), params.NSlots)

	keyPlaintextList := make([]*vche_1.TaggedPoly, numVec)
	valPlaintextList := make([]*vche_1.TaggedPoly, numVec)
	onePlaintext := vche_1.NewTaggedPoly(params)
	queryPlaintext := vche_1.NewTaggedPoly(params)
	indexPlaintext := vche_1.NewTaggedPoly(params)
	for i := 0; i < numVec; i++ {
		keyPlaintextList[i] = vche_1.NewTaggedPoly(params)
		valPlaintextList[i] = vche_1.NewTaggedPoly(params)
	}

	encoderPlaintext.Encode(oneTags, onePlaintext)
	encoderPlaintext.Encode(queryTags, queryPlaintext)
	encoderPlaintext.Encode(indexTags, indexPlaintext)
	for i := 0; i < numVec; i++ {
		encoderPlaintext.Encode(keysTags[i], keyPlaintextList[i])
		encoderPlaintext.Encode(valsTags[i], valPlaintextList[i])
	}

	return keyPlaintextList, valPlaintextList, onePlaintext, queryPlaintext, indexPlaintext
}

func benchEval(ctListKeys, ctListVals []*vche_1.Ciphertext, encryptedOne, encryptedQuery *vche_1.Ciphertext, maskPlaintext *vche_1.Plaintext, numPacked int, b *testing.B) *vche_1.Ciphertext {
	numVec := len(ctListKeys)
	var resCt *vche_1.Ciphertext = nil
	var ctMask = vche_1.NewCiphertext(params, 1)
	var tempCt2 = vche_1.NewCiphertext(params, 2)
	var tempCt1 = vche_1.NewCiphertext(params, 1)

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
					evaluator.RotateColumns(ctMask, params.NSlots-1<<j, tempCt1)
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

func benchVerif(ctListKeys, ctListVals []*vche_1.TaggedPoly, encryptedOne, encryptedQuery *vche_1.TaggedPoly, maskPlaintext *vche_1.TaggedPoly, numPacked int, b *testing.B) *vche_1.TaggedPoly {
	numVec := len(ctListKeys)
	var resCt *vche_1.TaggedPoly = nil
	var ctMask = vche_1.NewTaggedPoly(params)
	var tempCt2 = vche_1.NewTaggedPoly(params)
	var tempCt1 = vche_1.NewTaggedPoly(params)

	// Perform the search
	b.Run(benchmarkString("EvalVerif"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			for i := 0; i < numVec; i++ {
				evaluatorPlaintext.Mul(ctListKeys[i], encryptedQuery, tempCt2)
				evaluatorPlaintext.Relinearize(tempCt2, ctMask)

				evaluatorPlaintext.MulScalar(ctMask, 2, ctMask)

				evaluatorPlaintext.Sub(ctMask, ctListKeys[i], ctMask)

				evaluatorPlaintext.Sub(ctMask, encryptedQuery, ctMask)

				evaluatorPlaintext.Add(encryptedOne, ctMask, ctMask)

				for j := 0; j < 6; j++ { // cover the numBits*maxInputSize slots: 128
					evaluatorPlaintext.RotateColumns(ctMask, 1<<(j+1), tempCt1)
					evaluatorPlaintext.Mul(ctMask, tempCt1, tempCt2)
					evaluatorPlaintext.Relinearize(tempCt2, ctMask)
				}

				evaluatorPlaintext.Mul(ctMask, maskPlaintext, ctMask)
				for j := 0; j < 7; j++ { // cover the numBits*maxInputSize slots: 128
					evaluatorPlaintext.RotateColumns(ctMask, params.NSlots-1<<j, tempCt1)
					evaluatorPlaintext.Add(ctMask, tempCt1, ctMask)
				}

				// Multiply mask with database to get non-zero entry only for the required value
				evaluatorPlaintext.Mul(ctMask, ctListVals[i], tempCt2)
				evaluatorPlaintext.Relinearize(tempCt2, tempCt1)

				if i == 0 {
					resCt = evaluatorPlaintext.CopyNew(tempCt1)
				} else {
					evaluatorPlaintext.Add(resCt, tempCt1, resCt)
				}
			}

			if numPacked != 1 {
				// Sum over the first numbits*maxInputLen=128 slots
				for i := 0; i < int(math.Log2(float64(numPacked))-1); i++ { // Rotate up to half the vector
					evaluatorPlaintext.RotateColumns(resCt, 128*(1<<i), tempCt1)
					evaluatorPlaintext.Add(resCt, tempCt1, resCt)
				}
				// Do the final rotation (pt are represented as two N/2 vectors)
				evaluatorPlaintext.RotateRows(resCt, tempCt1)
				evaluatorPlaintext.Add(resCt, tempCt1, resCt)
			}
		}
	})

	return resCt
}

func benchDec(resCtxt *vche_1.Ciphertext, resVerif *vche_1.TaggedPoly, b *testing.B) []uint64 {
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

	return result
}

func benchmarkString(opname string) string {
	return "REP/" + opname
}
