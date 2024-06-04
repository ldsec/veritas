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
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/rlwe"
	"veritas/vche/examples/EncDNS"
	"veritas/vche/vche"
	"math"
)

var maxInputLen = EncDNS.MaxInputLen
var numBits = EncDNS.NumBits

// Encrypted search over a database
func searchfunc(dbFilename string, params bfv.Parameters, encoder bfv.Encoder, encryptorPk bfv.Encryptor, evaluator bfv.Evaluator, decryptor bfv.Decryptor) {

	// Load data
	vecListKeys, vecListVals, numPacked, numVec := EncDNS.LoadDB(dbFilename, params.N())

	// Create query
	queryKeyVec, _, queryKeyStr := EncDNS.GetQuery(EncDNS.QueryKey, numPacked, params.N())

	// Encode and Encrypt
	keyPlaintextList := make([]*bfv.Plaintext, numVec)
	valPlaintextList := make([]*bfv.Plaintext, numVec)
	onePlaintext := bfv.NewPlaintext(params)
	queryPlaintext := bfv.NewPlaintext(params)
	indexPlaintext := bfv.NewPlaintext(params)

	ctListKeys := make([]*bfv.Ciphertext, numVec)
	ctListVals := make([]*bfv.Ciphertext, numVec)
	encryptedOne := bfv.NewCiphertext(params, 1)
	encryptedQuery := bfv.NewCiphertext(params, 1)

	oneVecPlain := make([]uint64, params.N())
	for j := 0; j < len(oneVecPlain); j++ {
		oneVecPlain[j] = 1
	}
	index := make([]uint64, params.N())
	for j := 0; j < len(index); j++ {
		if j%(EncDNS.MaxInputLen*EncDNS.NumBits) == 0 {
			index[j] = 1 // All other entries are 0
		}
	}

	for i := 0; i < numVec; i++ {
		keyPlaintextList[i] = bfv.NewPlaintext(params)
		valPlaintextList[i] = bfv.NewPlaintext(params)
		ctListKeys[i] = bfv.NewCiphertext(params, 1)
		ctListVals[i] = bfv.NewCiphertext(params, 1)
	}

	encoder.EncodeUint(oneVecPlain, onePlaintext)
	encoder.EncodeUint(queryKeyVec, queryPlaintext)
	encoder.EncodeUint(index, indexPlaintext)
	for i := 0; i < numVec; i++ {
		encoder.EncodeUint(vecListKeys[i], keyPlaintextList[i])
		encoder.EncodeUint(vecListVals[i], valPlaintextList[i])
	}

	encryptorPk.Encrypt(onePlaintext, encryptedOne)
	encryptorPk.Encrypt(queryPlaintext, encryptedQuery)
	for i := 0; i < numVec; i++ {
		encryptorPk.Encrypt(keyPlaintextList[i], ctListKeys[i])
		encryptorPk.Encrypt(valPlaintextList[i], ctListVals[i])
	}

	// Perform the search
	var resCt *bfv.Ciphertext = nil
	var ctMask = bfv.NewCiphertext(params, 1)
	var tempCt2 = bfv.NewCiphertext(params, 2)
	var tempCt1 = bfv.NewCiphertext(params, 1)

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

		evaluator.Mul(ctMask, indexPlaintext, ctMask)
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

	// Decrypt
	resPt := encoder.DecodeUintNew(decryptor.DecryptNew(resCt))

	// Decode the string
	resString := EncDNS.DecodeString(resPt)
	fmt.Printf("The value of key [%v] is: %v\n", queryKeyStr, resString)
}

func main() {
	fmt.Printf("____ Start BFV DNS ____\n")
	// Select file and parameters
	dbFilename := "../dnsDB.csv"
	if (maxInputLen != 16) || (numBits != 8) {
		panic("[FATAL] Expecting max input of length 16 over 8 bits")
	}
	fmt.Printf("Use file %v\n", dbFilename)

	// Load crypto
	params := EncDNS.BfvParams
	encoder := bfv.NewEncoder(params)
	kgen := bfv.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	decryptor := bfv.NewDecryptor(params, sk)
	encryptorPk := bfv.NewEncryptor(params, pk)
	relk := kgen.GenRelinearizationKey(sk, 2)
	N := params.N()
	rotk := kgen.GenRotationKeysForRotations([]int{1, 2, 4, 6, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, N - 1, N - 2, N - 4, N - 8, N - 16, N - 32, N - 64, N - 128}, true, sk)
	evaluator := bfv.NewEvaluator(params, rlwe.EvaluationKey{Rlk: relk, Rtks: rotk})

	vche.PrintCryptoParams(params)

	// Execute the search
	searchfunc(dbFilename, params, encoder, encryptorPk, evaluator, decryptor)
}
