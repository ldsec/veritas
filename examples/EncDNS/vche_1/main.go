/*
Use case initially inspired and re-implemented from HElib's code for country DB lookup
released under Apache v2.0.
Sample program for education purposes only implementing a simple homomorphic encryption
based db search algorithm for demonstration purposes.

This example is adapted from code originally written by Jack Crawford for a lunch and learn
session at IBM Research (Hursley) in 2019. The original example code ships with HElib and
can be found at https://github.com/homenc/HElib/tree/master/examples/BGV_database_lookup

The original code was modify to work with Lattigo; the bit-wise ASCII representation
is used rather than the int-wise representation of char. A full packing helps reduce the
overhead. The Little Fermat Theorem is discarded in profit of a XOR equality testing.
The maximum size of the input is fixed to 16 char on 8 bits.

VCHE 1

*/
package main

import (
	"fmt"
	"github.com/ldsec/lattigo/v2/rlwe"
	"veritas/vche/examples/EncDNS"
	"veritas/vche/vche"
	"veritas/vche/vche_1"
	"math"
	"strconv"
)

var maxInputLen = EncDNS.MaxInputLen
var numBits = EncDNS.NumBits

// Encrypted search over a database
func searchfunc(dbFilename string, params vche_1.Parameters, encoder vche_1.Encoder, encryptorPk vche_1.Encryptor, evaluator vche_1.Evaluator,
	evaluatorPlaintext vche_1.EvaluatorPlaintext, encoderPlaintext vche_1.EncoderPlaintext, decryptor vche_1.Decryptor) {

	// Load data
	ptListKeys, ptListVals, numPacked, numVec := EncDNS.LoadDB(EncDNS.DbFilename, params.NSlots)

	// Create query
	queryKeyVec, _, queryKeyStr := EncDNS.GetQuery("google.com", numPacked, params.NSlots)

	var ctListKeys, ctListVals []*vche_1.Ciphertext
	var encryptedOne, encryptedQuery *vche_1.Ciphertext
	var indexPlaintext *vche_1.Plaintext

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

	// Encode and Encrypt
	keyPlaintextList := make([]*vche_1.Plaintext, numVec)
	valPlaintextList := make([]*vche_1.Plaintext, numVec)
	onePlaintext := vche_1.NewPlaintext(params)
	queryPlaintext := vche_1.NewPlaintext(params)
	indexPlaintext = vche_1.NewPlaintext(params)

	ctListKeys = make([]*vche_1.Ciphertext, numVec)
	ctListVals = make([]*vche_1.Ciphertext, numVec)
	encryptedOne = vche_1.NewCiphertext(params, 1)
	encryptedQuery = vche_1.NewCiphertext(params, 1)

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

	encoder.EncodeUint(oneVecPlain, oneTags, onePlaintext)
	encoder.EncodeUint(queryKeyVec, queryTags, queryPlaintext)
	encoder.EncodeUint(index, indexTags, indexPlaintext)
	for i := 0; i < numVec; i++ {
		encoder.EncodeUint(ptListKeys[i], keysTags[i], keyPlaintextList[i])
		encoder.EncodeUint(ptListVals[i], valsTags[i], valPlaintextList[i])
	}

	encryptorPk.Encrypt(onePlaintext, encryptedOne)
	encryptorPk.Encrypt(queryPlaintext, encryptedQuery)
	for i := 0; i < numVec; i++ {
		encryptorPk.Encrypt(keyPlaintextList[i], ctListKeys[i])
		encryptorPk.Encrypt(valPlaintextList[i], ctListVals[i])
	}

	// EncVerif
	var keyTagsVerif, valTagsVerif []*vche_1.TaggedPoly
	var oneTagVerif, queryTagsVerif, indexVerif *vche_1.TaggedPoly

	keyTagsVerif = make([]*vche_1.TaggedPoly, numVec)
	valTagsVerif = make([]*vche_1.TaggedPoly, numVec)
	oneTagVerif = vche_1.NewTaggedPoly(params)
	queryTagsVerif = vche_1.NewTaggedPoly(params)
	indexVerif = vche_1.NewTaggedPoly(params)
	for i := 0; i < numVec; i++ {
		keyTagsVerif[i] = vche_1.NewTaggedPoly(params)
		valTagsVerif[i] = vche_1.NewTaggedPoly(params)
	}

	encoderPlaintext.Encode(oneTags, oneTagVerif)
	encoderPlaintext.Encode(queryTags, queryTagsVerif)
	encoderPlaintext.Encode(indexTags, indexVerif)
	for i := 0; i < numVec; i++ {
		encoderPlaintext.Encode(keysTags[i], keyTagsVerif[i])
		encoderPlaintext.Encode(valsTags[i], valTagsVerif[i])
	}

	// Eval
	var resCt *vche_1.Ciphertext = nil
	var ctMask = vche_1.NewCiphertext(params, 1)
	var tempCt2 = vche_1.NewCiphertext(params, 2)
	var tempCt1 = vche_1.NewCiphertext(params, 1)

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

	//EvalVerif
	var resVerif *vche_1.TaggedPoly = nil
	var verifMask = vche_1.NewTaggedPoly(params)
	var tempVerif2 = vche_1.NewTaggedPoly(params)
	var tempVerif1 = vche_1.NewTaggedPoly(params)

	for i := 0; i < numVec; i++ {
		evaluatorPlaintext.Mul(keyTagsVerif[i], queryTagsVerif, tempVerif2)
		evaluatorPlaintext.Relinearize(tempVerif2, verifMask)

		evaluatorPlaintext.MulScalar(verifMask, 2, verifMask)
		evaluatorPlaintext.Sub(verifMask, keyTagsVerif[i], verifMask)
		evaluatorPlaintext.Sub(verifMask, queryTagsVerif, verifMask)
		evaluatorPlaintext.Add(oneTagVerif, verifMask, verifMask)

		for j := 0; j < 6; j++ { // cover the numBits*maxInputSize slots: 128
			evaluatorPlaintext.RotateColumns(verifMask, 1<<(j+1), tempVerif1)
			evaluatorPlaintext.Mul(verifMask, tempVerif1, tempVerif2)
			evaluatorPlaintext.Relinearize(tempVerif2, verifMask)
		}

		evaluatorPlaintext.Mul(verifMask, indexVerif, verifMask)
		for j := 0; j < 7; j++ { // cover the numBits*maxInputSize slots: 128
			evaluatorPlaintext.RotateColumns(verifMask, params.NSlots-1<<j, tempVerif1)
			evaluatorPlaintext.Add(verifMask, tempVerif1, verifMask)
		}

		// Multiply mask with database to get non-zero entry only for the required value
		evaluatorPlaintext.Mul(verifMask, valTagsVerif[i], tempVerif2)
		evaluatorPlaintext.Relinearize(tempVerif2, tempVerif1)

		if i == 0 {
			resVerif = evaluatorPlaintext.CopyNew(tempVerif1)
		} else {
			evaluatorPlaintext.Add(resVerif, tempVerif1, resVerif)
		}
	}

	if numPacked != 1 {
		// Sum over the first numbits*maxInputLen=128 slots
		for i := 0; i < int(math.Log2(float64(numPacked))-1); i++ { // Rotate up to half the vector
			evaluatorPlaintext.RotateColumns(resVerif, 128*(1<<i), tempVerif1)
			evaluatorPlaintext.Add(resVerif, tempVerif1, resVerif)
		}
		// Do the final rotation (pt are represented as two N/2 vectors)
		evaluatorPlaintext.RotateRows(resVerif, tempVerif1)
		evaluatorPlaintext.Add(resVerif, tempVerif1, resVerif)
	}

	// Decrypt
	resPt := encoder.DecodeUintNew(decryptor.DecryptNew(resCt), resVerif)

	// Decode the string
	resString := EncDNS.DecodeString(resPt)
	fmt.Printf("The value of key [%v] is: %v\n", queryKeyStr, resString)
}

func main() {
	fmt.Printf("____ Start BFV DNS VCHE1 ____\n")
	// Select file and parameters
	dbFilename := "../dnsDB.csv"
	if (maxInputLen != 16) || (numBits != 8) {
		panic("[FATAL] Expecting max input of length 16 over 8 bits")
	}
	fmt.Printf("Use file %v\n", dbFilename)

	// Load crypto
	lambda := 64
	params, err := vche_1.NewParameters(EncDNS.BfvParams, lambda)
	if err != nil {
		panic(err)
	}
	kgen := vche_1.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	encoder := vche_1.NewEncoder(params, sk.K, sk.S, false)
	decryptor := vche_1.NewDecryptor(params, sk)
	encryptorPk := vche_1.NewEncryptor(params, pk)
	relk := kgen.GenRelinearizationKey(sk, 2)
	N := params.NSlots
	rotk := kgen.GenRotationKeysForRotations([]int{1, 2, 4, 6, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, N - 1, N - 2, N - 4, N - 8, N - 16, N - 32, N - 64, N - 128}, true, sk)

	evk := &vche_1.EvaluationKey{
		EvaluationKey: rlwe.EvaluationKey{Rlk: relk.RelinearizationKey, Rtks: rotk.RotationKeySet},
		H:             sk.H,
	}
	evaluator := vche_1.NewEvaluator(params, evk)
	evaluatorPlaintext := vche_1.NewEvaluatorPlaintext(params, sk.H)
	evaluatorPlaintextEncoder := vche_1.NewEncoderPlaintext(params, sk.K)

	vche.PrintCryptoParams(params)

	// Execute the search
	searchfunc(dbFilename, params, encoder, encryptorPk, evaluator, evaluatorPlaintext, evaluatorPlaintextEncoder, decryptor)
}
