/* 	Basic example of disease susceptibility computation over BFV encrypted data.
Adapted from and using the computing method of Ayaday et al.'s "Protecting and Evaluating Genomic
Privacy in Medical" published at WPES'13.

VCHE_1 version
*/
package main

import (
	"fmt"
	"github.com/ldsec/lattigo/v2/rlwe"
	"veritas/vche/examples/DiseaseSusceptibilityPacked"
	"veritas/vche/vche"
	"veritas/vche/vche_1"
	"math"
)

// Utility function
func str2tag(datasetStr, messageStr string) vche.Tag {
	return vche.Tag{[]byte(datasetStr), []byte(messageStr)}
}

// Encrypted search over a database
func runDiseaseSusceptibility(fileStr string, disease string) (float64, float64) {
	// Import CSV files
	snpVec, weightVec, normFactor, cnt := DiseaseSusceptibilityPacked.ReadCsvFilesFullyPacked(fileStr, disease)
	fmt.Printf("File %v with %v SNP entries\n", fileStr, cnt)

	// Float result
	var floatRes float64
	for i := 0; i < cnt; i++ {
		floatRes += snpVec[i] * weightVec[i] / normFactor
	}
	fmt.Printf("Expected disease susceptibility is: %v\n", floatRes)
	fmt.Printf("Normfactor is: %v\n", normFactor)

	// Initialise encryption
	params, err := vche_1.NewParameters(DiseaseSusceptibilityPacked.BfvParams, 64)
	if err != nil {
		panic(err)
	}
	kgen := vche_1.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	encoder := vche_1.NewEncoder(params, sk.K, sk.S, false)
	decryptor := vche_1.NewDecryptor(params, sk)
	encryptorPk := vche_1.NewEncryptor(params, pk)
	relk := kgen.GenRelinearizationKey(sk, 2)
	rotk := kgen.GenRotationKeysForRotations([]int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384}, true, sk)

	// evk stores additionally the hash function
	evk := &vche_1.EvaluationKey{
		EvaluationKey: rlwe.EvaluationKey{Rlk: relk.RelinearizationKey, Rtks: rotk.RotationKeySet},
		H:             sk.H,
	}
	evaluator := vche_1.NewEvaluator(params, evk)
	evaluatorPlaintext := vche_1.NewEvaluatorPlaintext(params, sk.H)
	encoderPlaintext := vche_1.NewEncoderPlaintext(params, sk.K)
	
	vche.PrintCryptoParams(params)

	// Convert data to integers
	precision := DiseaseSusceptibilityPacked.Precision
	if len(snpVec) != len(weightVec) {
		panic("Mismatch in vector lengths: SNP != weights")
	}

	numVec := int(math.Ceil(float64(cnt) / float64(params.NSlots)))
	fmt.Printf("Packing into %v Ciphertext\n", numVec)
	snpIntVec := make([][]uint64, numVec)
	weightIntVec := make([][]uint64, numVec)

	snpTags := make([][]vche.Tag, numVec)
	weightTags := make([][]vche.Tag, numVec)

	for i := 0; i < numVec; i++ {
		snpIntVec[i] = make([]uint64, params.NSlots)
		snpTags[i] = make([]vche.Tag, params.NSlots)
		weightIntVec[i] = make([]uint64, params.NSlots)
		weightTags[i] = make([]vche.Tag, params.NSlots)
	}

	for i := 0; i < cnt; i++ {
		j := int(math.Floor(float64(i) / float64(params.NSlots)))
		k := i - params.NSlots*j
		snpIntVec[j][k] = uint64(math.Floor(2 * snpVec[i]))
		weightIntVec[j][k] = uint64(math.Floor(weightVec[i] * float64(precision)))

		snpTags[j][k] = str2tag("snp", fmt.Sprintf("%d-%d-%d", i, j, k))
		weightTags[j][k] = str2tag("weight", fmt.Sprintf("%d-%d-%d", i, j, k))
	}

	// Encrypt the database
	snpPlaintext := make([]*vche_1.Plaintext, numVec)
	weightPlaintext := make([]*vche_1.Plaintext, numVec)
	for i := 0; i < numVec; i++ {
		snpPlaintext[i] = vche_1.NewPlaintext(params)
		encoder.EncodeUint(snpIntVec[i], snpTags[i], snpPlaintext[i])

		weightPlaintext[i] = vche_1.NewPlaintext(params)
		encoder.EncodeUint(weightIntVec[i], weightTags[i], weightPlaintext[i])
	}

	// Create the ciphertexts
	snpCtxt := make([]*vche_1.Ciphertext, numVec)
	weightCtxt := make([]*vche_1.Ciphertext, numVec)
	for i := 0; i < numVec; i++ {
		snpCtxt[i] = encryptorPk.EncryptNew(snpPlaintext[i])
		weightCtxt[i] = encryptorPk.EncryptNew(weightPlaintext[i])
	}

	// Create the dummies
	snpVerif := make([]*vche_1.TaggedPoly, numVec)
	weightVerif := make([]*vche_1.TaggedPoly, numVec)

	for i := 0; i < numVec; i++ {
		snpVerif[i] = vche_1.NewTaggedPoly(params)
		weightVerif[i] = vche_1.NewTaggedPoly(params)
	}

	for i := 0; i < numVec; i++ {
		encoderPlaintext.Encode(snpTags[i], snpVerif[i])
		encoderPlaintext.Encode(weightTags[i], weightVerif[i])
	}

	resCtxt := vche_1.NewCiphertext(params, 1)
	tmpCtxt2 := vche_1.NewCiphertext(params, 2)
	tmpCtxt1 := vche_1.NewCiphertext(params, 1)

	var r int
	if (numVec == 1) {
		r = int(math.Ceil(math.Log2(float64(cnt))))
	} else {
		r = int(math.Log2(float64(params.NSlots))) - 1
	}

	// Perform the computation
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
	if (numVec > 1) {
		evaluator.RotateRows(resCtxt, tmpCtxt1)
		evaluator.Add(tmpCtxt1, resCtxt, resCtxt)
	}

	// Compute on the dummies
	resVerif := vche_1.NewTaggedPoly(params)
	tmpVerif2 := vche_1.NewTaggedPoly(params)
	tmpVerif1 := vche_1.NewTaggedPoly(params)

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
	if (numVec > 1) {
		evaluatorPlaintext.RotateRows(resVerif, tmpVerif1)
		evaluatorPlaintext.Add(tmpVerif1, resVerif, resVerif)
	}

	// Decrypt
	resPt := encoder.DecodeUintNew(decryptor.DecryptNew(resCtxt), resVerif)
	result := int64(resPt[0]) / (2 * precision)
	resultF := float64(result) / normFactor
	fmt.Println("============================================")
	fmt.Printf("Disease Susceptibility Packed Results: %v\n", disease)
	fmt.Println("============================================")
	fmt.Println()
	fmt.Printf("Disease susceptibility is: %v\n", resultF)
	errorR := (resultF - floatRes) / floatRes * 100
	errorA := resultF - floatRes
	return errorA, errorR
}

func main() {
	disease := DiseaseSusceptibilityPacked.Disease
	errorA, errorR := runDiseaseSusceptibility("HG01879", disease)
	fmt.Printf("error %v\n", errorA)
	fmt.Printf("Relative error %v\n", errorR)
}
