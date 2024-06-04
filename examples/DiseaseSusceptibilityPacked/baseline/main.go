/* 	Basic example of disease susceptibility computation over BFV encrypted data.
Adapted from and using the computing method of Ayaday et al.'s "Protecting and Evaluating Genomic
Privacy in Medical" published at WPES'13.

Packed bfv version
*/
package main

import (
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/rlwe"
	"veritas/vche/vche"
	"veritas/vche/examples/DiseaseSusceptibilityPacked"
	"math"
)

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
	params := DiseaseSusceptibilityPacked.BfvParams
	kgen := bfv.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	encoder := bfv.NewEncoder(params)
	decryptor := bfv.NewDecryptor(params, sk)
	encryptorPk := bfv.NewEncryptor(params, pk)
	relk := kgen.GenRelinearizationKey(sk, 2)
	rotk := kgen.GenRotationKeysForRotations([]int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384}, true, sk)
	evaluator := bfv.NewEvaluator(params, rlwe.EvaluationKey{Rlk: relk, Rtks: rotk})

	vche.PrintCryptoParams(params)

	// Convert data to integers
	precision := DiseaseSusceptibilityPacked.Precision
	if len(snpVec) != len(weightVec) {
		panic("Mismatch in vector lengths: SNP != weights")
	}

	numVec := int(math.Ceil(float64(cnt) / float64(params.N())))
	fmt.Printf("Packing into %v Ciphertext\n", numVec)
	snpIntVec := make([][]uint64, numVec)
	weightIntVec := make([][]uint64, numVec)

	for i := 0; i < numVec; i++ {
		snpIntVec[i] = make([]uint64, params.N())
		weightIntVec[i] = make([]uint64, params.N())
	}

	for i := 0; i < cnt; i++ {
		j := int(math.Floor(float64(i) / float64(params.N())))
		k := i - params.N()*j
		//fmt.Printf("store %v in ct[%v] slot %v\n", i, j, k)
		snpIntVec[j][k] = uint64(math.Floor(2 * snpVec[i]))
		weightIntVec[j][k] = uint64(math.Floor(weightVec[i] * float64(precision)))
	}

	// Encrypt the database
	snpPtxt := make([]*bfv.Plaintext, numVec)
	weightPtxt := make([]*bfv.Plaintext, numVec)
	for i := 0; i < numVec; i++ {
		snpPtxt[i] = bfv.NewPlaintext(params)
		encoder.EncodeUint(snpIntVec[i], snpPtxt[i])

		weightPtxt[i] = bfv.NewPlaintext(params)
		encoder.EncodeUint(weightIntVec[i], weightPtxt[i])
	}

	// Create the ciphertexts
	snpCtxt := make([]*bfv.Ciphertext, numVec)
	weightCtxt := make([]*bfv.Ciphertext, numVec)
	for i := 0; i < numVec; i++ {
		snpCtxt[i] = encryptorPk.EncryptNew(snpPtxt[i])
		weightCtxt[i] = encryptorPk.EncryptNew(weightPtxt[i])
	}

	resCtxt := bfv.NewCiphertext(params, 1)
	tmpCtxt2 := bfv.NewCiphertext(params, 2)
	tmpCtxt1 := bfv.NewCiphertext(params, 1)

	var r int
	if (numVec == 1)&&(cnt!=params.N()) {
		r = int(math.Ceil(math.Log2(float64(cnt))))
	} else {
		r = int(math.Log2(float64(params.N()))) - 1
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
	if (numVec > 1)||(cnt==params.N()) {
		evaluator.RotateRows(resCtxt, tmpCtxt1)
		evaluator.Add(tmpCtxt1, resCtxt, resCtxt)
	}

	// Decrypt
	resPt := encoder.DecodeUintNew(decryptor.DecryptNew(resCtxt))
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
