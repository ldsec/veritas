/*	Example of FEderated learning gradient averaging using the FedAvg algorithm.
	Weights were obtained using Vaseline555's implementation of McMahan et al.'s paper 
	"Communication-Efficient Learning of Deep Networks from Decentralized Data" - AISTATS 2017
	https://github.com/vaseline555/Federated-Averaging-PyTorch
	The 199,210 weighst correspond to a 2NN described in the original paper. 
 */

package main

import (
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/rlwe"
	"veritas/vche/examples/FedAvg"
	"veritas/vche/vche"
	"math"
	"strconv"
)

// Run the FedAvg
func fedAvg(filePath string, cntClient int, params bfv.Parameters, encoder bfv.Encoder, encryptorPk bfv.Encryptor,
	evaluator bfv.Evaluator, decryptor bfv.Decryptor) (errcnt int) {
	localW, globalW, lineCnt := FedAvg.ReadCsvFiles(filePath, cntClient)

	// Encode and Encrypt
	numPacked := 1 << params.LogN()

	// Get the number of local ciphertexts
	numCt := int(math.Ceil(float64(lineCnt) / float64(numPacked)))

	// Create input vectors
	ptVectors := make([][][]int64, cntClient)
	for i := 0; i < cntClient; i++ {
		ptVectors[i] = make([][]int64, numCt)
		for j := 0; j < numCt; j++ {
			ptVectors[i][j] = make([]int64, numPacked)
		}
	}

	// Set the input vectors
	for i := 0; i < lineCnt; i++ {
		for j := 0; j < cntClient; j++ {
			ptVectors[j][int(math.Floor(float64(i/numPacked)))][i%numPacked] = localW[j][i]
		}
	}
	ptGlobalVectors := make([][]int64, numCt)
	for j := 0; j < numCt; j++ {
		ptGlobalVectors[j] = make([]int64, numPacked)
	}
	for i := 0; i < lineCnt; i++ {
		ptGlobalVectors[int(math.Floor(float64(i/numPacked)))][i%numPacked] = globalW[i]
	}

	// Create plaintexts
	plaintextList := make([][]*bfv.Plaintext, cntClient)
	for i := 0; i < cntClient; i++ {
		plaintextList[i] = make([]*bfv.Plaintext, numCt)
		for j := 0; j < numCt; j++ {
			plaintextList[i][j] = bfv.NewPlaintext(params)
			encoder.EncodeInt(ptVectors[i][j], plaintextList[i][j])
		}
	}

	// Encrypt vectors
	ciphertextList := make([][]*bfv.Ciphertext, cntClient)
	for i := 0; i < cntClient; i++ {
		ciphertextList[i] = make([]*bfv.Ciphertext, numCt)
		for j := 0; j < numCt; j++ {
			ciphertextList[i][j] = encryptorPk.EncryptNew(plaintextList[i][j])
		}
	}

	// Sum
	resCt := make([]*bfv.Ciphertext, numCt)
	for j := 0; j < numCt; j++ {
		resCt[j] = ciphertextList[0][j].CopyNew()
		for i := 1; i < cntClient; i++ {
			evaluator.Add(resCt[j], ciphertextList[i][j], resCt[j])
		}
	}

	// Decrypt and Decode
	resPt := make([][]int64, numCt)
	for j := 0; j < numCt; j++ {
		resPt[j] = encoder.DecodeIntNew(decryptor.DecryptNew(resCt[j]))
	}

	// Compare to Global weight
	errCount := 0
	for j := 0; j < numCt; j++ {
		for k := 0; k < numPacked; k++ {
			if resPt[j][k] != ptGlobalVectors[j][k] {
				errCount += 1
			}
		}
	}
	return errCount
}

func main() {
	fmt.Printf("____ Start BFV FedAvg ____\n")

	// Import crypto
	params := FedAvg.BfvParams
	encoder := bfv.NewEncoder(params)
	kgen := bfv.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	decryptor := bfv.NewDecryptor(params, sk)
	encryptorPk := bfv.NewEncryptor(params, pk)
	evaluator := bfv.NewEvaluator(params, rlwe.EvaluationKey{})

	vche.PrintCryptoParams(params)

	cntClient := FedAvg.NumClients
	numEpoch := FedAvg.NumEpochs
	fmt.Printf("FedAvg over %d/100 epochs\n", numEpoch)

	// Loop over the epochs
	for i := 0; i < numEpoch; i++ {
		filePath := "../weights/R00" + strconv.Itoa(i+1) + "/all.weight"
		errCount := fedAvg(filePath, cntClient, params, encoder, encryptorPk, evaluator, decryptor)
		// Print error
		fmt.Printf("[Epoch %v] errors %v\n", i, errCount)
	}
}
