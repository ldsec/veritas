/*	Example of FEderated learning gradient averaging using the FedAvg algorithm.
	Weights were obtained using Vaseline555's implementation of McMahan et al.'s paper 
	"Communication-Efficient Learning of Deep Networks from Decentralized Data" - AISTATS 2017
	https://github.com/vaseline555/Federated-Averaging-PyTorch
	The 199,210 weighst correspond to a 2NN described in the original paper. 
VCHE 2 PRF
*/

package main

import (
	"fmt"
	"veritas/vche/examples/FedAvg"
	"veritas/vche/vche"
	"veritas/vche/vche_2"
	"math"
	"strconv"
)

// Utility function
func str2tag(datasetStr, messageStr string) vche.Tag {
	return vche.Tag{[]byte(datasetStr), []byte(messageStr)}
}

func fedAvg(filePath string, cntClient int, params vche_2.Parameters, encoder vche_2.Encoder, encryptorPk vche_2.Encryptor,
	evaluator vche_2.Evaluator, evaluatorPlaintext vche_2.EvaluatorPlaintextCFPRF, evaluatorPlaintextEncoder vche_2.EncoderPlaintextCFPRF, decryptor vche_2.Decryptor) (errcnt int) {
	localW, globalW, lineCnt := FedAvg.ReadCsvFiles(filePath, cntClient)

	// Encode and Encrypt
	numPacked := params.NSlots

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
	plaintextList := make([][]*vche_2.Plaintext, cntClient)
	plaintextListTags := make([][][]vche.Tag, cntClient)
	plaintextListVerif := make([][]*vche_2.VerifPlaintext, cntClient)

	for i := 0; i < cntClient; i++ {
		plaintextList[i] = make([]*vche_2.Plaintext, numCt)
		plaintextListTags[i] = make([][]vche.Tag, numCt)
		plaintextListVerif[i] = make([]*vche_2.VerifPlaintext, numCt)

		for j := 0; j < numCt; j++ {
			plaintextListTags[i][j] = make([]vche.Tag, params.NSlots)
			for k := 0; k < params.NSlots; k++ {
				plaintextListTags[i][j][k] = str2tag("tagGrad_clt"+fmt.Sprint(i)+"_vec"+fmt.Sprint(j), "_idx"+fmt.Sprint(k))
			}
			plaintextListVerif[i][j] = evaluatorPlaintextEncoder.EncodeNew(plaintextListTags[i][j])

			plaintextList[i][j] = vche_2.NewPlaintext(params)
			encoder.EncodeInt(ptVectors[i][j], plaintextListTags[i][j], plaintextList[i][j])
		}
	}

	// Encrypt vectors
	ciphertextList := make([][]*vche_2.Ciphertext, cntClient)
	for i := 0; i < cntClient; i++ {
		ciphertextList[i] = make([]*vche_2.Ciphertext, numCt)
		for j := 0; j < numCt; j++ {
			ciphertextList[i][j] = encryptorPk.EncryptNew(plaintextList[i][j])
		}
	}

	// Sum
	resCt := make([]*vche_2.Ciphertext, numCt)
	for j := 0; j < numCt; j++ {
		resCt[j] = ciphertextList[0][j].CopyNew()
		for i := 1; i < cntClient; i++ {
			evaluator.Add(resCt[j], ciphertextList[i][j], resCt[j])
		}
	}

	// Sum dummies
	resVerif := make([]*vche_2.VerifPlaintext, numCt)
	for j := 0; j < numCt; j++ {
		resVerif[j] = evaluatorPlaintext.CopyNew(plaintextListVerif[0][j])
		for i := 1; i < cntClient; i++ {
			evaluatorPlaintext.Add(resVerif[j], plaintextListVerif[i][j], resVerif[j])
		}
	}

	// Decrypt and Decode
	resPt := make([][]int64, numCt)
	for j := 0; j < numCt; j++ {
		evaluatorPlaintext.ComputeMemo(resVerif[j])
		resPt[j] = encoder.DecodeIntNew(decryptor.DecryptNew(resCt[j]), evaluatorPlaintext.Eval(resVerif[j]))
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
	fmt.Printf("____ Start BFV FedAvg VCHE2 CFPRF____ \n")

	// Import crypto
	params, err := vche_2.NewParameters(FedAvg.BfvParams)
	if err != nil {
		panic(err)
	}
	kgen := vche_2.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	encoder := vche_2.NewEncoder(params, sk.K, sk.Alpha, true)
	decryptor := vche_2.NewDecryptor(params, sk)
	encryptorPk := vche_2.NewEncryptor(params, pk)

	evk := &vche_2.EvaluationKey{}
	evaluator := vche_2.NewEvaluator(params, evk)
	evaluatorPlaintext := vche_2.NewEvaluatorPlaintextCFPRF(params)
	evaluatorPlaintextEncoder := vche_2.NewEncoderPlaintextCFPRF(params, sk.K)

	vche.PrintCryptoParams(params)

	cntClient := FedAvg.NumClients
	numEpoch := FedAvg.NumEpochs
	fmt.Printf("FedAvg over %d/100 epochs\n", numEpoch)

	// Loop over the epochs
	for i := 0; i < numEpoch; i++ {
		filePath := "../weights/R00" + strconv.Itoa(i+1) + "/all.weight"
		errCount := fedAvg(filePath, cntClient, params, encoder, encryptorPk, evaluator, evaluatorPlaintext, evaluatorPlaintextEncoder, decryptor)
		// Print error
		fmt.Printf("[Epoch %v] errors %v\n", i, errCount)
	}
}
