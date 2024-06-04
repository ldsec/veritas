/* 	Example of FEderated learning gradient averaging using the FedAvg algorithm.
	Weights were obtained using Vaseline555's implementation of McMahan et al.'s paper 
	"Communication-Efficient Learning of Deep Networks from Decentralized Data" - AISTATS 2017
	https://github.com/vaseline555/Federated-Averaging-PyTorch
	The 199,210 weighst correspond to a 2NN described in the original paper. 
*/
package main

import (
	"fmt"
	"github.com/DmitriyVTitov/size"
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/rlwe"
	"veritas/vche/examples/FedAvg"
	"veritas/vche/vche"
	"strconv"
	"testing"
)

var params = FedAvg.BfvParams
var encoder bfv.Encoder
var decryptor bfv.Decryptor
var evaluator bfv.Evaluator
var encryptorPk bfv.Encryptor

var numPacked int

func init() {
	encoder = bfv.NewEncoder(params)

	kgen := bfv.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	decryptor = bfv.NewDecryptor(params, sk)
	encryptorPk = bfv.NewEncryptor(params, pk)
	evaluator = bfv.NewEvaluator(params, rlwe.EvaluationKey{})
}

func BenchmarkFedAvg(b *testing.B) {
	vche.PrintCryptoParams(params)

	cntClient := FedAvg.NumClients
	numEpoch := FedAvg.NumEpochs
	fmt.Printf("FedAvg over %d/100 epochs\n", numEpoch)

	for i := 0; i < numEpoch; i++ {
		filePath := "../weights/R00" + strconv.Itoa(i+1) + "/all.weight"
		errCount := fedAvgRound(filePath, cntClient, b)
		fmt.Printf("[Epoch %v] errors %v\n", i, errCount)
	}
}

func fedAvgRound(filePath string, cntClient int, b *testing.B) (errcnt int) {
	ptVectors, _, ptGlobalVectors := FedAvg.GenDataAndTags(filePath, cntClient, params.N())
	numCt := len(ptVectors[0])

	ctxtList := benchEnc(ptVectors, numCt, b)

	resCt := benchEval(ctxtList, numCt, b)

	res := benchDec(resCt, numCt, b)

	// Compare to Global weight
	errCount := 0
	for j := 0; j < numCt; j++ {
		for k := range res[j] {
			if res[j][k] != ptGlobalVectors[j][k] {
				errCount += 1
			}
		}
	}
	return errCount
}

func benchEnc(ptVectors [][][]int64, numCt int, b *testing.B) [][]*bfv.Ciphertext {
	cntClient := FedAvg.NumClients
	// Create plaintexts
	plaintextList := make([][]*bfv.Plaintext, cntClient)
	for i := 0; i < cntClient; i++ {
		plaintextList[i] = make([]*bfv.Plaintext, numCt)
		for j := 0; j < numCt; j++ {
			plaintextList[i][j] = bfv.NewPlaintext(params)
		}
	}

	// Encrypt vectors
	ciphertextList := make([][]*bfv.Ciphertext, cntClient)
	for i := 0; i < cntClient; i++ {
		ciphertextList[i] = make([]*bfv.Ciphertext, numCt)
		for j := 0; j < numCt; j++ {
			ciphertextList[i][j] = bfv.NewCiphertext(params, 1)
		}
	}

	b.Run(benchmarkString("Encode"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			for i := 0; i < cntClient; i++ {
				for j := 0; j < numCt; j++ {
					encoder.EncodeInt(ptVectors[i][j], plaintextList[i][j])
				}
			}
		}
	})

	b.Run(benchmarkString("Encrypt"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			for i := 0; i < cntClient; i++ {
				for j := 0; j < numCt; j++ {
					ciphertextList[i][j] = encryptorPk.EncryptNew(plaintextList[i][j])
				}
			}
		}
	})

	b.Run(benchmarkString("Communication/Clients->SP"), func(b *testing.B) {
		b.ReportMetric(float64(len(ciphertextList)*len(ciphertextList[0])), "BFV-ctxt")
		b.ReportMetric(float64(size.Of(ciphertextList)), "bytes")
		b.ReportMetric(0.0, "ns/op")
	})

	return ciphertextList
}

func benchEval(ciphertextList [][]*bfv.Ciphertext, numCt int, b *testing.B) []*bfv.Ciphertext {
	resCt := make([]*bfv.Ciphertext, numCt)

	b.Run(benchmarkString("Eval"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			for j := 0; j < numCt; j++ {
				resCt[j] = ciphertextList[0][j].CopyNew()
				for i := 1; i < FedAvg.NumClients; i++ {
					evaluator.Add(resCt[j], ciphertextList[i][j], resCt[j])
				}
			}
		}
	})

	return resCt
}

func benchDec(resCt []*bfv.Ciphertext, numCt int, b *testing.B) [][]int64 {
	b.Run(benchmarkString("Communication/SP->Clients"), func(b *testing.B) {
		b.ReportMetric(float64(len(resCt)), "BFV-ctxt")
		b.ReportMetric(float64(size.Of(resCt)), "bytes")
		b.ReportMetric(0.0, "ns/op")
	})

	resPt := make([]*bfv.Plaintext, numCt)
	res := make([][]int64, numCt)
	for i := range resPt {
		resPt[i] = bfv.NewPlaintext(params)
		res[i] = make([]int64, params.N())
	}

	b.Run(benchmarkString("Decrypt"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			for j := 0; j < numCt; j++ {
				decryptor.Decrypt(resCt[j], resPt[j])
			}
		}
	})

	b.Run(benchmarkString("Decode"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			for j := 0; j < numCt; j++ {
				encoder.DecodeInt(resPt[j], res[j])
			}
		}
	})

	for j := 0; j < numCt; j++ {
		decryptor.Decrypt(resCt[j], resPt[j])
		encoder.DecodeInt(resPt[j], res[j])
	}
	return res
}

func benchmarkString(opname string) string {
	return "BFV/" + opname
}
