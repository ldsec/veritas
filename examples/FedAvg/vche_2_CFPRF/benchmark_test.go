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
	"veritas/vche/examples/FedAvg"
	"veritas/vche/vche"
	"veritas/vche/vche_2"
	"strconv"
	"testing"
)

var params = vche_2.Parameters{}
var encoder vche_2.Encoder
var decryptor vche_2.Decryptor
var evaluator vche_2.Evaluator
var encryptorPk vche_2.Encryptor

var encoderPlaintext vche_2.EncoderPlaintextCFPRF
var evaluatorPlaintext vche_2.EvaluatorPlaintextCFPRF

func init() {
	var err interface{}
	params, err = vche_2.NewParameters(FedAvg.BfvParams)
	if err != nil {
		panic(err)
	}

	kgen := vche_2.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()

	encoder = vche_2.NewEncoder(params, sk.K, sk.Alpha, true)

	decryptor = vche_2.NewDecryptor(params, sk)
	encryptorPk = vche_2.NewEncryptor(params, pk)
	evaluator = vche_2.NewEvaluator(params, &vche_2.EvaluationKey{})

	encoderPlaintext = vche_2.NewEncoderPlaintextCFPRF(params, sk.K)
	evaluatorPlaintext = vche_2.NewEvaluatorPlaintextCFPRF(params)
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
	ptVectors, tags, ptGlobalVectors := FedAvg.GenDataAndTags(filePath, cntClient, params.NSlots)
	numCt := len(ptVectors[0])

	ctxtList := benchEnc(ptVectors, tags, numCt, b)
	verifList := benchEncVerif(tags, numCt, b)

	resCt := benchEval(ctxtList, numCt, b)
	resVerif := benchVerif(verifList, numCt, b)

	res := benchDec(resCt, resVerif, numCt, b)

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

func benchEnc(ptVectors [][][]int64, ptTags [][][]vche.Tag, numCt int, b *testing.B) [][]*vche_2.Ciphertext {
	cntClient := FedAvg.NumClients
	// Create plaintexts
	plaintextList := make([][]*vche_2.Plaintext, cntClient)
	for i := 0; i < cntClient; i++ {
		plaintextList[i] = make([]*vche_2.Plaintext, numCt)
		for j := 0; j < numCt; j++ {
			plaintextList[i][j] = vche_2.NewPlaintext(params)
		}
	}

	// Encrypt vectors
	ciphertextList := make([][]*vche_2.Ciphertext, cntClient)
	for i := 0; i < cntClient; i++ {
		ciphertextList[i] = make([]*vche_2.Ciphertext, numCt)
		for j := 0; j < numCt; j++ {
			ciphertextList[i][j] = vche_2.NewCiphertext(params, 1)
		}
	}

	b.Run(benchmarkString("Encode"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			for i := 0; i < cntClient; i++ {
				for j := 0; j < numCt; j++ {
					encoder.EncodeInt(ptVectors[i][j], ptTags[i][j], plaintextList[i][j])
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
		b.ReportMetric(float64(len(ciphertextList)*len(ciphertextList[0])*ciphertextList[0][0].Len()), "BFV-ctxt")
		b.ReportMetric(float64(size.Of(ciphertextList)), "bytes")
		b.ReportMetric(0.0, "ns/op")
	})

	return ciphertextList
}

func benchEncVerif(ptTags [][][]vche.Tag, numCt int, b *testing.B) [][]*vche_2.VerifPlaintext {
	cntClient := FedAvg.NumClients
	// Create plaintexts
	polys := make([][]*vche_2.VerifPlaintext, cntClient)
	for i := 0; i < cntClient; i++ {
		polys[i] = make([]*vche_2.VerifPlaintext, numCt)
		for j := 0; j < numCt; j++ {
			polys[i][j] = vche_2.NewVerifPlaintext(params)
		}
	}

	for i := 0; i < cntClient; i++ {
		for j := 0; j < numCt; j++ {
			encoderPlaintext.Encode(ptTags[i][j], polys[i][j])
		}
	}

	return polys
}

func benchEval(ciphertextList [][]*vche_2.Ciphertext, numCt int, b *testing.B) []*vche_2.Ciphertext {
	resCt := make([]*vche_2.Ciphertext, numCt)

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

func benchVerif(ciphertextList [][]*vche_2.VerifPlaintext, numCt int, b *testing.B) []*vche_2.Poly {
	resCt := make([]*vche_2.VerifPlaintext, numCt)
	res := make([]*vche_2.Poly, numCt)

	{
		for j := 0; j < numCt; j++ {
			resCt[j] = evaluatorPlaintext.CopyNew(ciphertextList[0][j])
			for i := 1; i < FedAvg.NumClients; i++ {
				evaluatorPlaintext.Add(resCt[j], ciphertextList[i][j], resCt[j])
			}
		}
	}

	b.Run(benchmarkString("EvalVerif/Precomputable"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			for j := 0; j < numCt; j++ {
				evaluatorPlaintext.ComputeMemo(resCt[j])
			}
		}
	})

	b.Run(benchmarkString("EvalVerif"), func(b *testing.B) {
		for run := 0; run < b.N; run++ {
			for j := 0; j < numCt; j++ {
				resCt[j] = evaluatorPlaintext.CopyNew(ciphertextList[0][j])
				for i := 1; i < FedAvg.NumClients; i++ {
					evaluatorPlaintext.Add(resCt[j], ciphertextList[i][j], resCt[j])
				}
				res[j] = evaluatorPlaintext.Eval(resCt[j])
			}
		}
	})

	return res
}

func benchDec(resCt []*vche_2.Ciphertext, resVerif []*vche_2.Poly, numCt int, b *testing.B) [][]int64 {
	b.Run(benchmarkString("Communication/SP->Clients"), func(b *testing.B) {
		b.ReportMetric(float64(len(resCt)*resCt[0].Len()), "BFV-ctxt")
		b.ReportMetric(float64(size.Of(resCt)), "bytes")
		b.ReportMetric(0.0, "ns/op")
	})

	resPt := make([]*vche_2.Plaintext, numCt)
	res := make([][]int64, numCt)
	for i := range resPt {
		resPt[i] = vche_2.NewPlaintext(params)
		res[i] = make([]int64, params.NSlots)
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
				encoder.DecodeInt(resPt[j], resVerif[j], res[j])
			}
		}
	})
	return res
}

func benchmarkString(opname string) string {
	return "PE/CFPRF/" + opname
}
