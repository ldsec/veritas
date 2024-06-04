package DiseaseSusceptibilityPacked

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"veritas/vche/vche"
	"io"
	"log"
	"math"
	"os"
	"strconv"
	"math/rand"
)

var Disease = "Cancer" // Alzheimer, Bipolar, Cancer, Diabetes, Schizophrenia
var FileStr = "HG01879"
var BfvParams bfv.Parameters
var Precision = int64(1000000)

func init() {
	paramDef := bfv.PN15QP880
	paramDef.T = 72057594038321153 // 56 bits

	var err interface{}
	BfvParams, err = bfv.NewParametersFromLiteral(paramDef)
	if err != nil {
		panic(err)
	}
}

func ReadCsvFiles(fileName string, disease string) ([]float64, []float64, float64, int) {
	// Import SNP data
	csvFile, errCsv := os.Open("../data/" + disease + "/" + fileName + "vec.txt")
	if errCsv != nil {
		log.Fatal("[FATAL] Cannot read snp CSV file ../data/"+fileName+"vec.txt", errCsv)
	}
	defer func(csvFile *os.File) {
		err := csvFile.Close()
		if err != nil {
			panic(err)
		}
	}(csvFile)

	var snp []float64
	reader := csv.NewReader(bufio.NewReader(csvFile))
	cnt := 0
	for {
		line, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Fatal(err)
		}
		val, _ := strconv.ParseFloat(line[0], 64)
		snp = append(snp, val)
		cnt++
	}
	fmt.Printf("number of lines: %d\n", cnt)

	// Import SNPs weights
	var weights []float64
	var normFactor float64
	csvFileWeights, errWCsv := os.Open("../data/weights/" + disease + "weight.txt")
	if errWCsv != nil {
		log.Fatal("[FATAL] Cannot read weights CSV file ../data/"+fileName+"vec.txt", errCsv)
	}
	defer func(csvFileWeights *os.File) {
		err := csvFileWeights.Close()
		if err != nil {
			panic(err)
		}
	}(csvFileWeights)
	readerWeights := csv.NewReader(bufio.NewReader(csvFileWeights))
	for {
		lineWeights, errorW := readerWeights.Read()
		if errorW == io.EOF {
			break
		} else if errorW != nil {
			log.Fatal(errorW)
		}
		valWeight, _ := strconv.ParseFloat(lineWeights[0], 64)
		weights = append(weights, valWeight)
		normFactor += valWeight
	}
	return snp, weights, normFactor, cnt
}


func ReadCsvFilesFullyPacked(fileName string, disease string) ([]float64, []float64, float64, int) {

	N := 1<<BfvParams.LogN()

	// Import SNP data
	csvFile, errCsv := os.Open("../data/" + disease + "/" + fileName + "vec.txt")
	if errCsv != nil {
		log.Fatal("[FATAL] Cannot read snp CSV file ../data/"+fileName+"vec.txt", errCsv)
	}
	defer func(csvFile *os.File) {
		err := csvFile.Close()
		if err != nil {
			panic(err)
		}
	}(csvFile)

	var snp []float64
	reader := csv.NewReader(bufio.NewReader(csvFile))
	cnt := 0
	for {
		line, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Fatal(err)
		}
		val, _ := strconv.ParseFloat(line[0], 64)
		snp = append(snp, val)
		cnt++
	}
	fmt.Printf("number of lines: %d\n", cnt)

	// Import SNPs weights
	var weights []float64
	var normFactor float64
	csvFileWeights, errWCsv := os.Open("../data/weights/" + disease + "weight.txt")
	if errWCsv != nil {
		log.Fatal("[FATAL] Cannot read weights CSV file ../data/"+fileName+"vec.txt", errCsv)
	}
	defer func(csvFileWeights *os.File) {
		err := csvFileWeights.Close()
		if err != nil {
			panic(err)
		}
	}(csvFileWeights)
	readerWeights := csv.NewReader(bufio.NewReader(csvFileWeights))
	for {
		lineWeights, errorW := readerWeights.Read()
		if errorW == io.EOF {
			break
		} else if errorW != nil {
			log.Fatal(errorW)
		}
		valWeight, _ := strconv.ParseFloat(lineWeights[0], 64)
		weights = append(weights, valWeight)
		normFactor += valWeight
	}

	snpVec := make([]float64, N) 
	weightsVec := make([]float64, N) 
	for i := 0; i < N; i++ {
		if i < cnt {
			snpVec[i] = snp[i]
			weightsVec[i] = weights[i]
		}else{
			snpVec[i] = float64(rand.Intn(3))/float64(2)
			weightsVec[i] = 0
		}
	}
	return snpVec, weightsVec, normFactor, N
}


func GenDataAndTags(NSlots int) (snpIntVec, weightIntVec [][]uint64, snpTags, weightTags [][]vche.Tag, precision int64, normFactor float64, cnt int, resExpected float64) {
	// Import CSV files
	snpVec, weightVec, normFactor, cnt := ReadCsvFilesFullyPacked(FileStr, Disease)
	fmt.Printf("File %v with %v SNP entries\n", FileStr, cnt)
	precision = Precision

	// Float result
	for i := 0; i < cnt; i++ {
		resExpected += snpVec[i] * weightVec[i] / normFactor
	}
	fmt.Printf("Expected disease susceptibility is: %v\n", resExpected)

	// Convert data to integers
	if len(snpVec) != len(weightVec) {
		panic("Mismatch in vector lengths: SNP != weights")
	}

	numVec := int(math.Ceil(float64(cnt) / float64(NSlots)))
	fmt.Printf("Packing into %v Ciphertext\n", numVec)
	snpIntVec = make([][]uint64, numVec)
	weightIntVec = make([][]uint64, numVec)

	snpTags = make([][]vche.Tag, numVec)
	weightTags = make([][]vche.Tag, numVec)

	for i := 0; i < numVec; i++ {
		snpIntVec[i] = make([]uint64, NSlots)
		snpTags[i] = vche.GetIndexTags([]byte("snp-"+strconv.Itoa(i)), NSlots)

		weightIntVec[i] = make([]uint64, NSlots)
		weightTags[i] = vche.GetIndexTags([]byte("weight-"+strconv.Itoa(i)), NSlots)
	}

	for i := 0; i < cnt; i++ {
		j := int(math.Floor(float64(i) / float64(NSlots)))
		k := i - NSlots*j

		snpIntVec[j][k] = uint64(math.Floor(2 * snpVec[i]))
		weightIntVec[j][k] = uint64(math.Floor(weightVec[i] * float64(precision)))
	}

	return snpIntVec, weightIntVec, snpTags, weightTags, precision, normFactor, cnt, resExpected
}

func CheckResult(res, resExpected float64) {
	fmt.Println("============================================")
	fmt.Printf("Disease Susceptibility Results: %v\n", Disease)
	fmt.Println("============================================")
	fmt.Println()
	fmt.Printf("Disease susceptibility is: %v\n", res)
	errorR := (res - resExpected) / resExpected * 100
	errorA := res - resExpected

	fmt.Printf("Error %v\n", errorA)
	fmt.Printf("Relative error %v\n", errorR)
}
