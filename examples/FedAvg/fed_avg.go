package FedAvg

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
)

var BfvParams bfv.Parameters

var NumClients = 10
var NumEpochs = 5

func init() {
	paramDef := bfv.PN15QP880
	paramDef.T = 36028797019488257 // 55 bits

	var err interface{}
	BfvParams, err = bfv.NewParametersFromLiteral(paramDef)
	if err != nil {
		panic(err)
	}
}

func ReadCsvFiles(filePath string, cntClient int) ([][]int64, []int64, int) {
	// Import data
	csvFile, errCsv := os.Open(filePath)
	if errCsv != nil {
		log.Fatal("[FATAL] Cannot read CSV file "+filePath, errCsv)
	}
	defer func(csvFile *os.File) {
		err := csvFile.Close()
		if err != nil {

		}
	}(csvFile)

	// Create vectors
	localWeights := make([][]int64, cntClient)
	var globalWeights []int64

	// Create reader
	reader := csv.NewReader(bufio.NewReader(csvFile))
	cnt := int(0)
	for {
		line, error := reader.Read()
		if error == io.EOF {
			break
		} else if error != nil {
			log.Fatal(error)
		}

		// Init weight vectors and check plaintext correctness of FedAvg
		check := int64(0)
		for i := 0; i < cntClient; i++ {
			val, _ := strconv.ParseFloat(line[i], 64)
			localWeights[i] = append(localWeights[i], int64(val))
			check += int64(val)
		}
		val, _ := strconv.ParseFloat(line[cntClient], 64)
		globalWeights = append(globalWeights, int64(val))
		if check != int64(val) {
			panic("Wrong FedAvg")
		}
		cnt++
	}
	return localWeights, globalWeights, cnt
}

func GenDataAndTags(filePath string, cntClient int, NSlots int) ([][][]int64, [][][]vche.Tag, [][]int64) {
	localW, globalW, lineCnt := ReadCsvFiles(filePath, cntClient)
	numPacked := NSlots

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

	// Generate tags
	tags := make([][][]vche.Tag, NSlots)
	for i := 0; i < cntClient; i++ {
		tags[i] = make([][]vche.Tag, numCt)
		for j := 0; j < numCt; j++ {
			tags[i][j] = vche.GetIndexTags([]byte(fmt.Sprintf("client-%d-%d", i, j)), NSlots)
		}
	}

	return ptVectors, tags, ptGlobalVectors
}
