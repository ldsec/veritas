package EncDNS

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"veritas/vche/vche"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
)

var BfvParams bfv.Parameters
var DbFilename = "../dnsDB(512).csv"

var MaxInputLen = 16 // max number of chars
var NumBits = 8      // num of bits representing the chars

var QueryKey = "google.com"

func init() {
	bfvParamDef := vche.BfvPN16
	bfvParamDef.T = 288230376155250689 // 58 bits

	var err interface{}
	BfvParams, err = bfv.NewParametersFromLiteral(bfvParamDef)
	if err != nil {
		panic(err)
	}
}

func LoadDB(dbFilename string, NSlots int) (vecListKeys, vecListVals [][]uint64, numPacked, numVec int) {

	// Read csv to DB
	dataDB := ReadCsvFile(dbFilename)

	// Number of entries in DB
	dbLen := len(dataDB)

	// Pack the data into fully packed ciphertexts
	numPacked = int(math.Ceil(float64(NSlots / (MaxInputLen * NumBits))))
	numVec = int(math.Ceil(float64(dbLen) / float64(numPacked)))
	fmt.Printf("numPacked=%d, numVec=%d\n", numPacked, numVec)

	// Create the vectors
	vecListKeys = make([][]uint64, numVec)
	vecListVals = make([][]uint64, numVec)

	for i := 0; i < numVec; i++ {
		vecListKeys[i] = make([]uint64, NSlots)
		vecListVals[i] = make([]uint64, NSlots)
	}

	// Fill the plaintext vectors
	for i := 0; i < dbLen; i++ {
		tmpKey := dataDB[i][0]
		tmpVal := dataDB[i][1]

		vecIndex := int(math.Floor(float64(i / numPacked)))
		slotIndex := i % numPacked

		for j := 0; j < len(tmpKey); j++ {
			bitReprKey := Bits(int64(tmpKey[j]))
			for k := 0; k < NumBits; k++ {
				vecListKeys[vecIndex][slotIndex*(NumBits*MaxInputLen)+j*NumBits+k] = bitReprKey[k]
			}
		}
		for j := 0; j < len(tmpVal); j++ {
			bitReprVal := Bits(int64(tmpVal[j]))
			for k := 0; k < NumBits; k++ {
				vecListVals[vecIndex][slotIndex*(NumBits*MaxInputLen)+j*NumBits+k] = bitReprVal[k]
			}
		}
	}
	return vecListKeys, vecListVals, numPacked, numVec
}

// Get the query if no input ask the user
func GetQuery(query string, numPacked int, NSlots int) (queryKey []uint64, queryKeyTag []vche.Tag, queryKeyStr string) {
	// If empty query string ask the user
	if len(query) == 0 {
		// read from command line
		fmt.Printf("Please enter the name of a query key (max 16 char): \n")
		reader := bufio.NewReader(os.Stdin)
		text, _ := reader.ReadString('\n')
		// remove the delimeter from the string
		queryKeyStr = strings.TrimSuffix(text, "\n")
	} else {
		queryKeyStr = query
	}

	// Confirm the query
	if len(queryKeyStr) > 16 {
		panic("Query length exceeding 16 chars")
	}
	fmt.Printf("Looking for the value of key [%v]\n", queryKeyStr)

	// Get the query tag
	queryKeyTag = vche.GetIndexTags([]byte("query"), NSlots)

	// Convert query to numerical vector
	queryKey = make([]uint64, NSlots)
	for j := 0; j < len(queryKeyStr); j++ {
		bitReprQ := Bits(int64(queryKeyStr[j]))
		for k := 0; k < 8; k++ {
			for i := 0; i < numPacked; i++ {
				queryKey[i*128+j*8+k] = bitReprQ[k] // 128 maxInputLen*numbits
			}
		}
	}
	return queryKey, queryKeyTag, queryKeyStr
}

// ReadCsvFile is a utility function to parse the csv
func ReadCsvFile(filePath string) [][]string {
	f, err := os.Open(filePath)
	if err != nil {
		str := "[FATAL] Cannot read CSV file " + filePath
		panic(str)
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {

		}
	}(f)

	csvReader := csv.NewReader(f)
	records, err := csvReader.ReadAll()
	if err != nil {
		str := "[FATAL] Cannot parse CSV file " + filePath
		log.Fatal(fmt.Errorf(str))
	}
	return records
}

// Bits converts an integer to a slice of bits
func Bits(val int64) []uint64 {
	bits := make([]uint64, 8)
	for i, b := range strconv.FormatInt(val, 2) {
		if val <= 64 {
			i += 1
		}
		bits[i+1] = uint64(b) - 48 // sub 48 to make the result a bit in {0, 1}
	}
	return bits
}

func DecodeString(resPt []uint64) string {
	resString := ""
	for i := 0; i < MaxInputLen; i++ {
		charI := 0
		for j := 0; j < 8; j++ {
			charI += int(resPt[NumBits*i+j]) * int(math.Pow(2, float64(8-j-1)))
		}
		resString += string(rune(charI))
	}
	resString = strings.Trim(resString, "\000") // Trim null bytes
	return resString
}
