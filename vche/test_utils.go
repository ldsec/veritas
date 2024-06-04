package vche

import (
	"encoding/binary"
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/utils"
	"math"
	"math/bits"
)

func GetRandomCoeffs(N int, maxValue uint64) []uint64 {
	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}

	mask := uint64(1<<uint64(bits.Len64(maxValue))) - 1

	coeffs := make([]uint64, N)
	for i := range coeffs {
		coeffs[i] = ring.RandUniform(prng, maxValue, mask)
	}
	return coeffs
}

func GetRandomTags(N int) []Tag {
	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}

	datasetTag := make([]byte, 8)
	prng.Clock(datasetTag)

	tags := make([]Tag, N)
	for i := range tags {
		messageTag := make([]byte, 8)
		prng.Clock(messageTag)

		tags[i] = Tag{datasetTag, messageTag}
	}
	return tags
}

func GetRandomTagsSameIndex(N int) []Tag {
	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}

	datasetTag := make([]byte, 8)
	prng.Clock(datasetTag)

	tags := make([]Tag, N)
	for i := range tags {
		messageTag := make([]byte, 8)
		binary.BigEndian.PutUint64(messageTag, uint64(i))

		tags[i] = Tag{datasetTag, messageTag}
	}
	return tags
}

func GetTags(datasetTag []byte, indexTags [][]byte) []Tag {
	res := make([]Tag, len(indexTags))
	for i := range indexTags {
		res[i] = Tag{datasetTag, indexTags[i]}
	}
	return res
}

func GetIndexTags(datasetTag []byte, N int) []Tag {
	tags := make([]Tag, N)
	for i := range tags {
		messageTag := make([]byte, 8)
		binary.BigEndian.PutUint64(messageTag, uint64(i))
		tags[i] = Tag{datasetTag, messageTag}
	}
	return tags
}

func GetRandom(maxValue uint64) uint64 {
	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}
	mask := uint64(1<<uint64(bits.Len64(maxValue))) - 1
	return ring.RandUniform(prng, maxValue, mask)
}

func ApplyBinOp(op func(uint64, uint64) uint64, op0, op1 []uint64) []uint64 {
	res := make([]uint64, len(op0))
	for i := range op0 {
		res[i] = op(op0[i], op1[i])
	}
	return res
}

func ApplyUnOp(op func(uint64) uint64, op0 []uint64) []uint64 {
	res := make([]uint64, len(op0))
	for i := range op0 {
		res[i] = op(op0[i])
	}
	return res
}

func PrintCryptoParams(ps interface{}) {
	switch params := ps.(type) {
	case bfv.Parameters:
		fmt.Printf("Parameters : logN=%d, T=%d, logT=%d, logQ=%d, sigma = %f\n",
			params.LogN(), params.T(), uint64(math.Log2(float64(params.T()))), params.LogQ(), params.Sigma())
	case Parameters:
		fmt.Printf("Parameters : logN=%d, T=%d, logT=%d, logQ=%d, sigma = %f, NumReplications=%d, NSlots=%d\n",
			params.LogN(), params.T(), uint64(math.Log2(float64(params.T()))), params.LogQ(), params.Sigma(), params.NumReplications, params.NSlots)
	default:
		panic(fmt.Errorf("unexpected parameters argument"))
	}
}
