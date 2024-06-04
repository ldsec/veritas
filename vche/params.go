package vche

import (
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/rlwe"
)

var BfvPN16 = bfv.ParametersLiteral{
	LogN: 16,
	T:    0xffffffffffc0001,
	Q: []uint64{0x10000000006e0001,
		0xfffffffff840001,
		0x1000000000860001,
		0xfffffffff6a0001,
		0x1000000000980001,
		0xfffffffff5a0001,
		0x1000000000b00001,
		0x1000000000ce0001,
		0xfffffffff2a0001,
		0xfffffffff240001,
		0x1000000000f00001,
		0xffffffffefe0001,
		0x10000000011a0001,
		0xffffffffeca0001,
		0xffffffffe9e0001,
		0xffffffffe7c0001,
		0xffffffffe740001,
		0x10000000019a0001,
		0x1000000001a00001,
		0xffffffffe520001,
		0xffffffffe4c0001,
		0xffffffffe440001,
		0x1000000001be0001,
		0xffffffffe400001},
	P: []uint64{0x1fffffffffe00001,
		0x1fffffffffc80001,
		0x2000000000460001,
		0x1fffffffffb40001,
		0x2000000000500001},
	Sigma: rlwe.DefaultSigma,
}

type ParametersLiteral struct {
	bfv.ParametersLiteral
	NumReplications    int
	NumDistinctPRFKeys int
}

type Parameters struct {
	bfv.Parameters
	NumReplications    int
	NSlots             int
	NumDistinctPRFKeys int
}

func isPow2(x int) bool {
	return x&(x-1) == 0
}

// NewParameters instantiate a set of parameters from the generic BFV parameters and the VC-specific ones.
// It returns the empty parameters Parameters{} and a non-nil error if the specified parameters are invalid.
func NewParameters(bfvParams bfv.Parameters, numReplications int, numDistinctPRFKeys int) (p Parameters, err error) {
	if numReplications <= 0 || !isPow2(numReplications) {
		return Parameters{}, fmt.Errorf("parameter numReplications = %d should be a positive power of two", numReplications)
	}
	if numDistinctPRFKeys <= 0 {
		return Parameters{}, fmt.Errorf("parameter numDistinctPRFKeys = %d should be positive", numDistinctPRFKeys)
	}
	return Parameters{Parameters: bfvParams, NumReplications: numReplications, NSlots: bfvParams.N() / numReplications, NumDistinctPRFKeys: numDistinctPRFKeys}, nil
}

// NewParametersFromLiteral instantiate a set of parameters from a ParametersLiteral specification.
// It returns the empty parameters Parameters{} and a non-nil error if the specified parameters are invalid.
func NewParametersFromLiteral(pl ParametersLiteral) (Parameters, error) {
	params, err := bfv.NewParametersFromLiteral(pl.ParametersLiteral)
	if err != nil {
		return Parameters{}, err
	}
	if !(pl.NumReplications > 0 && (pl.NumReplications%2 == 0 || pl.NumReplications == 1)) {
		return Parameters{}, fmt.Errorf("parameter numReplications = %d should be positive, and either even or 1", pl.NumReplications)
	}
	if pl.NumDistinctPRFKeys <= 0 {
		return Parameters{}, fmt.Errorf("parameter numDistinctPRFKeys = %d should be positive", pl.NumDistinctPRFKeys)
	}

	return Parameters{params, pl.NumReplications, params.N() / pl.NumReplications, pl.NumDistinctPRFKeys}, err
}

func (p Parameters) Equals(other Parameters) bool {
	return p.Parameters.Equals(other.Parameters) && p.NumReplications == other.NumReplications && p.NSlots == other.NSlots && p.NumDistinctPRFKeys == other.NumDistinctPRFKeys
}
