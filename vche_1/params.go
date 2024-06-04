package vche_1

import (
	"github.com/ldsec/lattigo/v2/bfv"
	"veritas/vche/vche"
)

type ParametersLiteral = vche.ParametersLiteral
type Parameters = vche.Parameters

var DefaultParams []ParametersLiteral = nil
var DefaultPostQuantumParams []ParametersLiteral = nil
var DefaultNumReplications = 64

func init() {
	DefaultParams = make([]ParametersLiteral, len(bfv.DefaultParams)+1)
	for i := range bfv.DefaultParams {
		DefaultParams[i] = ParametersLiteral{ParametersLiteral: bfv.DefaultParams[i], NumReplications: DefaultNumReplications, NumDistinctPRFKeys: 1}
	}
	DefaultParams[len(DefaultParams)-1] = ParametersLiteral{ParametersLiteral: vche.BfvPN16, NumReplications: 1, NumDistinctPRFKeys: 1}

	DefaultPostQuantumParams = make([]ParametersLiteral, len(bfv.DefaultPostQuantumParams))
	for i := range bfv.DefaultPostQuantumParams {
		DefaultPostQuantumParams[i] = ParametersLiteral{ParametersLiteral: bfv.DefaultPostQuantumParams[i], NumReplications: DefaultNumReplications, NumDistinctPRFKeys: 1}
	}
}

func NewParameters(bfvParams bfv.Parameters, numReplications int) (p Parameters, err error) {
	return vche.NewParameters(bfvParams, numReplications, 1)
}

func NewParametersFromLiteral(pl ParametersLiteral) (Parameters, error) {
	return vche.NewParametersFromLiteral(pl)
}
