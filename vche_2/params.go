package vche_2

import (
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"veritas/vche/vche"
)

type ParametersLiteral = vche.ParametersLiteral
type Parameters = vche.Parameters

var DefaultParams []ParametersLiteral = nil
var DefaultPostQuantumParams []ParametersLiteral = nil

func init() {
	DefaultParams = make([]ParametersLiteral, len(bfv.DefaultParams)+1)
	for i := range bfv.DefaultParams {
		DefaultParams[i] = ParametersLiteral{ParametersLiteral: bfv.DefaultParams[i], NumReplications: 1, NumDistinctPRFKeys: 1}
	}
	DefaultParams[len(DefaultParams)-1] = ParametersLiteral{ParametersLiteral: vche.BfvPN16, NumReplications: 1, NumDistinctPRFKeys: 1}

	DefaultPostQuantumParams = make([]ParametersLiteral, len(bfv.DefaultPostQuantumParams))
	for i := range bfv.DefaultPostQuantumParams {
		DefaultPostQuantumParams[i] = ParametersLiteral{ParametersLiteral: bfv.DefaultPostQuantumParams[i], NumReplications: 1, NumDistinctPRFKeys: 1}
	}
}

func NewParameters(bfvParams bfv.Parameters) (p Parameters, err error) {
	return vche.NewParameters(bfvParams, 1, 1)
}

func NewParametersFromLiteral(pl ParametersLiteral) (Parameters, error) {
	if pl.NumReplications > 1 || pl.NumDistinctPRFKeys > 1 {
		// Using replication to increase security is disallowed in approach 2, however it might be useful for other applications
		return Parameters{}, fmt.Errorf("replication is disallowed for approach 2 for security reasons; please use 1 for the number of replications and number of distince PRF keys")
	}
	return vche.NewParametersFromLiteral(pl)
}
