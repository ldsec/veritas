package vche_2

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRunPolynomialProtocol(t *testing.T) {
	for _, paramDef := range DefaultParams[1:] {
		params, err := NewParametersFromLiteral(paramDef)
		if err != nil {
			panic(err)
		}

		testctx, err := genTestParams(params)
		if err != nil {
			panic(err)
		}
		_, _, _, ctxt, verifPtxt := newTestVectors(testctx, testctx.encryptorSk, params.T())

		require.NotPanics(t, func() {
			_ = RunPolynomialProtocolUint(testctx.prover, testctx.verifier, ctxt, verifPtxt)
		}, testString("RunPolynomialProtocol", params))
	}
}
