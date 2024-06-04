package neural_network

import (
	"github.com/ldsec/lattigo/v2/bfv"
)

func main() {
	// Initialize parameters
	paramsLiteral := bfv.PN13QP218
	paramsLiteral.T = 557057 // 638977, 737281, 786433

	params, err := bfv.NewParametersFromLiteral(paramsLiteral)
	if err != nil {
		panic(err)
	}
	_ = params
}
