package neural_network

import (
	"os"
	"path"
)

var weightsConvSmall = make([]float64, 5*5*5)
var biasConvSmall = make([]float64, 5)
var weightLinSmall = make([]float64, 10*245)
var biasLinSmall = make([]float64, 10)

func init() {
	p, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	p = path.Clean(path.Join(p, "../models/LoLa_MNIST_small/"))

	names := []string{"conv1.weight.csv", "conv1.bias.csv", "lin1.weight.csv", "lin1.bias.csv"}
	arrs := [][]float64{weightsConvSmall, biasConvSmall, weightLinSmall, biasLinSmall}
	for i := range names {
		readWeights(path.Join(p, names[i]), arrs[i])
	}
}
