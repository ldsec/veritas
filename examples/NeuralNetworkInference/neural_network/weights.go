package neural_network

import (
	"os"
	"path"
)

var weightsConv = make([]float64, 5*5*5)
var biasConv = make([]float64, 5)
var weightsLin1 = make([]float64, 845*100)
var biasLin1 = make([]float64, 100)
var weightsLin2 = make([]float64, 100*10)
var biasLin2 = make([]float64, 10)

func init() {
	p, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	p = path.Clean(path.Join(p, "../models/LoLa_MNIST/"))

	names := []string{"conv1.weight.csv", "conv1.bias.csv", "lin1.weight.csv", "lin1.bias.csv", "lin2.weight.csv", "lin2.bias.csv"}
	arrs := [][]float64{weightsConv, biasConv, weightsLin1, biasLin1, weightsLin2, biasLin2}
	for i := range names {
		_, _ = i, arrs
		readWeights(path.Join(p, names[i]), arrs[i])
	}
}
