package NeuralNetworkInference

import (
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"veritas/vche/vche"
	"github.com/petar/GoMNIST"
	"image/color"
	"math"
)

var BfvParams bfv.Parameters

var MNISTTestImages [][][]uint64
var MNISTTestLabels []uint64

func init() {
	bfvParamsLiteral := bfv.PN15QP880
	bfvParamsLiteral.T = 72057594038321153 // 56 bits

	var err interface{}
	BfvParams, err = bfv.NewParametersFromLiteral(bfvParamsLiteral)

	_, test, err := GoMNIST.Load("../data")
	if err != nil {
		panic(err)
	}

	MNISTTestImages = make([][][]uint64, test.Count())
	MNISTTestLabels = make([]uint64, test.Count())

	for idx := range MNISTTestImages {
		image, label := test.Get(idx)

		MNISTTestImages[idx] = make([][]uint64, 28)
		for i := range MNISTTestImages[idx] {
			MNISTTestImages[idx][i] = make([]uint64, 28)
			for j := 0; j < 28; j++ {
				MNISTTestImages[idx][i][j] = uint64(image.At(j, i).(color.Gray).Y)
			}
		}

		MNISTTestLabels[idx] = uint64(label)
	}
}

func GenTags(imgIdx int, label uint64, numConvs, NSlots int) [][]vche.Tag {
	tags := make([][]vche.Tag, numConvs)
	for i := range tags {
		datasetTag := []byte(fmt.Sprintf("MNIST-idx=%d-lbl=%d-%d", imgIdx, label, i))
		tags[i] = vche.GetIndexTags(datasetTag, NSlots)
	}
	return tags
}

func CheckResult(preds []float64, trueLabel uint64) {
	idxMax, max := -1, math.Inf(-1)
	for i := range preds {
		if preds[i] > max {
			idxMax = i
			max = preds[i]
		}
	}
	fmt.Printf("Predicted label: %d | True label: %d\n", idxMax, trueLabel)
}
