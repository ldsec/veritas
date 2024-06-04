package ObliviousRiding

import (
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/utils"
	"veritas/vche/vche"
	"math"
	"math/bits"
	"strconv"
)

var BfvParams bfv.Parameters
var NDrivers = 32

func init() {
	paramDef := bfv.PN15QP880
	paramDef.T = 72057594038321153 // 56 bits

	var err interface{}
	BfvParams, err = bfv.NewParametersFromLiteral(paramDef)
	if err != nil {
		panic(err)
	}
}

func GenDataAndTags(nbDrivers int, NSlots int, T uint64) ([]uint64, [][]uint64, []vche.Tag, [][]vche.Tag) {
	maxvalue := uint64(math.Sqrt(float64(T)))   // max values = floor(sqrt(plaintext modulus))
	mask := uint64(1<<bits.Len64(maxvalue) - 1) // binary mask upper-bound for the uniform sampling

	fmt.Printf("Generating %d driversData and 1 Rider randomly positioned on a grid of %d x %d units \n",
		nbDrivers, maxvalue, maxvalue)
	fmt.Println()

	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}

	riderData := make([]uint64, NSlots)
	riderTags := make([]vche.Tag, NSlots)
	riderPosX, riderPosY := ring.RandUniform(prng, maxvalue, mask), ring.RandUniform(prng, maxvalue, mask)

	driversData := make([][]uint64, nbDrivers)
	driversTags := make([][]vche.Tag, nbDrivers)
	for i := 0; i < nbDrivers; i++ {
		riderData[(i << 1)] = riderPosX
		riderData[(i<<1)+1] = riderPosY

		driversData[i] = make([]uint64, NSlots)
		driversData[i][(i << 1)] = ring.RandUniform(prng, maxvalue, mask)
		driversData[i][(i<<1)+1] = ring.RandUniform(prng, maxvalue, mask)

		driversTags[i] = make([]vche.Tag, NSlots)
	}

	indexTags := make([][]byte, NSlots)

	for j := 0; j < NSlots/2; j++ {
		indexTags[(j << 1)] = []byte("x" + strconv.Itoa(j))
		indexTags[(j<<1)+1] = []byte("y" + strconv.Itoa(j))
	}
	riderTags = vche.GetTags([]byte("Rider"), indexTags)
	for i := range driversTags {
		driversTags[i] = vche.GetTags([]byte("Driver_"+strconv.Itoa(i)), indexTags)
	}

	return riderData, driversData, riderTags, driversTags
}

func FindClosestAndCheck(result []uint64, riderData []uint64, driversData [][]uint64) {
	minIndex, minPosX, minPosY, minDist := 0, uint64(math.MaxUint64), uint64(math.MaxUint64), uint64(math.MaxUint64)

	riderPosX, riderPosY := riderData[0], riderData[1]

	errors := 0

	nbDrivers := len(driversData)
	for i := 0; i < nbDrivers; i++ {

		driverPosX, driverPosY := driversData[i][i<<1], driversData[i][(i<<1)+1]

		computedDist := result[i<<1] + result[(i<<1)+1]
		expectedDist := distance(driverPosX, driverPosY, riderPosX, riderPosY)

		if computedDist == expectedDist {
			if computedDist < minDist {
				minIndex = i
				minPosX, minPosY = driverPosX, driverPosY
				minDist = computedDist
			}
		} else {
			errors++
		}

		//if i < 4 || i > nbDrivers-5 {
		//	fmt.Printf("Distance with Driver %d : %8d = (%4d - %4d)^2 + (%4d - %4d)^2 --> correct: %t\n",
		//		i, computedDist, driverPosX, riderPosX, driverPosY, riderPosY, computedDist == expectedDist)
		//}
		//
		//if i == nbDrivers>>1 {
		//	fmt.Println("...")
		//}
	}

	fmt.Printf("\nFinished with %.2f%% errors\n\n", 100*float64(errors)/float64(nbDrivers))
	fmt.Printf("Closest Driver to Rider is n°%d (%d, %d) with a distance of %d units\n",
		minIndex, minPosX, minPosY, int(math.Sqrt(float64(minDist))))
}

func distance(a, b, c, d uint64) uint64 {
	if a > c {
		a, c = c, a
	}
	if b > d {
		b, d = d, b
	}
	x, y := a-c, b-d
	return x*x + y*y
}
