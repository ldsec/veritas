	// Taken from Lattigo's BFV example
	// This example simulates a situation where an anonymous rider
	// wants to find the closest available rider within a given area.
	// The application is inspired by the paper https://oride.epfl.ch/
	//
	// 		A. Pham, I. Dacosta, G. Endignoux, J. Troncoso-Pastoriza,
	//		K. Huguenin, and J.-P. Hubaux. ORide: A Privacy-Preserving
	//		yet Accountable Ride-Hailing Service. In Proceedings of the
	//		26th USENIX Security Symposium, Vancouver, BC, Canada, August 2017.
	//
	// Each area is represented as a rectangular grid where each driver
	// anyonymously signs in (i.e. the server only knows the driver is located
	// in the area).
	//
	// First, the rider generates an ephemeral key pair (riderSk, riderPk), which she
	// uses to encrypt her coordinates. She then sends the tuple (riderPk, enc(coordinates))
	// to the server handling the area she is in.
	//
	// Once the public key and the encrypted rider coordinates of the rider
	// have been received by the server, the rider's public key is transferred
	// to all the drivers within the area, with a randomized different index
	// for each of them, that indicates in which coefficient each driver must
	// encode her coordinates.
	//
	// Each driver encodes her coordinates in the designated coefficient and
	// uses the received public key to encrypt her encoded coordinates.
	// She then sends back the encrypted coordinates to the server.
	//
	// Once the encrypted coordinates of the drivers have been received, the server
	// homomorphically computes the squared distance: (x0 - x1)^2 + (y0 - y1)^2 between
	// the rider and each of the drivers, and sends back the encrypted result to the rider.
	//
	// The rider decrypts the result and chooses the closest driver.

package main

import (
	"fmt"
	"github.com/ldsec/lattigo/v2/rlwe"
	"veritas/vche/examples/ObliviousRiding"
	"veritas/vche/vche"
	"math"
	"math/bits"
	"strconv"

	"github.com/ldsec/lattigo/v2/utils"

	"github.com/ldsec/lattigo/v2/ring"
	"veritas/vche/vche_1"
)

func obliviousRiding() {

	params, err := vche_1.NewParameters(ObliviousRiding.BfvParams, 64)
	if err != nil {
		panic(err)
	}

	// Number of drivers in the area
	nbDrivers := ObliviousRiding.NDrivers

	// Rider's keygen
	kgen := vche_1.NewKeyGenerator(params)
	riderSk, riderPk := kgen.GenKeyPair()
	decryptor := vche_1.NewDecryptor(params, riderSk)
	encryptorRiderPk := vche_1.NewEncryptor(params, riderPk)
	encryptorRiderSk := vche_1.NewEncryptor(params, riderSk)

	// evk is only needed to store the hash function
	evk := &vche_1.EvaluationKey{
		EvaluationKey: rlwe.EvaluationKey{},
		H:             riderSk.H,
	}
	evaluator := vche_1.NewEvaluator(params, evk)
	evaluatorPlaintext := vche_1.NewEvaluatorPlaintextCFPRF(params, riderSk.H)
	evaluatorPlaintextEncoder := vche_1.NewEncoderPlaintextCFPRF(params, riderSk.K)

	encoder := vche_1.NewEncoder(params, riderSk.K, riderSk.S, true)

	vche.PrintCryptoParams(params)

	maxvalue := uint64(math.Sqrt(float64(params.T()))) // max values = floor(sqrt(plaintext modulus))
	mask := uint64(1<<bits.Len64(maxvalue) - 1)        // binary mask upper-bound for the uniform sampling

	fmt.Printf("Generating %d driversData and 1 Rider randomly positioned on a grid of %d x %d units \n",
		nbDrivers, maxvalue, maxvalue)

	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}
	// Rider coordinates [x, y, x, y, ....., x, y]
	riderPosX, riderPosY := ring.RandUniform(prng, maxvalue, mask), ring.RandUniform(prng, maxvalue, mask)

	Rider := make([]uint64, params.NSlots)
	RiderTags := make([]vche.Tag, params.NSlots)
	for i := 0; i < nbDrivers; i++ {
		Rider[(i << 1)] = riderPosX
		Rider[(i<<1)+1] = riderPosY
	}
	for j := 0; j < params.NSlots/2; j++ {
		RiderTags[(j << 1)] = str2tag("Rider", "x"+strconv.Itoa(j))
		RiderTags[(j<<1)+1] = str2tag("Rider", "y"+strconv.Itoa(j))
	}

	riderPlaintext := vche_1.NewPlaintext(params)
	encoder.EncodeUint(Rider, RiderTags, riderPlaintext)

	// driversData coordinates [0, 0, ..., x, y, ..., 0, 0]
	driversData := make([][]uint64, nbDrivers)

	driversPlaintexts := make([]*vche_1.Plaintext, nbDrivers)
	driversTags := make([][]vche.Tag, nbDrivers)
	driversVerif := make([]*vche_1.VerifPlaintext, nbDrivers)
	for i := 0; i < nbDrivers; i++ {
		driversData[i] = make([]uint64, params.NSlots)
		driversData[i][(i << 1)] = ring.RandUniform(prng, maxvalue, mask)
		driversData[i][(i<<1)+1] = ring.RandUniform(prng, maxvalue, mask)

		driversTags[i] = make([]vche.Tag, params.NSlots)
	}

	for j := 0; j < params.NSlots/2; j++ {
		for i := 0; i < nbDrivers; i++ {
			driversTags[i][(j << 1)] = str2tag("Driver_"+strconv.Itoa(i), "x"+strconv.Itoa(j))
			driversTags[i][(j<<1)+1] = str2tag("Driver_"+strconv.Itoa(i), "y"+strconv.Itoa(j))
		}
	}

	fmt.Printf("Encrypting %d driversData (x, y) and 1 Rider (%d, %d) \n", nbDrivers, riderPosX, riderPosY)
	fmt.Println()

	RiderCiphertext := encryptorRiderSk.EncryptNew(riderPlaintext)

	DriversCiphertexts := make([]*vche_1.Ciphertext, nbDrivers)
	for i := 0; i < nbDrivers; i++ {
		driversVerif[i] = evaluatorPlaintextEncoder.EncodeNew(driversTags[i])
		driversPlaintexts[i] = encoder.EncodeUintNew(driversData[i], driversTags[i])
		DriversCiphertexts[i] = encryptorRiderPk.EncryptNew(driversPlaintexts[i])
	}

	fmt.Println("Computing encrypted distance = ((CtD1 + CtD2 + CtD3 + CtD4...) - CtR)^2 ...")
	fmt.Println()

	RiderVerif := evaluatorPlaintextEncoder.EncodeNew(RiderTags)

	evaluator.Neg(RiderCiphertext, RiderCiphertext)
	evaluatorPlaintext.Neg(RiderVerif, RiderVerif)
	for i := 0; i < nbDrivers; i++ {
		evaluator.Add(RiderCiphertext, DriversCiphertexts[i], RiderCiphertext)
		evaluatorPlaintext.Add(RiderVerif, driversVerif[i], RiderVerif)
	}

	RiderCiphertext = evaluator.MulNew(RiderCiphertext, RiderCiphertext)
	RiderVerif = evaluatorPlaintext.MulNew(RiderVerif, RiderVerif)
	evaluatorPlaintext.ComputeMemo(RiderVerif)
	result := encoder.DecodeUintNew(decryptor.DecryptNew(RiderCiphertext), evaluatorPlaintext.Eval(RiderVerif))

	minIndex, minPosX, minPosY, minDist := 0, params.T(), params.T(), params.T()

	errors := 0

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

		if i < 4 || i > nbDrivers-5 {
			fmt.Printf("Distance with Driver %d : %8d = (%4d - %4d)^2 + (%4d - %4d)^2 --> correct: %t\n",
				i, computedDist, driverPosX, riderPosX, driverPosY, riderPosY, computedDist == expectedDist)
		}

		if i == nbDrivers>>1 {
			fmt.Println("...")
		}
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

func str2tag(datasetStr, messageStr string) vche.Tag {
	return vche.Tag{[]byte(datasetStr), []byte(messageStr)}
}

func main() {
	obliviousRiding()
}
