package vche

import (
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/rlwe"
	"github.com/ldsec/lattigo/v2/utils"
	"testing"
)

type testContext struct {
	params      bfv.Parameters
	ringQ       *ring.Ring
	ringT       *ring.Ring
	prng        utils.PRNG
	uSampler    *ring.UniformSampler
	encoder     bfv.Encoder
	kgen        rlwe.KeyGenerator
	sk          *rlwe.SecretKey
	rlk         *rlwe.RelinearizationKey
	evk         *rlwe.EvaluationKey
	rots        []int
	rotsEvk     rlwe.EvaluationKey
	encryptorSk bfv.Encryptor
	decryptor   bfv.Decryptor
	evaluator   bfv.Evaluator
}

func genTestParams(params bfv.Parameters) (testctx *testContext, err interface{}) {
	testctx = new(testContext)
	testctx.params = params

	if testctx.prng, err = utils.NewPRNG(); err != nil {
		return nil, err
	}

	testctx.ringQ = params.RingQ()
	testctx.ringT = params.RingT()

	testctx.uSampler = ring.NewUniformSampler(testctx.prng, testctx.ringT)
	testctx.kgen = bfv.NewKeyGenerator(testctx.params)
	//testctx.sk, testctx.pk = testctx.kgen.GenKeyPair()
	testctx.sk = testctx.kgen.GenSecretKey()
	if params.PCount() != 0 {
		testctx.rlk = testctx.kgen.GenRelinearizationKey(testctx.sk, 1)
	}

	testctx.encoder = bfv.NewEncoder(testctx.params)
	testctx.evk = &rlwe.EvaluationKey{Rlk: testctx.rlk, Rtks: nil}
	testctx.rots = []int{1}
	testctx.rotsEvk = rlwe.EvaluationKey{Rlk: testctx.rlk, Rtks: testctx.kgen.GenRotationKeysForRotations(testctx.rots, true, testctx.sk)}

	testctx.encryptorSk = bfv.NewEncryptor(testctx.params, testctx.sk)
	testctx.decryptor = bfv.NewDecryptor(testctx.params, testctx.sk)
	testctx.evaluator = bfv.NewEvaluator(testctx.params, *testctx.evk)
	return
}

func testStringNoSplit(opname string, p bfv.Parameters) string {
	return fmt.Sprintf("%sLogN=%d&logQ=%d&alpha=%d&beta=%d", opname, p.LogN(), p.LogQP(), p.PCount(), p.Beta())
}

func BenchmarkVCHEBFV(b *testing.B) {
	var err interface{}
	paramsLiteral := bfv.PN14QP438

	params, err := bfv.NewParametersFromLiteral(paramsLiteral)
	testctx, err := genTestParams(params)
	if err != nil {
		panic(err)
	}

	benchEncoder(testctx, b)
	benchEncrypt(testctx, b)
	benchDecrypt(testctx, b)
	benchEvaluator(testctx, b)
}

func benchEncoder(testctx *testContext, b *testing.B) {
	encoder := testctx.encoder
	coeffsOut := make([]uint64, testctx.params.N())
	coeffs := GetRandomCoeffs(testctx.params.N(), testctx.params.T())

	plaintext := bfv.NewPlaintext(testctx.params)

	b.Run(testStringNoSplit("Encoder/EncodeUint/", testctx.params), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			encoder.EncodeUint(coeffs, plaintext)
		}
	})

	b.Run(testStringNoSplit("Encoder/DecodeUint/", testctx.params), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			testctx.encoder.DecodeUint(plaintext, coeffsOut)
		}
	})
}

func benchEncrypt(testctx *testContext, b *testing.B) {

	//encryptorPk := testctx.encryptorPk
	encryptorSk := testctx.encryptorSk

	plaintext := bfv.NewPlaintext(testctx.params)
	ciphertext := bfv.NewCiphertextRandom(testctx.prng, testctx.params, 1)

	b.Run(testStringNoSplit("Encrypt/", testctx.params), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			encryptorSk.Encrypt(plaintext, ciphertext)
		}
	})
}

func benchDecrypt(testctx *testContext, b *testing.B) {
	decryptor := testctx.decryptor
	ciphertext := bfv.NewCiphertextRandom(testctx.prng, testctx.params, 1)

	b.Run(testStringNoSplit("Decrypt/", testctx.params), func(b *testing.B) {
		plaintext := bfv.NewPlaintext(testctx.params)
		for i := 0; i < b.N; i++ {
			decryptor.Decrypt(ciphertext, plaintext)
		}
	})
}

func benchEvaluator(testctx *testContext, b *testing.B) {
	encoder := testctx.encoder

	plaintext := bfv.NewPlaintext(testctx.params)

	coeffs := GetRandomCoeffs(testctx.params.N(), testctx.params.T())
	encoder.EncodeUint(coeffs, plaintext)

	ciphertext1 := bfv.NewCiphertextRandom(testctx.prng, testctx.params, 1)
	ciphertext2 := bfv.NewCiphertextRandom(testctx.prng, testctx.params, 1)
	receiver := bfv.NewCiphertextRandom(testctx.prng, testctx.params, 2)

	var rotkey *rlwe.RotationKeySet
	if testctx.params.PCount() != 0 {
		rotkey = testctx.kgen.GenRotationKeysForRotations([]int{1}, true, testctx.sk)
	}
	evaluator := testctx.evaluator.WithKey(rlwe.EvaluationKey{Rlk: testctx.rlk, Rtks: rotkey})

	b.Run(testStringNoSplit("Evaluator/Add/", testctx.params), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			evaluator.Add(ciphertext1, ciphertext2, ciphertext1)
		}
	})

	b.Run(testStringNoSplit("Evaluator/MulScalar/", testctx.params), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			evaluator.MulScalar(ciphertext1, 5, ciphertext1)
		}
	})

	ctxtDeg2 := bfv.NewCiphertext(testctx.params, 2)
	b.Run(testStringNoSplit("Evaluator/Mul/deg=1/deg=1/", testctx.params), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			evaluator.Mul(ciphertext1, ciphertext1, ctxtDeg2)
		}
	})

	evaluator.Relinearize(ctxtDeg2, ctxtDeg2)
	ctxtDeg4 := bfv.NewCiphertext(testctx.params, 2)
	b.Run(testStringNoSplit("Evaluator/Mul/deg=2/deg=2/", testctx.params), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			evaluator.Mul(ctxtDeg2, ctxtDeg2, ctxtDeg4)
		}
	})

	evaluator.Relinearize(ctxtDeg4, ctxtDeg4)
	ctxtDeg8 := bfv.NewCiphertext(testctx.params, 2)
	b.Run(testStringNoSplit("Evaluator/Mul/deg=4/deg=4/", testctx.params), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			evaluator.Mul(ctxtDeg4, ctxtDeg4, ctxtDeg8)
		}
	})

	evaluator.Mul(ciphertext1, ciphertext2, receiver)
	b.Run(testStringNoSplit("Evaluator/Relin/", testctx.params), func(b *testing.B) {

		if testctx.params.PCount() == 0 {
			b.Skip("#Pi is empty")
		}

		for i := 0; i < b.N; i++ {
			evaluator.Relinearize(receiver, ciphertext1)
		}
	})

	b.Run(testStringNoSplit("Evaluator/RotateRows/", testctx.params), func(b *testing.B) {

		if testctx.params.PCount() == 0 {
			b.Skip("#Pi is empty")
		}

		for i := 0; i < b.N; i++ {
			evaluator.RotateRows(ciphertext1, ciphertext1)
		}
	})

	b.Run(testStringNoSplit("Evaluator/RotateCols/", testctx.params), func(b *testing.B) {

		if testctx.params.PCount() == 0 {
			b.Skip("#Pi is empty")
		}

		for i := 0; i < b.N; i++ {
			evaluator.RotateColumns(ciphertext1, 1, ciphertext1)
		}
	})
}
