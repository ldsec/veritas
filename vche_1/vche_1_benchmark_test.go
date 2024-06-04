package vche_1

import (
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/rlwe"
	"veritas/vche/vche"
	"testing"
)

func BenchmarkVCHE1(b *testing.B) {
	var err interface{}
	paramsLiteral := ParametersLiteral{
		bfv.PN14QP438,
		64,
		1,
	}
	params, err := NewParametersFromLiteral(paramsLiteral)
	testctx, err := genTestParams(params)
	if err != nil {
		panic(err)
	}

	benchEncoder(testctx, b)
	benchEncrypt(testctx, b)
	benchDecrypt(testctx, b)
	benchEvaluator(testctx, b)
	benchEvaluatorPlaintext(testctx, b)
}

func benchEncoder(testctx *testContext, b *testing.B) {
	encoder := testctx.encoder
	coeffsOut := make([]uint64, testctx.params.NSlots)
	coeffs := vche.GetRandomCoeffs(testctx.params.NSlots, testctx.params.T())
	tags := vche.GetRandomTags(testctx.params.NSlots)
	verif := testctx.evaluatorPlaintextEncoder.EncodeNew(tags)

	plaintext := NewPlaintext(testctx.params)

	b.Run(testStringNoSplit("Encoder/EncodeUint/", testctx.params), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			encoder.EncodeUint(coeffs, tags, plaintext)
		}
	})

	encoder.EncodeUint(coeffs, tags, plaintext)

	b.Run(testStringNoSplit("Encoder/DecodeUint/", testctx.params), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			testctx.encoder.DecodeUint(plaintext, verif, coeffsOut)
		}
	})
}

func benchEncrypt(testctx *testContext, b *testing.B) {

	//encryptorPk := testctx.encryptorPk
	encryptorSk := testctx.encryptorSk

	plaintext := NewPlaintext(testctx.params)
	ciphertext := NewCiphertextRandom(testctx.prng, testctx.params, 1)

	b.Run(testStringNoSplit("Encrypt/", testctx.params), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			encryptorSk.Encrypt(plaintext, ciphertext)
		}
	})
}

func benchDecrypt(testctx *testContext, b *testing.B) {
	decryptor := testctx.decryptor
	ciphertext := NewCiphertextRandom(testctx.prng, testctx.params, 1)

	b.Run(testStringNoSplit("Decrypt/", testctx.params), func(b *testing.B) {
		plaintext := NewPlaintext(testctx.params)
		for i := 0; i < b.N; i++ {
			decryptor.Decrypt(ciphertext, plaintext)
		}
	})
}

func benchEvaluator(testctx *testContext, b *testing.B) {
	encoder := testctx.encoder

	plaintext := NewPlaintext(testctx.params)

	coeffs := vche.GetRandomCoeffs(testctx.params.NSlots, testctx.params.T())
	tags := vche.GetRandomTags(testctx.params.NSlots)
	encoder.EncodeUint(coeffs, tags, plaintext)

	ciphertext1 := NewCiphertextRandom(testctx.prng, testctx.params, 1)
	ciphertext2 := NewCiphertextRandom(testctx.prng, testctx.params, 1)
	receiver := NewCiphertextRandom(testctx.prng, testctx.params, 2)

	var rotkey *RotationKeySet
	if testctx.params.PCount() != 0 {
		rotkey = testctx.kgen.GenRotationKeysForRotations([]int{1}, true, testctx.sk)
	}
	evaluator := testctx.evaluator.WithKey(EvaluationKey{rlwe.EvaluationKey{Rlk: testctx.rlk.RelinearizationKey, Rtks: rotkey.RotationKeySet}, testctx.rlk.H})

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

	ctxtDeg2 := NewCiphertext(testctx.params, 2)
	b.Run(testStringNoSplit("Evaluator/Mul/deg=1/deg=1/", testctx.params), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			evaluator.Mul(ciphertext1, ciphertext1, ctxtDeg2)
		}
	})

	evaluator.Relinearize(ctxtDeg2, ctxtDeg2)
	ctxtDeg4 := NewCiphertext(testctx.params, 2)
	b.Run(testStringNoSplit("Evaluator/Mul/deg=2/deg=2/", testctx.params), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			evaluator.Mul(ctxtDeg2, ctxtDeg2, ctxtDeg4)
		}
	})

	evaluator.Relinearize(ctxtDeg4, ctxtDeg4)
	ctxtDeg8 := NewCiphertext(testctx.params, 2)
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

func benchEvaluatorPlaintext(testctx *testContext, b *testing.B) {

	tags1 := vche.GetRandomTags(testctx.params.NSlots)
	tags2 := vche.GetRandomTags(testctx.params.NSlots)

	op1 := testctx.evaluatorPlaintextEncoder.EncodeNew(tags1)
	op2 := testctx.evaluatorPlaintextEncoder.EncodeNew(tags2)
	receiver := NewTaggedPoly(testctx.params)

	evaluator := testctx.evaluatorPlaintext

	b.Run(testStringNoSplit("EvaluatorPlaintext/Add/", testctx.params), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			evaluator.Add(op1, op2, op1)
		}
	})

	b.Run(testStringNoSplit("EvaluatorPlaintext/MulScalar/", testctx.params), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			evaluator.MulScalar(op1, 5, op1)
		}
	})

	opDeg2 := NewTaggedPoly(testctx.params)
	b.Run(testStringNoSplit("EvaluatorPlaintext/Mul/deg=1/deg=1/", testctx.params), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			evaluator.Mul(op1, op2, opDeg2)
		}
	})

	evaluator.Relinearize(opDeg2, opDeg2)
	opDeg4 := NewTaggedPoly(testctx.params)
	b.Run(testStringNoSplit("EvaluatorPlaintext/Mul/deg=2/deg=2/", testctx.params), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			evaluator.Mul(opDeg2, opDeg2, opDeg4)
		}
	})

	evaluator.Relinearize(opDeg4, opDeg4)
	opDeg8 := NewTaggedPoly(testctx.params)
	b.Run(testStringNoSplit("EvaluatorPlaintext/Mul/deg=4/deg=4/", testctx.params), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			evaluator.Mul(opDeg4, opDeg4, opDeg8)
		}
	})

	evaluator.Mul(op1, op2, receiver)
	b.Run(testStringNoSplit("EvaluatorPlaintext/Relin/", testctx.params), func(b *testing.B) {

		if testctx.params.PCount() == 0 {
			b.Skip("#Pi is empty")
		}

		for i := 0; i < b.N; i++ {
			evaluator.Relinearize(receiver, op1)
		}
	})

	b.Run(testStringNoSplit("EvaluatorPlaintext/RotateRows/", testctx.params), func(b *testing.B) {

		if testctx.params.PCount() == 0 {
			b.Skip("#Pi is empty")
		}

		for i := 0; i < b.N; i++ {
			evaluator.RotateRows(op1, op1)
		}
	})

	b.Run(testStringNoSplit("EvaluatorPlaintext/RotateCols/", testctx.params), func(b *testing.B) {

		if testctx.params.PCount() == 0 {
			b.Skip("#Pi is empty")
		}

		for i := 0; i < b.N; i++ {
			evaluator.RotateColumns(op1, 1, op1)
		}
	})
}
