package vche_1_CFPRF

import (
	"encoding/json"
	"flag"
	"github.com/ldsec/lattigo/v2/utils"
	"veritas/vche/vche"
	"veritas/vche/vche_1"
	"math"
	"runtime"
	"testing"
)

var flagLongTest = flag.Bool("long", false, "run the long test suite (all parameters). Overrides -short and requires -timeout=0.")
var flagParamString = flag.String("params", "", "specify the test cryptographic parameters as a JSON string. Overrides -short and -long.")

func TestVCHE1CFPRF(t *testing.T) {
	defaultParams := vche_1.DefaultParams // the default test runs for ring degree N=2^12, 2^13, 2^14, 2^15
	if testing.Short() {
		defaultParams = vche_1.DefaultParams[:2] // the short test suite runs for ring degree N=2^12, 2^13
	}
	if *flagLongTest {
		defaultParams = append(defaultParams, vche_1.DefaultPostQuantumParams...) // the long test suite runs for all default parameters
	}
	if *flagParamString != "" {
		var jsonParams vche_1.ParametersLiteral
		err := json.Unmarshal([]byte(*flagParamString), &jsonParams)
		if err != nil {
			panic(err)
		}
		defaultParams = []vche_1.ParametersLiteral{jsonParams} // the custom test suite reads the parameters from the -params flag
	}

	for _, p := range defaultParams {

		params, err := vche_1.NewParametersFromLiteral(p)
		if err != nil {
			panic(err)
		}
		var testctx *testContext
		if testctx, err = genTestParams(params); err != nil {
			panic(err)
		}

		for _, testSet := range []func(testctx *testContext, t *testing.T){
			testEncoder,
			testEvaluator,
			testType1Fails,
			testType2Fails,
			//testMarshaller,
		} {
			testSet(testctx, t)
			runtime.GC()
		}
	}
}

func testEncoder(testctx *testContext, t *testing.T) {
	t.Run(testString("Encoder/Encode&Decode/Uint/", testctx.params), func(t *testing.T) {
		values, _, plaintext, _, verif := newTestVectors(testctx, nil, testctx.params.T())
		verifyTestVectors(testctx, nil, values, plaintext, verif, t)
	})
}

func testEvaluator(testctx *testContext, t *testing.T) {
	for _, testSet := range []func(testctx *testContext, t *testing.T){
		testEvaluatorAdd,
		testEvaluatorSub,
		testEvaluatorNeg,
		testEvaluatorMul,
		testEvaluatorMulScalar,
		testEvaluatorSwitchKeys,
		testEvaluatorRotate,
	} {
		testSet(testctx, t)
		runtime.GC()
	}
}

func testEvaluatorAdd(testctx *testContext, t *testing.T) {
	add := func(op0, op1 uint64) uint64 {
		T := testctx.params.T()
		return ((op0 % T) + (op1 % T)) % T
	}
	maxValue := testctx.params.T()

	t.Run(testString("Evaluator/Add/op1=Ciphertext/op2=Ciphertext/", testctx.params), func(t *testing.T) {
		values1, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		values2, _, _, ctxt2, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := ctxt1
		testctx.evaluator.Add(ctxt1, ctxt2, ciphertextRes)

		valuesRes := vche.ApplyBinOp(add, values1, values2)

		verifRes := verif2
		testctx.evaluatorPlaintext.Add(verif1, verif2, verifRes)

		verifyTestVectors(testctx, testctx.decryptor, valuesRes, ciphertextRes, verifRes, t)
	})

	t.Run(testString("Evaluator/Add/op1=Ciphertext/op2=Plaintext/", testctx.params), func(t *testing.T) {
		values1, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		values2, _, ptxt2, _, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := ctxt1
		testctx.evaluator.Add(ctxt1, ptxt2, ciphertextRes)

		valuesRes := vche.ApplyBinOp(add, values1, values2)

		verifRes := verif2
		testctx.evaluatorPlaintext.Add(verif1, verif2, verifRes)

		verifyTestVectors(testctx, testctx.decryptor, valuesRes, ciphertextRes, verifRes, t)
	})

	t.Run(testString("Evaluator/AddNew/op1=Ciphertext/op2=Ciphertext/", testctx.params), func(t *testing.T) {
		values1, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		values2, _, _, ctxt2, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := testctx.evaluator.AddNew(ctxt1, ctxt2)

		valuesRes := vche.ApplyBinOp(add, values1, values2)

		verifRes := testctx.evaluatorPlaintext.AddNew(verif1, verif2)

		verifyTestVectors(testctx, testctx.decryptor, valuesRes, ciphertextRes, verifRes, t)
	})

	t.Run(testString("Evaluator/AddNew/op1=Ciphertext/op2=Plaintext/", testctx.params), func(t *testing.T) {
		values1, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		values2, _, ptxt2, _, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := testctx.evaluator.AddNew(ctxt1, ptxt2)

		valuesRes := vche.ApplyBinOp(add, values1, values2)

		verifRes := testctx.evaluatorPlaintext.AddNew(verif1, verif2)

		verifyTestVectors(testctx, testctx.decryptor, valuesRes, ciphertextRes, verifRes, t)
	})

	t.Run(testString("Evaluator/AddNoMod/op1=Ciphertext/op2=Ciphertext/", testctx.params), func(t *testing.T) {
		values1, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		values2, _, _, ctxt2, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := ctxt1
		testctx.evaluator.AddNoMod(ctxt1, ctxt2, ciphertextRes)
		testctx.evaluator.Reduce(ciphertextRes, ciphertextRes)

		valuesRes := vche.ApplyBinOp(add, values1, values2)

		verifRes := verif2
		testctx.evaluatorPlaintext.AddNoMod(verif1, verif2, verifRes)
		testctx.evaluatorPlaintext.Reduce(verifRes, verifRes)

		verifyTestVectors(testctx, testctx.decryptor, valuesRes, ciphertextRes, verifRes, t)
	})

	t.Run(testString("Evaluator/AddNoMod/op1=Ciphertext/op2=Plaintext/", testctx.params), func(t *testing.T) {
		values1, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		values2, _, ptxt2, _, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := ctxt1
		testctx.evaluator.AddNoMod(ctxt1, ptxt2, ciphertextRes)
		testctx.evaluator.Reduce(ciphertextRes, ciphertextRes)

		valuesRes := vche.ApplyBinOp(add, values1, values2)

		verifRes := verif2
		testctx.evaluatorPlaintext.AddNoMod(verif1, verif2, verifRes)
		testctx.evaluatorPlaintext.Reduce(verifRes, verifRes)

		verifyTestVectors(testctx, testctx.decryptor, valuesRes, ciphertextRes, verifRes, t)
	})

	t.Run(testString("Evaluator/AddNoModNew/op1=Ciphertext/op2=Ciphertext/", testctx.params), func(t *testing.T) {
		values1, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		values2, _, _, ctxt2, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := testctx.evaluator.AddNoModNew(ctxt1, ctxt2)
		ciphertextRes = testctx.evaluator.ReduceNew(ciphertextRes)

		valuesRes := vche.ApplyBinOp(add, values1, values2)

		verifRes := testctx.evaluatorPlaintext.AddNoModNew(verif1, verif2)
		verifRes = testctx.evaluatorPlaintext.ReduceNew(verifRes)

		verifyTestVectors(testctx, testctx.decryptor, valuesRes, ciphertextRes, verifRes, t)
	})

	t.Run(testString("Evaluator/AddNoModNew/op1=Ciphertext/op2=Plaintext/", testctx.params), func(t *testing.T) {
		values1, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		values2, _, ptxt2, _, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := testctx.evaluator.AddNoModNew(ctxt1, ptxt2)
		ciphertextRes = testctx.evaluator.ReduceNew(ciphertextRes)

		valuesRes := vche.ApplyBinOp(add, values1, values2)

		verifRes := testctx.evaluatorPlaintext.AddNoModNew(verif1, verif2)
		verifRes = testctx.evaluatorPlaintext.ReduceNew(verifRes)

		verifyTestVectors(testctx, testctx.decryptor, valuesRes, ciphertextRes, verifRes, t)
	})
}

func testEvaluatorSub(testctx *testContext, t *testing.T) {
	sub := func(op0, op1 uint64) uint64 {
		T := testctx.params.T()
		return ((op0 % T) - (op1 % T) + T) % T
	}

	maxValue := testctx.params.T()

	t.Run(testString("Evaluator/Sub/op1=Ciphertext/op2=Ciphertext/", testctx.params), func(t *testing.T) {
		values1, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		values2, _, _, ctxt2, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := ctxt1
		testctx.evaluator.Sub(ctxt1, ctxt2, ciphertextRes)

		valuesRes := vche.ApplyBinOp(sub, values1, values2)

		verifRes := verif2
		testctx.evaluatorPlaintext.Sub(verif1, verif2, verifRes)

		verifyTestVectors(testctx, testctx.decryptor, valuesRes, ciphertextRes, verifRes, t)
	})

	t.Run(testString("Evaluator/Sub/op1=Ciphertext/op2=Plaintext/", testctx.params), func(t *testing.T) {
		values1, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		values2, _, ptxt2, _, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := ctxt1
		testctx.evaluator.Sub(ctxt1, ptxt2, ciphertextRes)

		valuesRes := vche.ApplyBinOp(sub, values1, values2)

		verifRes := verif2
		testctx.evaluatorPlaintext.Sub(verif1, verif2, verifRes)

		verifyTestVectors(testctx, testctx.decryptor, valuesRes, ciphertextRes, verifRes, t)
	})

	t.Run(testString("Evaluator/SubNew/op1=Ciphertext/op2=Ciphertext/", testctx.params), func(t *testing.T) {
		values1, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		values2, _, _, ctxt2, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := testctx.evaluator.SubNew(ctxt1, ctxt2)

		valuesRes := vche.ApplyBinOp(sub, values1, values2)

		verifRes := testctx.evaluatorPlaintext.SubNew(verif1, verif2)

		verifyTestVectors(testctx, testctx.decryptor, valuesRes, ciphertextRes, verifRes, t)
	})

	t.Run(testString("Evaluator/SubNew/op1=Ciphertext/op2=Plaintext/", testctx.params), func(t *testing.T) {
		values1, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		values2, _, ptxt2, _, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := testctx.evaluator.SubNew(ctxt1, ptxt2)

		valuesRes := vche.ApplyBinOp(sub, values1, values2)

		verifRes := testctx.evaluatorPlaintext.SubNew(verif1, verif2)

		verifyTestVectors(testctx, testctx.decryptor, valuesRes, ciphertextRes, verifRes, t)
	})

	t.Run(testString("Evaluator/SubNoMod/op1=Ciphertext/op2=Ciphertext/", testctx.params), func(t *testing.T) {
		values1, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		values2, _, _, ctxt2, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := ctxt1
		testctx.evaluator.SubNoMod(ctxt1, ctxt2, ciphertextRes)
		testctx.evaluator.Reduce(ciphertextRes, ciphertextRes)

		valuesRes := vche.ApplyBinOp(sub, values1, values2)

		verifRes := verif2
		testctx.evaluatorPlaintext.SubNoMod(verif1, verif2, verifRes)
		testctx.evaluatorPlaintext.Reduce(verifRes, verifRes)

		verifyTestVectors(testctx, testctx.decryptor, valuesRes, ciphertextRes, verifRes, t)
	})

	t.Run(testString("Evaluator/SubNoMod/op1=Ciphertext/op2=Plaintext/", testctx.params), func(t *testing.T) {
		values1, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		values2, _, ptxt2, _, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := ctxt1
		testctx.evaluator.SubNoMod(ctxt1, ptxt2, ciphertextRes)
		testctx.evaluator.Reduce(ciphertextRes, ciphertextRes)

		valuesRes := vche.ApplyBinOp(sub, values1, values2)

		verifRes := verif2
		testctx.evaluatorPlaintext.SubNoMod(verif1, verif2, verifRes)
		testctx.evaluatorPlaintext.Reduce(verifRes, verifRes)

		verifyTestVectors(testctx, testctx.decryptor, valuesRes, ciphertextRes, verifRes, t)
	})

	t.Run(testString("Evaluator/SubNoModNew/op1=Ciphertext/op2=Ciphertext/", testctx.params), func(t *testing.T) {
		values1, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		values2, _, _, ctxt2, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := testctx.evaluator.SubNoModNew(ctxt1, ctxt2)
		ciphertextRes = testctx.evaluator.ReduceNew(ciphertextRes)

		valuesRes := vche.ApplyBinOp(sub, values1, values2)

		verifRes := testctx.evaluatorPlaintext.SubNoModNew(verif1, verif2)
		verifRes = testctx.evaluatorPlaintext.ReduceNew(verifRes)

		verifyTestVectors(testctx, testctx.decryptor, valuesRes, ciphertextRes, verifRes, t)
	})

	t.Run(testString("Evaluator/SubNoModNew/op1=Ciphertext/op2=Plaintext/", testctx.params), func(t *testing.T) {
		values1, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		values2, _, ptxt2, _, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := testctx.evaluator.SubNoModNew(ctxt1, ptxt2)
		ciphertextRes = testctx.evaluator.ReduceNew(ciphertextRes)

		valuesRes := vche.ApplyBinOp(sub, values1, values2)

		verifRes := testctx.evaluatorPlaintext.SubNoModNew(verif1, verif2)
		verifRes = testctx.evaluatorPlaintext.ReduceNew(verifRes)

		verifyTestVectors(testctx, testctx.decryptor, valuesRes, ciphertextRes, verifRes, t)
	})
}

func testEvaluatorNeg(testctx *testContext, t *testing.T) {
	neg := func(op uint64) uint64 {
		T := testctx.params.T()
		return (T - op) % T
	}

	t.Run(testString("Evaluator/Neg/", testctx.params), func(t *testing.T) {
		values, _, _, ctxt, verif := newTestVectors(testctx, testctx.encryptorSk, testctx.params.T())

		ciphertextRes := ctxt
		testctx.evaluator.Neg(ctxt, ciphertextRes)

		valuesRes := vche.ApplyUnOp(neg, values)

		verifRes := verif
		testctx.evaluatorPlaintext.Neg(verif, verifRes)

		verifyTestVectors(testctx, testctx.decryptor, valuesRes, ciphertextRes, verifRes, t)
	})

	t.Run(testString("Evaluator/NegNew/", testctx.params), func(t *testing.T) {
		values, _, _, ctxt, verif := newTestVectors(testctx, testctx.encryptorSk, testctx.params.T())

		ciphertextRes := testctx.evaluator.NegNew(ctxt)

		valuesRes := vche.ApplyUnOp(neg, values)

		verifRes := testctx.evaluatorPlaintext.NegNew(verif)

		verifyTestVectors(testctx, testctx.decryptor, valuesRes, ciphertextRes, verifRes, t)
	})
}

func testEvaluatorMul(testctx *testContext, t *testing.T) {
	mul := func(op0, op1 uint64) uint64 {
		T := testctx.params.T()
		return ((op0 % T) * (op1 % T)) % T
	}

	t.Run(testString("Evaluator/Mul/Relinearize/", testctx.params), func(t *testing.T) {
		maxValue := uint64(math.Floor(math.Sqrt(float64(testctx.params.T()))))
		values1, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		values2, _, _, ctxt2, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextProd := vche_1.NewCiphertext(testctx.params, ctxt1.Degree()+ctxt2.Degree())
		testctx.evaluator.Mul(ctxt1, ctxt2, ciphertextProd)
		ciphertextRes := vche_1.NewCiphertext(testctx.params, ctxt1.Degree())
		testctx.evaluator.Relinearize(ciphertextProd, ciphertextRes)

		valuesRes := vche.ApplyBinOp(mul, values1, values2)

		verifRes := verif2
		testctx.evaluatorPlaintext.Mul(verif1, verif2, verifRes)
		testctx.evaluatorPlaintext.Relinearize(verifRes, verifRes)

		verifyTestVectors(testctx, testctx.decryptor, valuesRes, ciphertextRes, verifRes, t)
	})

	t.Run(testString("Evaluator/Mul/RelinearizeNew/", testctx.params), func(t *testing.T) {
		maxValue := uint64(math.Floor(math.Sqrt(float64(testctx.params.T()))))
		values1, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		values2, _, _, ctxt2, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextProd := vche_1.NewCiphertext(testctx.params, ctxt1.Degree()+ctxt2.Degree())
		testctx.evaluator.Mul(ctxt1, ctxt2, ciphertextProd)
		ciphertextRes := testctx.evaluator.RelinearizeNew(ciphertextProd)

		valuesRes := vche.ApplyBinOp(mul, values1, values2)

		verifProd := vche_1.NewVerifPlaintext(testctx.params)
		testctx.evaluatorPlaintext.Mul(verif1, verif2, verifProd)
		verifRes := testctx.evaluatorPlaintext.RelinearizeNew(verifProd)

		verifyTestVectors(testctx, testctx.decryptor, valuesRes, ciphertextRes, verifRes, t)
	})

	t.Run(testString("Evaluator/Mul/op1=Ciphertext/op2=Ciphertext/", testctx.params), func(t *testing.T) {
		maxValue := uint64(math.Floor(math.Sqrt(float64(testctx.params.T()))))
		values1, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		values2, _, _, ctxt2, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := vche_1.NewCiphertext(testctx.params, ctxt1.Degree()+ctxt2.Degree())
		testctx.evaluator.Mul(ctxt1, ctxt2, ciphertextRes)

		valuesRes := vche.ApplyBinOp(mul, values1, values2)

		verifRes := verif2
		testctx.evaluatorPlaintext.Mul(verif1, verif2, verifRes)

		verifyTestVectors(testctx, testctx.decryptor, valuesRes, ciphertextRes, verifRes, t)
	})

	t.Run(testString("Evaluator/Mul/op1=Ciphertext/op2=Plaintext/", testctx.params), func(t *testing.T) {
		maxValue := uint64(math.Floor(math.Sqrt(float64(testctx.params.T()))))
		values1, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		values2, _, ptxt2, _, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := vche_1.NewCiphertext(testctx.params, ctxt1.Degree()+ptxt2.Degree())
		testctx.evaluator.Mul(ctxt1, ptxt2, ciphertextRes)

		valuesRes := vche.ApplyBinOp(mul, values1, values2)

		verifRes := vche_1.NewVerifPlaintext(testctx.params)
		testctx.evaluatorPlaintext.Mul(verif1, verif2, verifRes)

		verifyTestVectors(testctx, testctx.decryptor, valuesRes, ciphertextRes, verifRes, t)
	})

	t.Run(testString("Evaluator/MulNew/op1=Ciphertext/op2=Ciphertext/", testctx.params), func(t *testing.T) {
		maxValue := uint64(math.Floor(math.Sqrt(float64(testctx.params.T()))))
		values1, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		values2, _, _, ctxt2, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := testctx.evaluator.MulNew(ctxt1, ctxt2)

		valuesRes := vche.ApplyBinOp(mul, values1, values2)

		verifRes := testctx.evaluatorPlaintext.MulNew(verif1, verif2)

		verifyTestVectors(testctx, testctx.decryptor, valuesRes, ciphertextRes, verifRes, t)
	})

	t.Run(testString("Evaluator/MulNew/op1=Ciphertext/op2=Plaintext/", testctx.params), func(t *testing.T) {
		maxValue := uint64(math.Floor(math.Sqrt(float64(testctx.params.T()))))
		values1, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		values2, _, ptxt2, _, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := testctx.evaluator.MulNew(ctxt1, ptxt2)

		valuesRes := vche.ApplyBinOp(mul, values1, values2)

		verifRes := testctx.evaluatorPlaintext.MulNew(verif1, verif2)

		verifyTestVectors(testctx, testctx.decryptor, valuesRes, ciphertextRes, verifRes, t)
	})
}

func testEvaluatorMulScalar(testctx *testContext, t *testing.T) {
	mul := func(op0, op1 uint64) uint64 {
		T := testctx.params.T()
		return ((op0 % T) * (op1 % T)) % T
	}

	t.Run(testString("Evaluator/MulScalar/", testctx.params), func(t *testing.T) {
		scalar := vche.GetRandom(testctx.params.T())
		maxValue := uint64(math.Floor(float64(testctx.params.T()) / float64(scalar)))
		values, _, _, ctxt, verif := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		scalars := make([]uint64, len(values))
		for i := range scalars {
			scalars[i] = scalar
		}

		ciphertextRes := ctxt
		testctx.evaluator.MulScalar(ctxt, scalar, ciphertextRes)

		valuesRes := vche.ApplyBinOp(mul, values, scalars)

		verifRes := verif
		testctx.evaluatorPlaintext.MulScalar(verif, scalar, verifRes)

		verifyTestVectors(testctx, testctx.decryptor, valuesRes, ciphertextRes, verifRes, t)
	})

	t.Run(testString("Evaluator/MulScalarNew/", testctx.params), func(t *testing.T) {
		scalar := vche.GetRandom(testctx.params.T())
		maxValue := uint64(math.Floor(float64(testctx.params.T()) / float64(scalar)))
		values, _, _, ctxt, verif := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		scalars := make([]uint64, len(values))
		for i := range scalars {
			scalars[i] = scalar
		}

		ciphertextRes := testctx.evaluator.MulScalarNew(ctxt, scalar)

		valuesRes := vche.ApplyBinOp(mul, values, scalars)

		verifRes := testctx.evaluatorPlaintext.MulScalarNew(verif, scalar)

		verifyTestVectors(testctx, testctx.decryptor, valuesRes, ciphertextRes, verifRes, t)
	})
}

func testEvaluatorSwitchKeys(testctx *testContext, t *testing.T) {
	if testctx.params.PCount() == 0 {
		t.Skip("#Pi is empty")
	}
	sk2 := testctx.kgen.GenSecretKey()
	sk2.S = testctx.sk.S
	decryptorSk2 := vche_1.NewDecryptor(testctx.params, sk2)
	switchKey := testctx.kgen.GenSwitchingKey(testctx.sk, sk2)

	t.Run(testString("Evaluator/SwitchKeys/", testctx.params), func(t *testing.T) {
		values, _, _, ciphertext, verif := newTestVectors(testctx, testctx.encryptorSk, testctx.params.T())
		testctx.evaluator.SwitchKeys(ciphertext, switchKey, ciphertext)
		testctx.evaluatorPlaintext.SwitchKeys(verif, switchKey, verif)
		verifyTestVectors(testctx, decryptorSk2, values, ciphertext, verif, t)
	})

	t.Run(testString("Evaluator/SwitchKeysNew/", testctx.params), func(t *testing.T) {
		values, _, _, ciphertext, verif := newTestVectors(testctx, testctx.encryptorSk, testctx.params.T())
		ciphertextRes := testctx.evaluator.SwitchKeysNew(ciphertext, switchKey)
		verifRes := testctx.evaluatorPlaintext.SwitchKeysNew(verif, switchKey)
		verifyTestVectors(testctx, decryptorSk2, values, ciphertextRes, verifRes, t)
	})
}

func testEvaluatorRotate(testctx *testContext, t *testing.T) {
	if testctx.params.PCount() == 0 {
		t.Skip("#Pi is empty")
	}

	evaluator := testctx.evaluator.WithKey(testctx.rotsEvk)

	t.Run(testString("Evaluator/RotateRows/", testctx.params), func(t *testing.T) {
		values, _, _, ciphertext, verif := newTestVectors(testctx, testctx.encryptorSk, testctx.params.T())
		evaluator.RotateRows(ciphertext, ciphertext)
		testctx.evaluatorPlaintext.RotateRows(verif, verif)

		values = append(values[testctx.params.NSlots>>1:], values[:testctx.params.NSlots>>1]...)
		verifyTestVectors(testctx, testctx.decryptor, values, ciphertext, verif, t)
	})

	t.Run(testString("Evaluator/RotateRowsNew/", testctx.params), func(t *testing.T) {
		values, _, _, ciphertext, verif := newTestVectors(testctx, testctx.encryptorSk, testctx.params.T())
		ciphertext = evaluator.RotateRowsNew(ciphertext)
		verif = testctx.evaluatorPlaintext.RotateRowsNew(verif)
		values = append(values[testctx.params.NSlots>>1:], values[:testctx.params.NSlots>>1]...)
		verifyTestVectors(testctx, testctx.decryptor, values, ciphertext, verif, t)
	})

	t.Run(testString("Evaluator/RotateColumns/", testctx.params), func(t *testing.T) {
		values, _, _, ciphertext, verif := newTestVectors(testctx, testctx.encryptorSk, testctx.params.T())

		receiver := vche_1.NewCiphertext(testctx.params, 1)
		verifTmp := vche_1.NewVerifPlaintext(testctx.params)
		for _, n := range testctx.rots {
			evaluator.RotateColumns(ciphertext, n, receiver)
			testctx.evaluatorPlaintext.RotateColumns(verif, n, verifTmp)
			valuesWant := utils.RotateUint64Slots(values, n)

			verifyTestVectors(testctx, testctx.decryptor, valuesWant, receiver, verifTmp, t)
		}
	})

	t.Run(testString("Evaluator/RotateColumnsNew/", testctx.params), func(t *testing.T) {
		values, _, _, ciphertext, verif := newTestVectors(testctx, testctx.encryptorSk, testctx.params.T())

		for _, n := range testctx.rots {
			receiver := evaluator.RotateColumnsNew(ciphertext, n)
			verifTmp := testctx.evaluatorPlaintext.RotateColumnsNew(verif, n)
			valuesWant := utils.RotateUint64Slots(values, n)

			verifyTestVectors(testctx, testctx.decryptor, valuesWant, receiver, verifTmp, t)
		}
	})

	evaluator = evaluator.WithKey(testctx.innerSumEvk)

	t.Run(testString("Evaluator/Rotate/InnerSum/", testctx.params), func(t *testing.T) {
		values, _, _, ciphertext, verif := newTestVectors(testctx, testctx.encryptorSk, testctx.params.T())

		evaluator.InnerSum(ciphertext, ciphertext)
		testctx.evaluatorPlaintext.InnerSum(verif, verif)

		var sum uint64
		for _, c := range values {
			sum += c
		}

		sum %= testctx.params.T()

		for i := range values {
			values[i] = sum
		}
		verifyTestVectors(testctx, testctx.decryptor, values, ciphertext, verif, t)
	})
}

func testType1Fails(testctx *testContext, t *testing.T) {
	for _, testSet := range []func(testctx *testContext, t *testing.T){
		testType1FailsAdd,
		testType1FailsSub,
		testType1FailsNeg,
		testType1FailsMul,
		testType1FailsMulScalar,
		testType1FailsSwitchKeys,
		testType1FailsRotate,
	} {
		testSet(testctx, t)
		runtime.GC()
	}
}

func testType1FailsAdd(testctx *testContext, t *testing.T) {
	t.Run(testString("Type1Fails/Add/op1=Ciphertext/op2=Ciphertext/", testctx.params), func(t *testing.T) {
		maxValue := testctx.params.T()
		_, _, _, ctxt1, verif1 := newType1TestVectors(testctx, testctx.encryptorSk, maxValue)
		_, _, _, ctxt2, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := ctxt1
		testctx.evaluator.Add(ctxt1, ctxt2, ciphertextRes)

		verifRes := verif2
		testctx.evaluatorPlaintext.Add(verif1, verif2, verifRes)

		decodingPanics(testctx, t, ciphertextRes, verifRes)
	})

	t.Run(testString("Type1Fails/Add/op1=Ciphertext/op2=Plaintext/", testctx.params), func(t *testing.T) {
		maxValue := testctx.params.T()
		_, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		_, _, ptxt2, _, verif2 := newType1TestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := ctxt1
		testctx.evaluator.Add(ctxt1, ptxt2, ciphertextRes)

		verifRes := verif2
		testctx.evaluatorPlaintext.Add(verif1, verif2, verifRes)

		decodingPanics(testctx, t, ciphertextRes, verifRes)
	})

	t.Run(testString("Type1Fails/AddNoMod/op1=Ciphertext/op2=Ciphertext/", testctx.params), func(t *testing.T) {
		maxValue := testctx.params.T()
		_, _, _, ctxt1, verif1 := newType1TestVectors(testctx, testctx.encryptorSk, maxValue)
		_, _, _, ctxt2, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := ctxt1
		testctx.evaluator.AddNoMod(ctxt1, ctxt2, ciphertextRes)

		verifRes := verif2
		testctx.evaluatorPlaintext.AddNoMod(verif1, verif2, verifRes)

		decodingPanics(testctx, t, ciphertextRes, verifRes)
	})

	t.Run(testString("Type1Fails/AddNoMod/op1=Ciphertext/op2=Plaintext/", testctx.params), func(t *testing.T) {
		maxValue := testctx.params.T()
		_, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		_, _, ptxt2, _, verif2 := newType1TestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := ctxt1
		testctx.evaluator.AddNoMod(ctxt1, ptxt2, ciphertextRes)

		verifRes := verif2
		testctx.evaluatorPlaintext.AddNoMod(verif1, verif2, verifRes)

		decodingPanics(testctx, t, ciphertextRes, verifRes)
	})
}

func testType1FailsSub(testctx *testContext, t *testing.T) {
	maxValue := testctx.params.T()

	t.Run(testString("Type1Fails/Sub/op1=Ciphertext/op2=Ciphertext/", testctx.params), func(t *testing.T) {
		_, _, _, ctxt1, verif1 := newType1TestVectors(testctx, testctx.encryptorSk, maxValue)
		_, _, _, ctxt2, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := ctxt1
		testctx.evaluator.Sub(ctxt1, ctxt2, ciphertextRes)

		verifRes := verif2
		testctx.evaluatorPlaintext.Sub(verif1, verif2, verifRes)

		decodingPanics(testctx, t, ciphertextRes, verifRes)
	})

	t.Run(testString("Type1Fails/Sub/op1=Ciphertext/op2=Plaintext/", testctx.params), func(t *testing.T) {
		_, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		_, _, ptxt2, _, verif2 := newType1TestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := ctxt1
		testctx.evaluator.Sub(ctxt1, ptxt2, ciphertextRes)

		verifRes := verif2
		testctx.evaluatorPlaintext.Sub(verif1, verif2, verifRes)

		decodingPanics(testctx, t, ciphertextRes, verifRes)
	})

	t.Run(testString("Type1Fails/SubNoMod/op1=Ciphertext/op2=Ciphertext/", testctx.params), func(t *testing.T) {
		_, _, _, ctxt1, verif1 := newType1TestVectors(testctx, testctx.encryptorSk, maxValue)
		_, _, _, ctxt2, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := ctxt1
		testctx.evaluator.SubNoMod(ctxt1, ctxt2, ciphertextRes)
		testctx.evaluator.Reduce(ciphertextRes, ciphertextRes)

		verifRes := verif2
		testctx.evaluatorPlaintext.SubNoMod(verif1, verif2, verifRes)
		testctx.evaluatorPlaintext.Reduce(verifRes, verifRes)

		decodingPanics(testctx, t, ciphertextRes, verifRes)
	})

	t.Run(testString("Type1Fails/SubNoMod/op1=Ciphertext/op2=Plaintext/", testctx.params), func(t *testing.T) {
		_, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		_, _, ptxt2, _, verif2 := newType1TestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := ctxt1
		testctx.evaluator.SubNoMod(ctxt1, ptxt2, ciphertextRes)
		testctx.evaluator.Reduce(ciphertextRes, ciphertextRes)

		verifRes := verif2
		testctx.evaluatorPlaintext.SubNoMod(verif1, verif2, verifRes)
		testctx.evaluatorPlaintext.Reduce(verifRes, verifRes)

		decodingPanics(testctx, t, ciphertextRes, verifRes)
	})
}

func testType1FailsNeg(testctx *testContext, t *testing.T) {
	t.Run(testString("Type1Fails/Neg/", testctx.params), func(t *testing.T) {
		_, _, _, ctxt, verif := newType1TestVectors(testctx, testctx.encryptorSk, testctx.params.T())

		ciphertextRes := ctxt
		testctx.evaluator.Neg(ctxt, ciphertextRes)

		verifRes := verif
		testctx.evaluatorPlaintext.Neg(verif, verifRes)

		decodingPanics(testctx, t, ciphertextRes, verifRes)
	})
}

func testType1FailsMul(testctx *testContext, t *testing.T) {
	maxValue := testctx.params.T()
	t.Run(testString("Type1Fails/Mul/Relinearize/", testctx.params), func(t *testing.T) {
		_, _, _, ctxt1, verif1 := newType1TestVectors(testctx, testctx.encryptorSk, maxValue)
		_, _, _, ctxt2, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextProd := vche_1.NewCiphertext(testctx.params, ctxt1.Degree()+ctxt2.Degree())
		testctx.evaluator.Mul(ctxt1, ctxt2, ciphertextProd)
		ciphertextRes := vche_1.NewCiphertext(testctx.params, ctxt1.Degree())
		testctx.evaluator.Relinearize(ciphertextProd, ciphertextRes)

		verifRes := verif2
		testctx.evaluatorPlaintext.Mul(verif1, verif2, verifRes)
		testctx.evaluatorPlaintext.Relinearize(verifRes, verifRes)

		decodingPanics(testctx, t, ciphertextRes, verifRes)
	})

	t.Run(testString("Type1Fails/Mul/op1=Ciphertext/op2=Ciphertext/", testctx.params), func(t *testing.T) {
		_, _, _, ctxt1, verif1 := newType1TestVectors(testctx, testctx.encryptorSk, maxValue)
		_, _, _, ctxt2, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := vche_1.NewCiphertext(testctx.params, ctxt1.Degree()+ctxt2.Degree())
		testctx.evaluator.Mul(ctxt1, ctxt2, ciphertextRes)

		verifRes := verif2
		testctx.evaluatorPlaintext.Mul(verif1, verif2, verifRes)

		decodingPanics(testctx, t, ciphertextRes, verifRes)
	})

	t.Run(testString("Type1Fails/Mul/op1=Ciphertext/op2=Plaintext/", testctx.params), func(t *testing.T) {
		_, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		_, _, ptxt2, _, verif2 := newType1TestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := vche_1.NewCiphertext(testctx.params, ctxt1.Degree()+ptxt2.Degree())
		testctx.evaluator.Mul(ctxt1, ptxt2, ciphertextRes)

		verifRes := vche_1.NewVerifPlaintext(testctx.params)
		testctx.evaluatorPlaintext.Mul(verif1, verif2, verifRes)

		decodingPanics(testctx, t, ciphertextRes, verifRes)
	})
}

func testType1FailsMulScalar(testctx *testContext, t *testing.T) {
	t.Run(testString("Type1Fails/MulScalar/", testctx.params), func(t *testing.T) {
		scalar := vche.GetRandom(testctx.params.T())
		maxValue := testctx.params.T()
		_, _, _, ctxt, verif := newType1TestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := ctxt
		testctx.evaluator.MulScalar(ctxt, scalar, ciphertextRes)

		verifRes := verif
		testctx.evaluatorPlaintext.MulScalar(verif, scalar, verifRes)

		decodingPanics(testctx, t, ciphertextRes, verifRes)
	})
}

func testType1FailsSwitchKeys(testctx *testContext, t *testing.T) {
	if testctx.params.PCount() == 0 {
		t.Skip("#Pi is empty")
	}
	sk2 := testctx.kgen.GenSecretKey()
	sk2.S = testctx.sk.S
	decryptorSk2 := vche_1.NewDecryptor(testctx.params, sk2)
	switchKey := testctx.kgen.GenSwitchingKey(testctx.sk, sk2)

	t.Run(testString("Type1Fails/SwitchKeys/", testctx.params), func(t *testing.T) {
		_, _, _, ciphertext, verif := newType1TestVectors(testctx, testctx.encryptorSk, testctx.params.T())
		testctx.evaluator.SwitchKeys(ciphertext, switchKey, ciphertext)
		testctx.evaluatorPlaintext.SwitchKeys(verif, switchKey, verif)
		decodingPanicsWithDecryptor(testctx, t, decryptorSk2, ciphertext, verif)
	})

	t.Run(testString("Type1Fails/SwitchKeysNew/", testctx.params), func(t *testing.T) {
		_, _, _, ciphertext, verif := newType1TestVectors(testctx, testctx.encryptorSk, testctx.params.T())
		ciphertextRes := testctx.evaluator.SwitchKeysNew(ciphertext, switchKey)
		verifRes := testctx.evaluatorPlaintext.SwitchKeysNew(verif, switchKey)
		decodingPanicsWithDecryptor(testctx, t, decryptorSk2, ciphertextRes, verifRes)
	})
}

func testType1FailsRotate(testctx *testContext, t *testing.T) {
	if testctx.params.PCount() == 0 {
		t.Skip("#Pi is empty")
	}

	evaluator := testctx.evaluator.WithKey(testctx.rotsEvk)

	t.Run(testString("Type1Fails/RotateRows/", testctx.params), func(t *testing.T) {
		_, _, _, ciphertext, verif := newType1TestVectors(testctx, testctx.encryptorSk, testctx.params.T())
		evaluator.RotateRows(ciphertext, ciphertext)
		testctx.evaluatorPlaintext.RotateRows(verif, verif)

		decodingPanics(testctx, t, ciphertext, verif)
	})

	t.Run(testString("Type1Fails/RotateColumns/", testctx.params), func(t *testing.T) {
		_, _, _, ciphertext, verif := newType1TestVectors(testctx, testctx.encryptorSk, testctx.params.T())

		receiver := vche_1.NewCiphertext(testctx.params, 1)
		verifTmp := vche_1.NewVerifPlaintext(testctx.params)
		for _, n := range testctx.rots {
			evaluator.RotateColumns(ciphertext, n, receiver)
			testctx.evaluatorPlaintext.RotateColumns(verif, n, verifTmp)

			decodingPanics(testctx, t, receiver, verifTmp)
		}
	})
}

func testType2Fails(testctx *testContext, t *testing.T) {
	for _, testSet := range []func(testctx *testContext, t *testing.T){
		testType2FailsAdd,
		testType2FailsSub,
		testType2FailsNeg,
		testType2FailsMul,
		testType2FailsMulScalar,
		testType2FailsSwitchKeys,
		testType2FailsRotate,
	} {
		testSet(testctx, t)
		runtime.GC()
	}
}

func testType2FailsAdd(testctx *testContext, t *testing.T) {
	t.Run(testString("Type2Fails/Add/op1=Ciphertext/op2=Ciphertext/", testctx.params), func(t *testing.T) {
		maxValue := testctx.params.T()
		_, _, _, ctxt1, verif1 := newType2TestVectors(testctx, testctx.encryptorSk, maxValue)
		_, _, _, ctxt2, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := ctxt1
		testctx.evaluator.Add(ctxt1, ctxt2, ciphertextRes)

		verifRes := verif2
		testctx.evaluatorPlaintext.Add(verif1, verif2, verifRes)

		decodingPanics(testctx, t, ciphertextRes, verifRes)
	})

	t.Run(testString("Type2Fails/Add/op1=Ciphertext/op2=Plaintext/", testctx.params), func(t *testing.T) {
		maxValue := testctx.params.T()
		_, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		_, _, ptxt2, _, verif2 := newType2TestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := ctxt1
		testctx.evaluator.Add(ctxt1, ptxt2, ciphertextRes)

		verifRes := verif2
		testctx.evaluatorPlaintext.Add(verif1, verif2, verifRes)

		decodingPanics(testctx, t, ciphertextRes, verifRes)
	})

	t.Run(testString("Type2Fails/AddNoMod/op1=Ciphertext/op2=Ciphertext/", testctx.params), func(t *testing.T) {
		maxValue := testctx.params.T()
		_, _, _, ctxt1, verif1 := newType2TestVectors(testctx, testctx.encryptorSk, maxValue)
		_, _, _, ctxt2, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := ctxt1
		testctx.evaluator.AddNoMod(ctxt1, ctxt2, ciphertextRes)

		verifRes := verif2
		testctx.evaluatorPlaintext.AddNoMod(verif1, verif2, verifRes)

		decodingPanics(testctx, t, ciphertextRes, verifRes)
	})

	t.Run(testString("Type2Fails/AddNoMod/op1=Ciphertext/op2=Plaintext/", testctx.params), func(t *testing.T) {
		maxValue := testctx.params.T()
		_, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		_, _, ptxt2, _, verif2 := newType2TestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := ctxt1
		testctx.evaluator.AddNoMod(ctxt1, ptxt2, ciphertextRes)

		verifRes := verif2
		testctx.evaluatorPlaintext.AddNoMod(verif1, verif2, verifRes)

		decodingPanics(testctx, t, ciphertextRes, verifRes)
	})
}

func testType2FailsSub(testctx *testContext, t *testing.T) {
	maxValue := testctx.params.T()

	t.Run(testString("Type2Fails/Sub/op1=Ciphertext/op2=Ciphertext/", testctx.params), func(t *testing.T) {
		_, _, _, ctxt1, verif1 := newType2TestVectors(testctx, testctx.encryptorSk, maxValue)
		_, _, _, ctxt2, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := ctxt1
		testctx.evaluator.Sub(ctxt1, ctxt2, ciphertextRes)

		verifRes := verif2
		testctx.evaluatorPlaintext.Sub(verif1, verif2, verifRes)

		decodingPanics(testctx, t, ciphertextRes, verifRes)
	})

	t.Run(testString("Type2Fails/Sub/op1=Ciphertext/op2=Plaintext/", testctx.params), func(t *testing.T) {
		_, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		_, _, ptxt2, _, verif2 := newType2TestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := ctxt1
		testctx.evaluator.Sub(ctxt1, ptxt2, ciphertextRes)

		verifRes := verif2
		testctx.evaluatorPlaintext.Sub(verif1, verif2, verifRes)

		decodingPanics(testctx, t, ciphertextRes, verifRes)
	})

	t.Run(testString("Type2Fails/SubNoMod/op1=Ciphertext/op2=Ciphertext/", testctx.params), func(t *testing.T) {
		_, _, _, ctxt1, verif1 := newType2TestVectors(testctx, testctx.encryptorSk, maxValue)
		_, _, _, ctxt2, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := ctxt1
		testctx.evaluator.SubNoMod(ctxt1, ctxt2, ciphertextRes)
		testctx.evaluator.Reduce(ciphertextRes, ciphertextRes)

		verifRes := verif2
		testctx.evaluatorPlaintext.SubNoMod(verif1, verif2, verifRes)
		testctx.evaluatorPlaintext.Reduce(verifRes, verifRes)

		decodingPanics(testctx, t, ciphertextRes, verifRes)
	})

	t.Run(testString("Type2Fails/SubNoMod/op1=Ciphertext/op2=Plaintext/", testctx.params), func(t *testing.T) {
		_, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		_, _, ptxt2, _, verif2 := newType2TestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := ctxt1
		testctx.evaluator.SubNoMod(ctxt1, ptxt2, ciphertextRes)
		testctx.evaluator.Reduce(ciphertextRes, ciphertextRes)

		verifRes := verif2
		testctx.evaluatorPlaintext.SubNoMod(verif1, verif2, verifRes)
		testctx.evaluatorPlaintext.Reduce(verifRes, verifRes)

		decodingPanics(testctx, t, ciphertextRes, verifRes)
	})
}

func testType2FailsNeg(testctx *testContext, t *testing.T) {
	t.Run(testString("Type2Fails/Neg/", testctx.params), func(t *testing.T) {
		_, _, _, ctxt, verif := newType2TestVectors(testctx, testctx.encryptorSk, testctx.params.T())

		ciphertextRes := ctxt
		testctx.evaluator.Neg(ctxt, ciphertextRes)

		verifRes := verif
		testctx.evaluatorPlaintext.Neg(verif, verifRes)

		decodingPanics(testctx, t, ciphertextRes, verifRes)
	})
}

func testType2FailsMul(testctx *testContext, t *testing.T) {
	maxValue := testctx.params.T()
	t.Run(testString("Type2Fails/Mul/Relinearize/", testctx.params), func(t *testing.T) {
		_, _, _, ctxt1, verif1 := newType2TestVectors(testctx, testctx.encryptorSk, maxValue)
		_, _, _, ctxt2, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextProd := vche_1.NewCiphertext(testctx.params, ctxt1.Degree()+ctxt2.Degree())
		testctx.evaluator.Mul(ctxt1, ctxt2, ciphertextProd)
		ciphertextRes := vche_1.NewCiphertext(testctx.params, ctxt1.Degree())
		testctx.evaluator.Relinearize(ciphertextProd, ciphertextRes)

		verifRes := verif2
		testctx.evaluatorPlaintext.Mul(verif1, verif2, verifRes)
		testctx.evaluatorPlaintext.Relinearize(verifRes, verifRes)

		decodingPanics(testctx, t, ciphertextRes, verifRes)
	})

	t.Run(testString("Type2Fails/Mul/op1=Ciphertext/op2=Ciphertext/", testctx.params), func(t *testing.T) {
		_, _, _, ctxt1, verif1 := newType2TestVectors(testctx, testctx.encryptorSk, maxValue)
		_, _, _, ctxt2, verif2 := newTestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := vche_1.NewCiphertext(testctx.params, ctxt1.Degree()+ctxt2.Degree())
		testctx.evaluator.Mul(ctxt1, ctxt2, ciphertextRes)

		verifRes := verif2
		testctx.evaluatorPlaintext.Mul(verif1, verif2, verifRes)

		decodingPanics(testctx, t, ciphertextRes, verifRes)
	})

	t.Run(testString("Type2Fails/Mul/op1=Ciphertext/op2=Plaintext/", testctx.params), func(t *testing.T) {
		_, _, _, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, maxValue)
		_, _, ptxt2, _, verif2 := newType2TestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := vche_1.NewCiphertext(testctx.params, ctxt1.Degree()+ptxt2.Degree())
		testctx.evaluator.Mul(ctxt1, ptxt2, ciphertextRes)

		verifRes := vche_1.NewVerifPlaintext(testctx.params)
		testctx.evaluatorPlaintext.Mul(verif1, verif2, verifRes)

		decodingPanics(testctx, t, ciphertextRes, verifRes)
	})
}

func testType2FailsMulScalar(testctx *testContext, t *testing.T) {
	t.Run(testString("Type2Fails/MulScalar/", testctx.params), func(t *testing.T) {
		scalar := vche.GetRandom(testctx.params.T())
		maxValue := testctx.params.T()
		_, _, _, ctxt, verif := newType2TestVectors(testctx, testctx.encryptorSk, maxValue)

		ciphertextRes := ctxt
		testctx.evaluator.MulScalar(ctxt, scalar, ciphertextRes)

		verifRes := verif
		testctx.evaluatorPlaintext.MulScalar(verif, scalar, verifRes)

		decodingPanics(testctx, t, ciphertextRes, verifRes)
	})
}

func testType2FailsSwitchKeys(testctx *testContext, t *testing.T) {
	if testctx.params.PCount() == 0 {
		t.Skip("#Pi is empty")
	}
	sk2 := testctx.kgen.GenSecretKey()
	sk2.S = testctx.sk.S
	decryptorSk2 := vche_1.NewDecryptor(testctx.params, sk2)
	switchKey := testctx.kgen.GenSwitchingKey(testctx.sk, sk2)

	t.Run(testString("Type2Fails/SwitchKeys/", testctx.params), func(t *testing.T) {
		_, _, _, ciphertext, verif := newType2TestVectors(testctx, testctx.encryptorSk, testctx.params.T())
		testctx.evaluator.SwitchKeys(ciphertext, switchKey, ciphertext)
		testctx.evaluatorPlaintext.SwitchKeys(verif, switchKey, verif)
		decodingPanicsWithDecryptor(testctx, t, decryptorSk2, ciphertext, verif)
	})

	t.Run(testString("Type2Fails/SwitchKeysNew/", testctx.params), func(t *testing.T) {
		_, _, _, ciphertext, verif := newType2TestVectors(testctx, testctx.encryptorSk, testctx.params.T())
		ciphertextRes := testctx.evaluator.SwitchKeysNew(ciphertext, switchKey)
		verifRes := testctx.evaluatorPlaintext.SwitchKeysNew(verif, switchKey)
		decodingPanicsWithDecryptor(testctx, t, decryptorSk2, ciphertextRes, verifRes)
	})
}

func testType2FailsRotate(testctx *testContext, t *testing.T) {
	if testctx.params.PCount() == 0 {
		t.Skip("#Pi is empty")
	}

	evaluator := testctx.evaluator.WithKey(testctx.rotsEvk)

	t.Run(testString("Type2Fails/RotateRows/", testctx.params), func(t *testing.T) {
		_, _, _, ciphertext, verif := newType2TestVectors(testctx, testctx.encryptorSk, testctx.params.T())
		evaluator.RotateRows(ciphertext, ciphertext)
		testctx.evaluatorPlaintext.RotateRows(verif, verif)

		decodingPanics(testctx, t, ciphertext, verif)
	})

	t.Run(testString("Type2Fails/RotateColumns/", testctx.params), func(t *testing.T) {
		_, _, _, ciphertext, verif := newType2TestVectors(testctx, testctx.encryptorSk, testctx.params.T())

		receiver := vche_1.NewCiphertext(testctx.params, 1)
		verifTmp := vche_1.NewVerifPlaintext(testctx.params)
		for _, n := range testctx.rots {
			evaluator.RotateColumns(ciphertext, n, receiver)
			testctx.evaluatorPlaintext.RotateColumns(verif, n, verifTmp)

			decodingPanics(testctx, t, receiver, verifTmp)
		}
	})
}
