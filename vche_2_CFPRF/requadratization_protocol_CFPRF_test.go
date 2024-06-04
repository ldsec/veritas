package vche_2_CFPRF

import (
	"github.com/ldsec/lattigo/v2/utils"
	"veritas/vche/vche"
	"veritas/vche/vche_2"
	"testing"
)

func TestRunRequadratizationProtocol(t *testing.T) {
	for _, paramDef := range vche_2.DefaultParams[1:] { // Skip PN12, since we want multiplicative depth >= 2 for the tests
		params, err := vche_2.NewParametersFromLiteral(paramDef)
		if err != nil {
			panic(err)
		}

		testctx, err := genTestParams(params)
		if err != nil {
			panic(err)
		}

		R := testctx.params.RingT()

		v, _, _, ctxt, verif := newTestVectors(testctx, testctx.encryptorSk, params.T())
		values := R.NewPoly()
		values.SetCoefficients([][]uint64{v})

		v1, _, ptxt1, ctxt1, verif1 := newTestVectors(testctx, testctx.encryptorSk, params.T())
		values1 := R.NewPoly()
		values1.SetCoefficients([][]uint64{v1})

		// Create ctxt of degree 2
		ctxt2 := testctx.evaluator.MulNew(ctxt, ctxt)
		verif2 := testctx.evaluatorPlaintext.MulNew(verif, verif)
		values2 := R.NewPoly()
		R.MulCoeffs(values, values, values2)

		// Create ctxt of degree 4
		ctxt4 := testctx.evaluator.MulNew(ctxt2, ctxt2)
		verif4 := testctx.evaluatorPlaintext.MulNew(verif2, verif2)
		values4 := R.NewPoly()
		R.MulCoeffs(values2, values2, values4)

		// Create ctxt of degree 2 and BFV degree 1
		ctxt2_1 := testctx.evaluator.RelinearizeNew(ctxt2)

		// Create ctxt of degree 4 and BFV degree 1
		ctxt4_1 := testctx.evaluator.MulNew(ctxt2_1, ctxt2_1)
		ctxt4_1 = testctx.evaluator.RelinearizeNew(ctxt4_1)

		t.Run(testString("ReQuad(c4)/", params), func(t *testing.T) {
			ctxtRes, verifRes := vche_2.RunRequadratizationProtocolCFPRF(testctx.prover, testctx.verifier, ctxt4, verif4)
			valuesRes := values4
			verifyTestVectors(testctx, testctx.decryptor, valuesRes.Coeffs[0], ctxtRes, verifRes, false, t)
		})

		t.Run(testString("ReQuad(c4)+c1/", params), func(t *testing.T) {
			ctxtRes, verifRes := vche_2.RunRequadratizationProtocolCFPRF(testctx.prover, testctx.verifier, ctxt4, verif4)
			testctx.evaluator.Add(ctxtRes, ctxt1, ctxtRes)
			testctx.evaluatorPlaintext.Add(verifRes, verif1, verifRes)

			valuesRes := testctx.params.RingT().NewPoly()
			R.Add(values4, values1, valuesRes)

			verifyTestVectors(testctx, testctx.decryptor, valuesRes.Coeffs[0], ctxtRes, verifRes, false, t)
		})

		t.Run(testString("ReQuad(c4)+ReQuad(c4+c1)/", params), func(t *testing.T) {
			ctxt2, verif2 := vche_2.RunRequadratizationProtocolCFPRF(testctx.prover, testctx.verifier, ctxt4, verif4)

			ctxt4_ := testctx.evaluator.AddNew(ctxt4, ctxt1)
			verif4_ := testctx.evaluatorPlaintext.AddNew(verif4, verif1)
			ctxt2_, verif2_ := vche_2.RunRequadratizationProtocolCFPRF(testctx.prover, testctx.verifier, ctxt4_, verif4_)

			ctxtRes := testctx.evaluator.AddNew(ctxt2, ctxt2_)
			verifRes := testctx.evaluatorPlaintext.AddNew(verif2, verif2_)

			valuesRes := testctx.params.RingT().NewPoly()
			R.Add(values4, values1, valuesRes)
			R.Add(values4, valuesRes, valuesRes)

			verifyTestVectors(testctx, testctx.decryptor, valuesRes.Coeffs[0], ctxtRes, verifRes, false, t)
		})

		t.Run(testString("ReQuad(c4)-c1/", params), func(t *testing.T) {
			ctxtRes, verifRes := vche_2.RunRequadratizationProtocolCFPRF(testctx.prover, testctx.verifier, ctxt4, verif4)
			testctx.evaluator.Sub(ctxtRes, ctxt1, ctxtRes)
			testctx.evaluatorPlaintext.Sub(verifRes, verif1, verifRes)

			valuesRes := testctx.params.RingT().NewPoly()
			R.Sub(values4, values1, valuesRes)

			verifyTestVectors(testctx, testctx.decryptor, valuesRes.Coeffs[0], ctxtRes, verifRes, false, t)
		})

		t.Run(testString("ReQuad(c4)-ReQuad(c4-c1)/", params), func(t *testing.T) {
			ctxt2, verif2 := vche_2.RunRequadratizationProtocolCFPRF(testctx.prover, testctx.verifier, ctxt4, verif4)

			ctxt4_ := testctx.evaluator.SubNew(ctxt4, ctxt1)
			verif4_ := testctx.evaluatorPlaintext.SubNew(verif4, verif1)
			ctxt2_, verif2_ := vche_2.RunRequadratizationProtocolCFPRF(testctx.prover, testctx.verifier, ctxt4_, verif4_)

			ctxtRes := testctx.evaluator.SubNew(ctxt2, ctxt2_)
			verifRes := testctx.evaluatorPlaintext.SubNew(verif2, verif2_)

			valuesRes := values1.CopyNew()

			verifyTestVectors(testctx, testctx.decryptor, valuesRes.Coeffs[0], ctxtRes, verifRes, false, t)
		})

		t.Run(testString("ReQuad(c4)*scalar/", params), func(t *testing.T) {
			scalar := vche.GetRandom(testctx.params.T())
			ctxtRes, verifRes := vche_2.RunRequadratizationProtocolCFPRF(testctx.prover, testctx.verifier, ctxt4, verif4)
			testctx.evaluator.MulScalar(ctxtRes, scalar, ctxtRes)
			testctx.evaluatorPlaintext.MulScalar(verifRes, scalar, verifRes)

			valuesRes := testctx.params.RingT().NewPoly()
			R.MulScalar(values4, scalar, valuesRes)

			verifyTestVectors(testctx, testctx.decryptor, valuesRes.Coeffs[0], ctxtRes, verifRes, false, t)
		})

		t.Run(testString("ReQuad(c4_1)/", params), func(t *testing.T) {
			ctxtRes, verifRes := vche_2.RunRequadratizationProtocolCFPRF(testctx.prover, testctx.verifier, ctxt4_1, verif4)
			valuesRes := values4
			verifyTestVectors(testctx, testctx.decryptor, valuesRes.Coeffs[0], ctxtRes, verifRes, false, t)
		})

		t.Run(testString("ReLin(ReQuad(c4))/", params), func(t *testing.T) {
			evk := vche_2.EvaluationKey{Rlk: testctx.kgen.GenRelinearizationKey(testctx.sk, 6), Rtks: nil}
			eval := testctx.evaluator.WithKey(evk)

			ctxtRes, verifRes := vche_2.RunRequadratizationProtocolCFPRF(testctx.prover, testctx.verifier, ctxt4, verif4)

			ctxtRes = eval.RelinearizeNew(ctxtRes)
			verifRes = testctx.evaluatorPlaintext.RelinearizeNew(verifRes)

			valuesRes := values4
			verifyTestVectors(testctx, testctx.decryptor, valuesRes.Coeffs[0], ctxtRes, verifRes, false, t)
		})

		t.Run(testString("RotateColumns(ReQuad(c4_1),rot)/", params), func(t *testing.T) {
			rot := -1
			eval := testctx.evaluator.WithKey(testctx.rotsEvk)

			ctxtRes, verifRes := vche_2.RunRequadratizationProtocolCFPRF(testctx.prover, testctx.verifier, ctxt4_1, verif4)

			ctxtRes = eval.RelinearizeNew(ctxtRes)
			verifRes = testctx.evaluatorPlaintext.RelinearizeNew(verifRes)

			eval.RotateColumns(ctxtRes, rot, ctxtRes)
			testctx.evaluatorPlaintext.RotateColumns(verifRes, rot, verifRes)

			values := values4.Coeffs[0]
			values = utils.RotateUint64Slots(values, rot)

			verifyTestVectors(testctx, testctx.decryptor, values, ctxtRes, verifRes, false, t)
		})

		t.Run(testString("RotateRows(ReQuad(c4_1))/", params), func(t *testing.T) {
			evk := vche_2.EvaluationKey{Rlk: nil, Rtks: testctx.kgen.GenRotationKeysForRotations([]int{0}, true, testctx.sk)}
			eval := testctx.evaluator.WithKey(evk)

			ctxtRes, verifRes := vche_2.RunRequadratizationProtocolCFPRF(testctx.prover, testctx.verifier, ctxt4_1, verif4)

			eval.RotateRows(ctxtRes, ctxtRes)
			testctx.evaluatorPlaintext.RotateRows(verifRes, verifRes)

			values := values4.Coeffs[0]
			values = append(values[testctx.params.NSlots>>1:], values[:testctx.params.NSlots>>1]...)

			verifyTestVectors(testctx, testctx.decryptor, values, ctxtRes, verifRes, false, t)
		})

		t.Run(testString("InnerSum(ReQuad(c4))/", params), func(t *testing.T) {
			eval := testctx.evaluator.WithKey(testctx.innerSumEvk)

			ctxtRes, verifRes := vche_2.RunRequadratizationProtocolCFPRF(testctx.prover, testctx.verifier, ctxt4_1, verif4)

			eval.InnerSum(ctxtRes, ctxtRes)
			testctx.evaluatorPlaintext.InnerSum(verifRes, verifRes)

			vals := make([]uint64, len(values4.Coeffs[0]))
			copy(vals, values4.Coeffs[0])
			var sum uint64
			for _, c := range vals {
				sum += c
			}

			sum %= testctx.params.T()

			for i := range vals {
				vals[i] = sum
			}

			verifyTestVectors(testctx, testctx.decryptor, vals, ctxtRes, verifRes, false, t)
		})

		t.Run(testString("ReQuad(ReQuad(c4)*p1)/", params), func(t *testing.T) {
			ctxtRes, verifRes := vche_2.RunRequadratizationProtocolCFPRF(testctx.prover, testctx.verifier, ctxt4, verif4)

			ctxtRes = testctx.evaluator.MulNew(ctxtRes, ptxt1)
			testctx.evaluatorPlaintext.Mul(verifRes, verif1, verifRes)

			ctxtRes, verifRes = vche_2.RunRequadratizationProtocolCFPRF(testctx.prover, testctx.verifier, ctxtRes, verifRes)

			valuesRes := testctx.params.RingT().NewPoly()
			R.MulCoeffs(values4, values1, valuesRes)

			verifyTestVectors(testctx, testctx.decryptor, valuesRes.Coeffs[0], ctxtRes, verifRes, false, t)
		})

		t.Run(testString("ReQuad(c4)*c1/", params), func(t *testing.T) {
			ctxtRes, verifRes := vche_2.RunRequadratizationProtocolCFPRF(testctx.prover, testctx.verifier, ctxt4, verif4)

			ctxtRes = testctx.evaluator.MulNew(ctxtRes, ctxt1)
			testctx.evaluatorPlaintext.Mul(verifRes, verif1, verifRes)

			valuesRes := testctx.params.RingT().NewPoly()
			R.MulCoeffs(values4, values1, valuesRes)

			verifyTestVectors(testctx, testctx.decryptor, valuesRes.Coeffs[0], ctxtRes, verifRes, false, t)
		})

		t.Run(testString("ReQuad(...ReQuad(c4)*c1)*c1.../", params), func(t *testing.T) {
			ctxtRes, verifRes := vche_2.RunRequadratizationProtocolCFPRF(testctx.prover, testctx.verifier, ctxt4_1, verif4)
			valuesRes := values4.CopyNew()

			for mul := 0; mul < testctx.params.MaxLevel(); mul++ {
				ctxtRes = testctx.evaluator.MulNew(ctxtRes, ctxt1)
				testctx.evaluatorPlaintext.Mul(verifRes, verif1, verifRes)

				ctxtRes = testctx.evaluator.RelinearizeNew(ctxtRes)
				verifRes = testctx.evaluatorPlaintext.RelinearizeNew(verifRes)

				ctxtRes, verifRes = vche_2.RunRequadratizationProtocolCFPRF(testctx.prover, testctx.verifier, ctxtRes, verifRes)

				R.MulCoeffs(valuesRes, values1, valuesRes)

				verifyTestVectors(testctx, testctx.decryptor, valuesRes.Coeffs[0], ctxtRes, verifRes, false, t)
			}

		})

		t.Run(testString("ReQuad(c4_1)*c2/", params), func(t *testing.T) {
			ctxtRes, verifRes := vche_2.RunRequadratizationProtocolCFPRF(testctx.prover, testctx.verifier, ctxt4_1, verif4)

			ctxtRes = testctx.evaluator.MulNew(ctxtRes, ctxt2)
			testctx.evaluatorPlaintext.Mul(verifRes, verif2, verifRes)

			valuesRes := testctx.params.RingT().NewPoly()
			R.MulCoeffs(values4, values2, valuesRes)

			verifyTestVectors(testctx, testctx.decryptor, valuesRes.Coeffs[0], ctxtRes, verifRes, false, t)
		})

		t.Run(testString("ReQuad(...ReQuad(c4)*c2)*c2.../", params), func(t *testing.T) {
			ctxtRes, verifRes := vche_2.RunRequadratizationProtocolCFPRF(testctx.prover, testctx.verifier, ctxt4_1, verif4)
			valuesRes := values4.CopyNew()

			for mul := 0; mul < testctx.params.MaxLevel(); mul++ {
				ctxtRes = testctx.evaluator.MulNew(ctxtRes, ctxt2_1)
				testctx.evaluatorPlaintext.Mul(verifRes, verif2, verifRes)

				ctxtRes = testctx.evaluator.RelinearizeNew(ctxtRes)
				verifRes = testctx.evaluatorPlaintext.RelinearizeNew(verifRes)

				ctxtRes, verifRes = vche_2.RunRequadratizationProtocolCFPRF(testctx.prover, testctx.verifier, ctxtRes, verifRes)

				R.MulCoeffs(valuesRes, values2, valuesRes)

				verifyTestVectors(testctx, testctx.decryptor, valuesRes.Coeffs[0], ctxtRes, verifRes, false, t)
			}
		})
	}
}
