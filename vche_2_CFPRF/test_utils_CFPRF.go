package vche_2_CFPRF

import (
	"fmt"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/utils"
	"veritas/vche/vche"
	"veritas/vche/vche_2"
	"github.com/stretchr/testify/require"
	"testing"
)

type testContext struct {
	params                    vche_2.Parameters
	ringQ                     *ring.Ring
	ringT                     *ring.Ring
	prng                      utils.PRNG
	uSampler                  *ring.UniformSampler
	encoder                   vche_2.Encoder
	evaluatorPlaintextEncoder vche_2.EncoderPlaintextCFPRF
	kgen                      vche_2.KeyGenerator
	sk                        *vche_2.SecretKey
	pk                        *vche_2.PublicKey
	rlk                       *vche_2.RelinearizationKey
	evk                       *vche_2.EvaluationKey
	rots                      []int
	rotsEvk                   vche_2.EvaluationKey
	innerSumEvk               vche_2.EvaluationKey
	encryptorPk               vche_2.Encryptor
	encryptorSk               vche_2.Encryptor
	decryptor                 vche_2.Decryptor
	evaluator                 vche_2.Evaluator
	evaluatorPlaintext        vche_2.EvaluatorPlaintextCFPRF
	prover                    vche_2.Prover
	verifier                  vche_2.Verifier
}

func testString(opname string, p vche_2.Parameters) string {
	return fmt.Sprintf("%sLogN=%d/logQ=%d/alpha=%d/beta=%d", opname, p.LogN(), p.LogQP(), p.PCount(), p.Beta())
}

func genTestParams(params vche_2.Parameters) (testctx *testContext, err error) {
	testctx = new(testContext)
	testctx.params = params

	if testctx.prng, err = utils.NewPRNG(); err != nil {
		return nil, err
	}

	testctx.ringQ = params.RingQ()
	testctx.ringT = params.RingT()

	testctx.uSampler = ring.NewUniformSampler(testctx.prng, testctx.ringT)
	testctx.kgen = vche_2.NewKeyGenerator(testctx.params)
	testctx.sk, testctx.pk = testctx.kgen.GenKeyPair()
	if params.PCount() != 0 {
		testctx.rlk = testctx.kgen.GenRelinearizationKey(testctx.sk, 1)
	}

	testctx.encoder = vche_2.NewEncoder(testctx.params, testctx.sk.K, testctx.sk.Alpha, true)
	testctx.evaluatorPlaintextEncoder = vche_2.NewEncoderPlaintextCFPRFRequad(testctx.params, testctx.sk.K)
	testctx.encryptorPk = vche_2.NewEncryptor(testctx.params, testctx.pk)
	testctx.evk = &vche_2.EvaluationKey{Rlk: testctx.rlk, Rtks: nil}
	innerSumRotKeys := testctx.kgen.GenRotationKeysForInnerSum(testctx.sk)
	testctx.innerSumEvk = vche_2.EvaluationKey{Rlk: testctx.rlk, Rtks: innerSumRotKeys}
	testctx.rots = []int{1, -1, 4, -4, 63, -63}
	testctx.rotsEvk = vche_2.EvaluationKey{Rlk: testctx.rlk, Rtks: testctx.kgen.GenRotationKeysForRotations(testctx.rots, true, testctx.sk)}

	testctx.encryptorSk = vche_2.NewEncryptor(testctx.params, testctx.sk)
	testctx.decryptor = vche_2.NewDecryptor(testctx.params, testctx.sk)
	testctx.evaluator = vche_2.NewEvaluator(testctx.params, testctx.evk)
	testctx.evaluatorPlaintext = vche_2.NewEvaluatorPlaintextCFPRFRequad(testctx.params)

	testctx.prover, testctx.verifier = vche_2.NewProverVerifier(testctx.params, testctx.sk, innerSumRotKeys)

	return
}

func newTestVectors(testctx *testContext, encryptor vche_2.Encryptor, maxValue uint64) (coeffs []uint64, tags []vche.Tag, plaintext *vche_2.Plaintext, ciphertext *vche_2.Ciphertext, verifPlaintext *vche_2.VerifPlaintext) {
	coeffs = vche.GetRandomCoeffs(testctx.params.NSlots, maxValue)
	tags = vche.GetRandomTagsSameIndex(testctx.params.NSlots)

	plaintext = vche_2.NewPlaintext(testctx.params)

	testctx.encoder.EncodeUint(coeffs, tags, plaintext)

	if encryptor != nil {
		ciphertext = encryptor.EncryptNew(plaintext)
	}

	verifPlaintext = testctx.evaluatorPlaintextEncoder.EncodeNew(tags)

	return coeffs, tags, plaintext, ciphertext, verifPlaintext
}

func newType1TestVectors(testctx *testContext, encryptor vche_2.Encryptor, maxValue uint64) (coeffs []uint64, tags []vche.Tag, plaintext *vche_2.Plaintext, ciphertext *vche_2.Ciphertext, verifPlaintext *vche_2.VerifPlaintext) {
	coeffs = vche.GetRandomCoeffs(testctx.params.NSlots, maxValue)
	tags = vche.GetRandomTagsSameIndex(testctx.params.NSlots)
	tagsForged := make([]vche.Tag, len(tags))
	copy(tagsForged, tags)
	tagsForged[vche.GetRandom(uint64(testctx.params.NSlots))] = vche.GetRandomTags(1)[0]

	plaintext = vche_2.NewPlaintext(testctx.params)

	testctx.encoder.EncodeUint(coeffs, tagsForged, plaintext)

	if encryptor != nil {
		ciphertext = encryptor.EncryptNew(plaintext)
	}

	verifPlaintext = testctx.evaluatorPlaintextEncoder.EncodeNew(tags)

	return coeffs, tags, plaintext, ciphertext, verifPlaintext
}

func newType2TestVectors(testctx *testContext, encryptor vche_2.Encryptor, maxValue uint64) (coeffs []uint64, tags []vche.Tag, plaintext *vche_2.Plaintext, ciphertext *vche_2.Ciphertext, verifPlaintext *vche_2.VerifPlaintext) {
	coeffs = vche.GetRandomCoeffs(testctx.params.NSlots, maxValue)
	tags = vche.GetRandomTagsSameIndex(testctx.params.NSlots)

	plaintext = vche_2.NewPlaintext(testctx.params)
	testctx.encoder.EncodeUint(coeffs, tags, plaintext)

	plaintext.Plaintexts[0].Value.Coeffs[0][vche.GetRandom(uint64(testctx.params.NSlots))] = vche.GetRandom(maxValue)

	if encryptor != nil {
		ciphertext = encryptor.EncryptNew(plaintext)
	}

	verifPlaintext = testctx.evaluatorPlaintextEncoder.EncodeNew(tags)

	return coeffs, tags, plaintext, ciphertext, verifPlaintext
}

func verifyTestVectors(testctx *testContext, decryptor vche_2.Decryptor, coeffs []uint64, element vche_2.Operand, verifPtxt *vche_2.VerifPlaintext, polyProt bool, t *testing.T) {
	var coeffsTest []uint64

	switch el := element.(type) {
	case *vche_2.Plaintext:
		testctx.evaluatorPlaintext.ComputeMemo(verifPtxt)
		coeffsTest = testctx.encoder.DecodeUintNew(el, testctx.evaluatorPlaintext.Eval(verifPtxt))
		require.True(t, utils.EqualSliceUint64(coeffs, coeffsTest))
	case *vche_2.Ciphertext:
		if testctx.params.MaxLevel() <= 1 {
			polyProt = false
			t.Logf("skipping polynomial protocol for parameters %+v, not enough levels available", testctx.params)
		}

		if polyProt && el.BfvDegree() > 1 {
			t.Logf("ciphertext has degree %d, performing relinearization in order to run polynomial protocol", el.BfvDegree())
			el = testctx.evaluator.RelinearizeNew(el)
		}

		testctx.evaluatorPlaintext.ComputeMemo(verifPtxt)
		v := testctx.evaluatorPlaintext.Eval(verifPtxt)

		if polyProt {
			// Test polynomial protocol
			require.NotPanics(t, func() {
				coeffsTest = vche_2.RunPolynomialProtocolUint(testctx.prover, testctx.verifier, el, v)
			})
			require.True(t, utils.EqualSliceUint64(coeffs, coeffsTest))
		}

		// Test unoptimized verification procedure
		require.NotPanics(t, func() {
			coeffsTest = testctx.encoder.DecodeUintNew(decryptor.DecryptNew(el), v)
		})
		require.True(t, utils.EqualSliceUint64(coeffs, coeffsTest))
	default:
		t.Error("invalid test object to verify")
	}
}

func decodingPanics(testctx *testContext, t *testing.T, ciphertext *vche_2.Ciphertext, verif *vche_2.VerifPlaintext, usePolyProt bool) {
	decodingPanicsWithDecryptor(testctx, t, testctx.decryptor, ciphertext, verif, usePolyProt)
}

func decodingPanicsWithDecryptor(testctx *testContext, t *testing.T, decryptor vche_2.Decryptor, ciphertext *vche_2.Ciphertext, verif *vche_2.VerifPlaintext, usePolyProt bool) {
	if testctx.params.MaxLevel() <= 1 {
		usePolyProt = false
		t.Logf("skipping polynomial protocol for parameters %+v, not enough levels available", testctx.params)
	}

	if usePolyProt && ciphertext.BfvDegree() > 1 {
		t.Logf("ciphertext has degree %d, performing relinearization in order to run polynomial protocol", ciphertext.BfvDegree())
		ciphertext = testctx.evaluator.RelinearizeNew(ciphertext)
	}
	testctx.evaluatorPlaintext.ComputeMemo(verif)
	v := testctx.evaluatorPlaintext.Eval(verif)

	if usePolyProt {
		require.Panics(t, func() {
			_ = vche_2.RunPolynomialProtocolUint(testctx.prover, testctx.verifier, ciphertext, v)
		})
	}

	// Test unoptimized verification procedure
	require.Panics(t, func() {
		_ = testctx.encoder.DecodeUintNew(decryptor.DecryptNew(ciphertext), v)
	})
}
