package vche_2

import (
	"fmt"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/utils"
	"veritas/vche/vche"
	"github.com/stretchr/testify/require"
	"testing"
)

type testContext struct {
	params                    Parameters
	ringQ                     *ring.Ring
	ringT                     *ring.Ring
	prng                      utils.PRNG
	uSampler                  *ring.UniformSampler
	encoder                   Encoder
	evaluatorPlaintextEncoder EncoderPlaintext
	kgen                      KeyGenerator
	sk                        *SecretKey
	pk                        *PublicKey
	rlk                       *RelinearizationKey
	evk                       *EvaluationKey
	rots                      []int
	rotsEvk                   EvaluationKey
	innerSumEvk               EvaluationKey
	encryptorPk               Encryptor
	encryptorSk               Encryptor
	decryptor                 Decryptor
	evaluator                 Evaluator
	evaluatorPlaintext        EvaluatorPlaintext
	prover                    Prover
	verifier                  Verifier
}

func testString(opname string, p Parameters) string {
	return fmt.Sprintf("%sLogN=%d/logQ=%d/alpha=%d/beta=%d", opname, p.LogN(), p.LogQP(), p.PCount(), p.Beta())
}

func testStringNoSplit(opname string, p Parameters) string {
	return fmt.Sprintf("%sLogN=%d&logQ=%d&alpha=%d&beta=%d", opname, p.LogN(), p.LogQP(), p.PCount(), p.Beta())
}

func genTestParams(params Parameters) (testctx *testContext, err error) {
	testctx = new(testContext)
	testctx.params = params

	if testctx.prng, err = utils.NewPRNG(); err != nil {
		return nil, err
	}

	testctx.ringQ = params.RingQ()
	testctx.ringT = params.RingT()

	testctx.uSampler = ring.NewUniformSampler(testctx.prng, testctx.ringT)
	testctx.kgen = NewKeyGenerator(testctx.params)
	testctx.sk, testctx.pk = testctx.kgen.GenKeyPair()
	if params.PCount() != 0 {
		testctx.rlk = testctx.kgen.GenRelinearizationKey(testctx.sk, 1)
	}

	testctx.encoder = NewEncoder(testctx.params, testctx.sk.K, testctx.sk.Alpha, false)
	testctx.evaluatorPlaintextEncoder = NewEncoderPlaintextRequad(testctx.params, testctx.sk.K)
	testctx.encryptorPk = NewEncryptor(testctx.params, testctx.pk)
	testctx.evk = &EvaluationKey{Rlk: testctx.rlk, Rtks: nil}
	innerSumRotKeys := testctx.kgen.GenRotationKeysForInnerSum(testctx.sk)
	testctx.innerSumEvk = EvaluationKey{Rlk: testctx.rlk, Rtks: innerSumRotKeys}
	testctx.rots = []int{1, -1, 4, -4, 63, -63}
	testctx.rotsEvk = EvaluationKey{Rlk: testctx.rlk, Rtks: testctx.kgen.GenRotationKeysForRotations(testctx.rots, true, testctx.sk)}

	testctx.encryptorSk = NewEncryptor(testctx.params, testctx.sk)
	testctx.decryptor = NewDecryptor(testctx.params, testctx.sk)
	testctx.evaluator = NewEvaluator(testctx.params, testctx.evk)
	testctx.evaluatorPlaintext = NewEvaluatorPlaintextRequad(testctx.params)

	testctx.prover, testctx.verifier = NewProverVerifier(testctx.params, testctx.sk, innerSumRotKeys)

	return
}

func newTestVectors(testctx *testContext, encryptor Encryptor, maxValue uint64) (coeffs []uint64, tags []vche.Tag, plaintext *Plaintext, ciphertext *Ciphertext, verifPlaintext *Poly) {
	coeffs = vche.GetRandomCoeffs(testctx.params.NSlots, maxValue)
	tags = vche.GetRandomTags(testctx.params.NSlots)

	plaintext = NewPlaintext(testctx.params)

	testctx.encoder.EncodeUint(coeffs, tags, plaintext)

	if encryptor != nil {
		ciphertext = encryptor.EncryptNew(plaintext)
	}

	verifPlaintext = testctx.evaluatorPlaintextEncoder.EncodeNew(tags)

	return coeffs, tags, plaintext, ciphertext, verifPlaintext
}

func newType1TestVectors(testctx *testContext, encryptor Encryptor, maxValue uint64) (coeffs []uint64, tags []vche.Tag, plaintext *Plaintext, ciphertext *Ciphertext, verifPlaintext *Poly) {
	coeffs = vche.GetRandomCoeffs(testctx.params.NSlots, maxValue)
	tags = vche.GetRandomTags(testctx.params.NSlots)
	tagsForged := make([]vche.Tag, len(tags))
	copy(tagsForged, tags)
	tagsForged[vche.GetRandom(uint64(testctx.params.NSlots))] = vche.GetRandomTags(1)[0]

	plaintext = NewPlaintext(testctx.params)

	testctx.encoder.EncodeUint(coeffs, tagsForged, plaintext)

	if encryptor != nil {
		ciphertext = encryptor.EncryptNew(plaintext)
	}

	verifPlaintext = testctx.evaluatorPlaintextEncoder.EncodeNew(tags)

	return coeffs, tags, plaintext, ciphertext, verifPlaintext
}

func newType2TestVectors(testctx *testContext, encryptor Encryptor, maxValue uint64) (coeffs []uint64, tags []vche.Tag, plaintext *Plaintext, ciphertext *Ciphertext, verifPlaintext *Poly) {
	coeffs = vche.GetRandomCoeffs(testctx.params.NSlots, maxValue)
	tags = vche.GetRandomTags(testctx.params.NSlots)

	plaintext = NewPlaintext(testctx.params)
	testctx.encoder.EncodeUint(coeffs, tags, plaintext)

	plaintext.Plaintexts[0].Value.Coeffs[0][vche.GetRandom(uint64(testctx.params.NSlots))] = vche.GetRandom(maxValue)

	if encryptor != nil {
		ciphertext = encryptor.EncryptNew(plaintext)
	}

	verifPlaintext = testctx.evaluatorPlaintextEncoder.EncodeNew(tags)

	return coeffs, tags, plaintext, ciphertext, verifPlaintext
}

func verifyTestVectors(testctx *testContext, decryptor Decryptor, coeffs []uint64, element Operand, verifPtxt *Poly, polyProt bool, t *testing.T) {
	var coeffsTest []uint64

	switch el := element.(type) {
	case *Plaintext:
		coeffsTest = testctx.encoder.DecodeUintNew(el, verifPtxt)
		require.True(t, utils.EqualSliceUint64(coeffs, coeffsTest))
	case *Ciphertext:
		if testctx.params.MaxLevel() <= 1 {
			polyProt = false
			t.Logf("skipping polynomial protocol for parameters %+v, not enough levels available", testctx.params)
		}

		if polyProt && el.BfvDegree() > 1 {
			t.Logf("ciphertext has degree %d, performing relinearization in order to run polynomial protocol", el.BfvDegree())
			el = testctx.evaluator.RelinearizeNew(el)
		}

		if polyProt {
			// Test polynomial protocol
			require.NotPanics(t, func() {
				coeffsTest = RunPolynomialProtocolUint(testctx.prover, testctx.verifier, el, verifPtxt)
			})
			require.True(t, utils.EqualSliceUint64(coeffs, coeffsTest))
		}

		// Test unoptimized verification procedure
		require.NotPanics(t, func() {
			coeffsTest = testctx.encoder.DecodeUintNew(decryptor.DecryptNew(el), verifPtxt)
		})
		require.True(t, utils.EqualSliceUint64(coeffs, coeffsTest))
	default:
		t.Error("invalid test object to verify")
	}
}

func decodingPanics(testctx *testContext, t *testing.T, ciphertext *Ciphertext, verif *Poly, usePolyProt bool) {
	decodingPanicsWithDecryptor(testctx, t, testctx.decryptor, ciphertext, verif, usePolyProt)
}

func decodingPanicsWithDecryptor(testctx *testContext, t *testing.T, decryptor Decryptor, ciphertext *Ciphertext, verif *Poly, usePolyProt bool) {
	if testctx.params.MaxLevel() <= 1 {
		usePolyProt = false
		t.Logf("skipping polynomial protocol for parameters %+v, not enough levels available", testctx.params)
	}

	if usePolyProt && ciphertext.BfvDegree() > 1 {
		t.Logf("ciphertext has degree %d, performing relinearization in order to run polynomial protocol", ciphertext.BfvDegree())
		ciphertext = testctx.evaluator.RelinearizeNew(ciphertext)
	}

	if usePolyProt {
		require.Panics(t, func() {
			_ = RunPolynomialProtocolUint(testctx.prover, testctx.verifier, ciphertext, verif)
		})
	}

	// Test unoptimized verification procedure
	require.Panics(t, func() {
		_ = testctx.encoder.DecodeUintNew(decryptor.DecryptNew(ciphertext), verif)
	})
}
