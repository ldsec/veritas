package vche_1_CFPRF

import (
	"fmt"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/rlwe"
	"github.com/ldsec/lattigo/v2/utils"
	"veritas/vche/vche"
	"veritas/vche/vche_1"
	"github.com/stretchr/testify/require"
	"testing"
)

type testContext struct {
	params                    vche_1.Parameters
	ringQ                     *ring.Ring
	ringT                     *ring.Ring
	prng                      utils.PRNG
	uSampler                  *ring.UniformSampler
	encoder                   vche_1.Encoder
	evaluatorPlaintextEncoder vche_1.EncoderPlaintextCFPRF
	kgen                      vche_1.KeyGenerator
	sk                        *vche_1.SecretKey
	//pk          *rlwe.PublicKey
	rlk         *vche_1.RelinearizationKey
	evk         *vche_1.EvaluationKey
	rots        []int
	rotsEvk     vche_1.EvaluationKey
	innerSumEvk vche_1.EvaluationKey
	//encryptorPk Encryptor
	encryptorSk        vche_1.Encryptor
	decryptor          vche_1.Decryptor
	evaluator          vche_1.Evaluator
	evaluatorPlaintext vche_1.EvaluatorPlaintextCFPRF
}

func testString(opname string, p vche_1.Parameters) string {
	return fmt.Sprintf("%sLogN=%d/logQ=%d/alpha=%d/beta=%d", opname, p.LogN(), p.LogQP(), p.PCount(), p.Beta())
}

func genTestParams(params vche_1.Parameters) (testctx *testContext, err error) {

	testctx = new(testContext)
	testctx.params = params

	if testctx.prng, err = utils.NewPRNG(); err != nil {
		return nil, err
	}

	testctx.ringQ = params.RingQ()
	testctx.ringT = params.RingT()

	testctx.uSampler = ring.NewUniformSampler(testctx.prng, testctx.ringT)
	testctx.kgen = vche_1.NewKeyGenerator(testctx.params)
	//testctx.sk, testctx.pk = testctx.kgen.GenKeyPair()
	testctx.sk = testctx.kgen.GenSecretKey()
	if params.PCount() != 0 {
		testctx.rlk = testctx.kgen.GenRelinearizationKey(testctx.sk, 1)
	}

	testctx.encoder = vche_1.NewEncoder(testctx.params, testctx.sk.K, testctx.sk.S, true)
	testctx.evaluatorPlaintextEncoder = vche_1.NewEncoderPlaintextCFPRF(testctx.params, testctx.sk.K)
	//testctx.encryptorPk = NewEncryptor(testctx.params, testctx.pk)
	testctx.evk = &vche_1.EvaluationKey{EvaluationKey: rlwe.EvaluationKey{Rlk: testctx.rlk.RelinearizationKey, Rtks: nil}, H: testctx.rlk.H}
	testctx.innerSumEvk = vche_1.EvaluationKey{EvaluationKey: rlwe.EvaluationKey{Rlk: testctx.rlk.RelinearizationKey, Rtks: testctx.kgen.GenRotationKeysForInnerSum(testctx.sk).RotationKeySet}, H: testctx.sk.H}
	testctx.rots = []int{1, -1, 4, -4, 63, -63}
	testctx.rotsEvk = vche_1.EvaluationKey{EvaluationKey: rlwe.EvaluationKey{Rlk: testctx.rlk.RelinearizationKey, Rtks: testctx.kgen.GenRotationKeysForRotations(testctx.rots, true, testctx.sk).RotationKeySet}, H: testctx.sk.H}

	testctx.encryptorSk = vche_1.NewEncryptor(testctx.params, testctx.sk)
	testctx.decryptor = vche_1.NewDecryptor(testctx.params, testctx.sk)
	testctx.evaluator = vche_1.NewEvaluator(testctx.params, testctx.evk)
	testctx.evaluatorPlaintext = vche_1.NewEvaluatorPlaintextCFPRF(testctx.params, testctx.evk.H)
	return

}

func newTestVectors(testctx *testContext, encryptor vche_1.Encryptor, maxValue uint64) (coeffs []uint64, tags []vche.Tag, plaintext *vche_1.Plaintext, ciphertext *vche_1.Ciphertext, verifPlaintext *vche_1.VerifPlaintext) {
	coeffs = vche.GetRandomCoeffs(testctx.params.NSlots, maxValue)
	tags = vche.GetRandomTagsSameIndex(testctx.params.NSlots)

	plaintext = vche_1.NewPlaintext(testctx.params)

	testctx.encoder.EncodeUint(coeffs, tags, plaintext)

	if encryptor != nil {
		ciphertext = encryptor.EncryptNew(plaintext)
	}

	verifPlaintext = testctx.evaluatorPlaintextEncoder.EncodeNew(tags)

	return coeffs, tags, plaintext, ciphertext, verifPlaintext
}

func newType1TestVectors(testctx *testContext, encryptor vche_1.Encryptor, maxValue uint64) (coeffs []uint64, tags []vche.Tag, plaintext *vche_1.Plaintext, ciphertext *vche_1.Ciphertext, verifPlaintext *vche_1.VerifPlaintext) {
	coeffs = vche.GetRandomCoeffs(testctx.params.NSlots, maxValue)
	tags = vche.GetRandomTagsSameIndex(testctx.params.NSlots)
	tagsForged := make([]vche.Tag, len(tags))
	copy(tagsForged, tags)
	tagsForged[vche.GetRandom(uint64(len(tags)))] = vche.GetRandomTagsSameIndex(1)[0]

	plaintext = vche_1.NewPlaintext(testctx.params)

	testctx.encoder.EncodeUint(coeffs, tagsForged, plaintext)

	if encryptor != nil {
		ciphertext = encryptor.EncryptNew(plaintext)
	}

	verifPlaintext = testctx.evaluatorPlaintextEncoder.EncodeNew(tags)

	return coeffs, tags, plaintext, ciphertext, verifPlaintext
}

func newType2TestVectors(testctx *testContext, encryptor vche_1.Encryptor, maxValue uint64) (coeffs []uint64, tags []vche.Tag, plaintext *vche_1.Plaintext, ciphertext *vche_1.Ciphertext, verifPlaintext *vche_1.VerifPlaintext) {
	coeffs = vche.GetRandomCoeffs(testctx.params.NSlots, maxValue)
	tags = vche.GetRandomTagsSameIndex(testctx.params.NSlots)

	plaintext = vche_1.NewPlaintext(testctx.params)
	testctx.encoder.EncodeUint(coeffs, tags, plaintext)

	plaintext.Value.Coeffs[0][vche.GetRandom(uint64(testctx.params.NSlots))] = vche.GetRandom(maxValue)

	if encryptor != nil {
		ciphertext = encryptor.EncryptNew(plaintext)
	}

	verifPlaintext = testctx.evaluatorPlaintextEncoder.EncodeNew(tags)

	return coeffs, tags, plaintext, ciphertext, verifPlaintext
}

func verifyTestVectors(testctx *testContext, decryptor vche_1.Decryptor, coeffs []uint64, element vche_1.Operand, verifPtxt *vche_1.VerifPlaintext, t *testing.T) {
	var coeffsTest []uint64

	switch el := element.(type) {
	case *vche_1.Plaintext:
		testctx.evaluatorPlaintext.ComputeMemo(verifPtxt)
		coeffsTest = testctx.encoder.DecodeUintNew(el, testctx.evaluatorPlaintext.Eval(verifPtxt))
	case *vche_1.Ciphertext:
		testctx.evaluatorPlaintext.ComputeMemo(verifPtxt)
		coeffsTest = testctx.encoder.DecodeUintNew(decryptor.DecryptNew(el), testctx.evaluatorPlaintext.Eval(verifPtxt))
	default:
		t.Error("invalid test object to verify")
	}

	require.True(t, utils.EqualSliceUint64(coeffs, coeffsTest))
}

func decodingPanics(testctx *testContext, t *testing.T, ciphertext *vche_1.Ciphertext, verif *vche_1.VerifPlaintext) {
	decodingPanicsWithDecryptor(testctx, t, testctx.decryptor, ciphertext, verif)
}

func decodingPanicsWithDecryptor(testctx *testContext, t *testing.T, decryptor vche_1.Decryptor, ciphertext *vche_1.Ciphertext, verif *vche_1.VerifPlaintext) {
	plaintext := decryptor.DecryptNew(ciphertext)
	testctx.evaluatorPlaintext.ComputeMemo(verif)
	require.Panics(t, func() { testctx.encoder.DecodeUintNew(plaintext, testctx.evaluatorPlaintext.Eval(verif)) })
}
