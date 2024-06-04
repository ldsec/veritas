package vche_1

import (
	"fmt"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/rlwe"
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
	//pk          *rlwe.PublicKey
	rlk         *RelinearizationKey
	evk         *EvaluationKey
	rots        []int
	rotsEvk     EvaluationKey
	innerSumEvk EvaluationKey
	//encryptorPk Encryptor
	encryptorSk        Encryptor
	decryptor          Decryptor
	evaluator          Evaluator
	evaluatorPlaintext EvaluatorPlaintext
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
	//testctx.sk, testctx.pk = testctx.kgen.GenKeyPair()
	testctx.sk = testctx.kgen.GenSecretKey()
	if params.PCount() != 0 {
		testctx.rlk = testctx.kgen.GenRelinearizationKey(testctx.sk, 1)
	}

	testctx.encoder = NewEncoder(testctx.params, testctx.sk.K, testctx.sk.S, false)
	testctx.evaluatorPlaintextEncoder = NewEncoderPlaintext(testctx.params, testctx.sk.K)
	//testctx.encryptorPk = NewEncryptor(testctx.params, testctx.pk)
	testctx.evk = &EvaluationKey{rlwe.EvaluationKey{Rlk: testctx.rlk.RelinearizationKey, Rtks: nil}, testctx.rlk.H}
	testctx.innerSumEvk = EvaluationKey{rlwe.EvaluationKey{Rlk: testctx.rlk.RelinearizationKey, Rtks: testctx.kgen.GenRotationKeysForInnerSum(testctx.sk).RotationKeySet}, testctx.sk.H}
	testctx.rots = []int{1, -1, 4, -4, 63, -63}
	testctx.rotsEvk = EvaluationKey{rlwe.EvaluationKey{Rlk: testctx.rlk.RelinearizationKey, Rtks: testctx.kgen.GenRotationKeysForRotations(testctx.rots, true, testctx.sk).RotationKeySet}, testctx.sk.H}

	testctx.encryptorSk = NewEncryptor(testctx.params, testctx.sk)
	testctx.decryptor = NewDecryptor(testctx.params, testctx.sk)
	testctx.evaluator = NewEvaluator(testctx.params, testctx.evk)
	testctx.evaluatorPlaintext = NewEvaluatorPlaintext(testctx.params, testctx.evk.H)
	return
}

func newTestVectors(testctx *testContext, encryptor Encryptor, maxValue uint64) (coeffs []uint64, tags []vche.Tag, plaintext *Plaintext, ciphertext *Ciphertext, verifPlaintext *TaggedPoly) {
	coeffs = vche.GetRandomCoeffs(testctx.params.NSlots, maxValue)
	//DEBUG
	for i := range coeffs {
		coeffs[i] = 0 //testctx.params.T() - 1
	}
	//
	tags = vche.GetRandomTags(testctx.params.NSlots)

	plaintext = NewPlaintext(testctx.params)

	testctx.encoder.EncodeUint(coeffs, tags, plaintext)

	if encryptor != nil {
		ciphertext = encryptor.EncryptNew(plaintext)
	}

	verifPlaintext = testctx.evaluatorPlaintextEncoder.EncodeNew(tags)

	return coeffs, tags, plaintext, ciphertext, verifPlaintext
}

func newType1TestVectors(testctx *testContext, encryptor Encryptor, maxValue uint64) (coeffs []uint64, tags []vche.Tag, plaintext *Plaintext, ciphertext *Ciphertext, verifPlaintext *TaggedPoly) {
	coeffs = vche.GetRandomCoeffs(testctx.params.NSlots, maxValue)
	tags = vche.GetRandomTags(testctx.params.NSlots)
	tagsForged := make([]vche.Tag, len(tags))
	copy(tagsForged, tags)
	tagsForged[vche.GetRandom(uint64(len(tags)))] = vche.GetRandomTags(1)[0]

	plaintext = NewPlaintext(testctx.params)

	testctx.encoder.EncodeUint(coeffs, tagsForged, plaintext)

	if encryptor != nil {
		ciphertext = encryptor.EncryptNew(plaintext)
	}

	verifPlaintext = testctx.evaluatorPlaintextEncoder.EncodeNew(tags)

	return coeffs, tags, plaintext, ciphertext, verifPlaintext
}

func newType2TestVectors(testctx *testContext, encryptor Encryptor, maxValue uint64) (coeffs []uint64, tags []vche.Tag, plaintext *Plaintext, ciphertext *Ciphertext, verifPlaintext *TaggedPoly) {
	coeffs = vche.GetRandomCoeffs(testctx.params.NSlots, maxValue)
	tags = vche.GetRandomTags(testctx.params.NSlots)

	plaintext = NewPlaintext(testctx.params)
	testctx.encoder.EncodeUint(coeffs, tags, plaintext)

	plaintext.Value.Coeffs[0][vche.GetRandom(uint64(testctx.params.NSlots))] = vche.GetRandom(maxValue)

	if encryptor != nil {
		ciphertext = encryptor.EncryptNew(plaintext)
	}

	verifPlaintext = testctx.evaluatorPlaintextEncoder.EncodeNew(tags)

	return coeffs, tags, plaintext, ciphertext, verifPlaintext
}

func verifyTestVectors(testctx *testContext, decryptor Decryptor, coeffs []uint64, element Operand, verifPtxt *TaggedPoly, t *testing.T) {
	var coeffsTest []uint64

	switch el := element.(type) {
	case *Plaintext:
		coeffsTest = testctx.encoder.DecodeUintNew(el, verifPtxt)
	case *Ciphertext:
		coeffsTest = testctx.encoder.DecodeUintNew(decryptor.DecryptNew(el), verifPtxt)
	default:
		t.Error("invalid test object to verify")
	}

	require.True(t, utils.EqualSliceUint64(coeffs, coeffsTest))
}

func decodingPanics(testctx *testContext, t *testing.T, ciphertext *Ciphertext, verif *TaggedPoly) {
	decodingPanicsWithDecryptor(testctx, t, testctx.decryptor, ciphertext, verif)
}

func decodingPanicsWithDecryptor(testctx *testContext, t *testing.T, decryptor Decryptor, ciphertext *Ciphertext, verif *TaggedPoly) {
	plaintext := decryptor.DecryptNew(ciphertext)
	require.Panics(t, func() { testctx.encoder.DecodeUintNew(plaintext, verif) })
}
