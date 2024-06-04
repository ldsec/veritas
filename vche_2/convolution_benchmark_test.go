package vche_2

import (
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/utils"
	"veritas/vche/vche"
	"github.com/stretchr/testify/require"
	"testing"
)

func BenchmarkConvolution(b *testing.B) {
	var params, _ = NewParametersFromLiteral(DefaultParams[len(DefaultParams)-1])
	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	relinKey := kgen.GenRelinearizationKey(sk, 1)
	var eval *evaluator = &evaluator{vche.NewEvaluator(params, vche.EvaluationKey{
		Rlk:  relinKey,
		Rtks: nil,
	}), params, params.RingT().NewPoly()}
	var prng, _ = utils.NewPRNG()

	for run := 0; run < b.N; run++ {
		ciphertexts := make([]*bfv.Ciphertext, 2)
		for i := range ciphertexts {
			ciphertexts[i] = bfv.NewCiphertextRandom(prng, params.Parameters, 1)
		}
		ctxt1 := &Ciphertext{ciphertexts}
		ctxt2 := ctxt1.CopyNew()
		ctxt3 := ctxt1.CopyNew()

		for i := 1; i < 8; i++ {
			var tmp *Ciphertext
			b.Run(fmt.Sprintf("Mul_%dx%d/Naive", ctxt1.Len(), ctxt1.Len()), func(b *testing.B) {
				tmp = eval.MulNaiveNew(ctxt1, ctxt1)
			})
			eval.Relinearize(tmp, tmp)
			ctxt1 = tmp

			b.Run(fmt.Sprintf("Mul_%dx%d/Karatsuba", ctxt2.Len(), ctxt2.Len()), func(b *testing.B) {
				tmp = eval.MulKaratsubaNew(ctxt2, ctxt2)
			})
			eval.Relinearize(tmp, tmp)
			ctxt2 = tmp

			b.Run(fmt.Sprintf("Mul_%dx%d/Fast", ctxt3.Len(), ctxt3.Len()), func(b *testing.B) {
				tmp.Ciphertexts = eval.Evaluator.Convolve(ctxt3.Ciphertexts, ctxt3.Ciphertexts)
			})
			eval.Relinearize(tmp, tmp)
			ctxt3 = tmp
		}
	}
}

func TestConvolution(t *testing.T) {
	var params, _ = NewParametersFromLiteral(DefaultParams[len(DefaultParams)-1])
	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	relinKey := kgen.GenRelinearizationKey(sk, 1)
	var eval *evaluator = &evaluator{vche.NewEvaluator(params, vche.EvaluationKey{
		Rlk:  relinKey,
		Rtks: nil,
	}), params, nil}
	encoder := NewEncoder(params, sk.K, sk.Alpha, false)
	encryptor := NewEncryptor(params, sk)
	decryptor := NewDecryptor(params, sk)
	encoderPlaintext := NewEncoderPlaintext(params, sk.K)
	evaluatorPlaintext := NewEvaluatorPlaintext(params)

	var prng, _ = utils.NewPRNG()

	ciphertexts := make([]*bfv.Ciphertext, 2)
	for i := range ciphertexts {
		ciphertexts[i] = bfv.NewCiphertextRandom(prng, params.Parameters, 1)
	}
	coeffs := vche.GetRandomCoeffs(params.NSlots, params.T())
	tags := vche.GetRandomTags(params.NSlots)
	ctxt1 := encryptor.EncryptNew(encoder.EncodeUintNew(coeffs, tags))
	ctxt2 := ctxt1.CopyNew()
	ctxt3 := ctxt1.CopyNew()
	verif := encoderPlaintext.EncodeNew(tags)

	for i := 1; i < 4; i++ {
		var tmp *Ciphertext
		var tmpVerif *Poly

		t.Run(fmt.Sprintf("Mul_%dx%d/Naive", ctxt1.Len(), ctxt1.Len()), func(t *testing.T) {
			tmp = eval.MulNaiveNew(ctxt1, ctxt1)
			tmpVerif = evaluatorPlaintext.MulNew(verif, verif)

			eval.Relinearize(tmp, tmp)
			evaluatorPlaintext.Relinearize(tmpVerif, tmpVerif)

		})
		truth := encoder.DecodeUintNew(decryptor.DecryptNew(tmp), tmpVerif)
		ctxt1 = tmp
		verif = tmpVerif

		t.Run(fmt.Sprintf("Mul_%dx%d/Karatsuba", ctxt2.Len(), ctxt2.Len()), func(t *testing.T) {
			tmp = eval.MulKaratsubaNew(ctxt2, ctxt2)
			require.Equal(t, truth, encoder.DecodeUintNew(decryptor.DecryptNew(tmp), verif))
		})
		eval.Relinearize(tmp, tmp)
		ctxt2 = tmp

		t.Run(fmt.Sprintf("Mul_%dx%d/Fast", ctxt3.Len(), ctxt3.Len()), func(t *testing.T) {
			tmp.Ciphertexts = eval.Evaluator.Convolve(ctxt3.Ciphertexts, ctxt3.Ciphertexts)

			require.Equal(t, truth, encoder.DecodeUintNew(decryptor.DecryptNew(tmp), verif))
		})
		eval.Relinearize(tmp, tmp)
		ctxt3 = tmp
	}
}
