package vche_2

import (
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/rlwe"
	"github.com/ldsec/lattigo/v2/utils"
	"veritas/vche/vche"
	"math/big"
	"math/bits"
)

type KeyGenerator interface {
	GenSecretKey() (sk *SecretKey)
	GenPublicKey(sk *SecretKey) (pk *PublicKey)
	GenKeyPair() (sk *SecretKey, pk *PublicKey)
	GenRelinearizationKey(sk *SecretKey, maxDegree int) (evk *RelinearizationKey)
	GenSwitchingKey(skInput, skOutput *SecretKey) (newevakey *SwitchingKey)
	GenRotationKeys(galEls []uint64, sk *SecretKey) (rks *RotationKeySet)
	GenRotationKeysForRotations(ks []int, inclueSwapRows bool, sk *SecretKey) (rks *RotationKeySet)
	GenRotationKeysForInnerSum(sk *SecretKey) (rks *RotationKeySet)
}

type keyGenerator struct {
	rlwe.KeyGenerator
	params Parameters
}

func NewKeyGenerator(params Parameters) KeyGenerator {
	return &keyGenerator{bfv.NewKeyGenerator(params.Parameters), params}
}

func (keygen *keyGenerator) GenSecretKey() (sk *SecretKey) {
	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}

	sk = &SecretKey{
		SecretKey: keygen.KeyGenerator.GenSecretKey(),
		K:         make([]vche.PRFKey, keygen.params.NumDistinctPRFKeys),
		Alpha:     make([]uint64, keygen.params.NumDistinctPRFKeys),
		alphaInv:  make([]uint64, keygen.params.NumDistinctPRFKeys),
	}
	for i := 0; i < keygen.params.NumDistinctPRFKeys; i++ {
		sk.K[i] = vche.NewPRFKey(8)

		alpha := uint64(0)
		for alpha == 0 {
			alpha = ring.RandUniform(prng, keygen.params.T(), uint64(1<<uint64(bits.Len64(keygen.params.T())))-1)
		}
		sk.Alpha[i] = alpha

		alphaInv := modInv(alpha, keygen.params.T())
		if multModT(alpha, alphaInv, keygen.params.T()) != uint64(1) {
			panic(fmt.Errorf("alpha=%d (at position %d) is not invertible", alpha, i))
		}

		sk.alphaInv[i] = alphaInv
	}
	return sk
}

func (keygen *keyGenerator) GenPublicKey(sk *SecretKey) (pk *PublicKey) {
	return keygen.KeyGenerator.GenPublicKey(sk.SecretKey)
}

func (keygen *keyGenerator) GenKeyPair() (sk *SecretKey, pk *PublicKey) {
	sk = keygen.GenSecretKey()
	return sk, keygen.GenPublicKey(sk)
}

func (keygen *keyGenerator) GenSwitchingKey(skInput, skOutput *SecretKey) (newevakey *SwitchingKey) {
	if !utils.EqualSliceUint64(skInput.Alpha, skOutput.Alpha) {
		panic("alpha of old and new key must be the same to generate a switching key")
	}
	return keygen.KeyGenerator.GenSwitchingKey(skInput.SecretKey, skOutput.SecretKey)
}

func (keygen *keyGenerator) GenRotationKeys(galEls []uint64, sk *SecretKey) (rks *RotationKeySet) {
	return keygen.KeyGenerator.GenRotationKeys(galEls, sk.SecretKey)
}

func (keygen *keyGenerator) GenRelinearizationKey(sk *SecretKey, maxDegree int) (evk *RelinearizationKey) {
	return keygen.KeyGenerator.GenRelinearizationKey(sk.SecretKey, maxDegree)
}

func (keygen *keyGenerator) GenRotationKeysForRotations(ks []int, inclueSwapRows bool, sk *SecretKey) (rks *RotationKeySet) {
	ksPrime := make([]int, len(ks))
	for i := range ks {
		ksPrime[i] = ks[i] * keygen.params.NumReplications
	}
	return keygen.KeyGenerator.GenRotationKeysForRotations(ksPrime, inclueSwapRows, sk.SecretKey)
}

func (keygen *keyGenerator) GenRotationKeysForInnerSum(sk *SecretKey) (rks *RotationKeySet) {
	return keygen.KeyGenerator.GenRotationKeysForInnerSum(sk.SecretKey)
}

func modInv(x, T uint64) uint64 {
	return big.NewInt(0).ModInverse(big.NewInt(int64(x)), big.NewInt(int64(T))).Uint64()
}

func multModT(a, b uint64, T uint64) uint64 {
	res := big.NewInt(0)
	res = res.Mul(big.NewInt(int64(a)), big.NewInt(int64(b)))
	res = res.Mod(res, big.NewInt(int64(T)))
	return res.Uint64()
}
