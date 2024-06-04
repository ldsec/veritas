package vche_1

import (
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/rlwe"
	"github.com/ldsec/lattigo/v2/utils"
	"veritas/vche/vche"
	"golang.org/x/crypto/blake2b"
	"hash"
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
	H      hash.Hash
}

func NewKeyGenerator(params Parameters) KeyGenerator {
	H, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}

	return &keyGenerator{bfv.NewKeyGenerator(params.Parameters), params, H}
}

func (keygen *keyGenerator) GenSecretKey() (sk *SecretKey) {
	return &SecretKey{SecretKey: keygen.KeyGenerator.GenSecretKey(),
		H: keygen.H,
		K: vche.NewPRFKey(8),
		S: NewDummySet(keygen.params.NumReplications),
	}
}

func (keygen *keyGenerator) GenPublicKey(sk *SecretKey) (pk *PublicKey) {
	return &PublicKey{keygen.KeyGenerator.GenPublicKey(sk.SecretKey)}
}

func (keygen *keyGenerator) GenKeyPair() (sk *SecretKey, pk *PublicKey) {
	sk = keygen.GenSecretKey()
	return sk, keygen.GenPublicKey(sk)
}

func (keygen *keyGenerator) GenSwitchingKey(skInput, skOutput *SecretKey) (newevakey *SwitchingKey) {
	if !Eq(skOutput.S, skInput.S) {
		panic("dummy set of old and new key must be the same to generate a switching key")
	}
	return &SwitchingKey{
		keygen.KeyGenerator.GenSwitchingKey(skInput.SecretKey, skOutput.SecretKey),
		keygen.H,
	}
}

func (keygen *keyGenerator) GenRotationKeys(galEls []uint64, sk *SecretKey) (rks *RotationKeySet) {
	return &RotationKeySet{keygen.KeyGenerator.GenRotationKeys(galEls, sk.SecretKey), keygen.H}
}

func (keygen *keyGenerator) GenRelinearizationKey(sk *SecretKey, maxDegree int) (evk *RelinearizationKey) {
	return &RelinearizationKey{keygen.KeyGenerator.GenRelinearizationKey(sk.SecretKey, maxDegree), keygen.H}
}

func (keygen *keyGenerator) GenRotationKeysForRotations(ks []int, inclueSwapRows bool, sk *SecretKey) (rks *RotationKeySet) {
	ksPrime := make([]int, len(ks))
	for i := range ks {
		ksPrime[i] = ks[i] * keygen.params.NumReplications
	}
	return &RotationKeySet{keygen.KeyGenerator.GenRotationKeysForRotations(ksPrime, inclueSwapRows, sk.SecretKey), sk.H}
}

func (keygen *keyGenerator) GenRotationKeysForInnerSum(sk *SecretKey) (rks *RotationKeySet) {
	return &RotationKeySet{keygen.KeyGenerator.GenRotationKeysForInnerSum(sk.SecretKey), sk.H}
}

func NewDummySet(lambda int) DummySet {
	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}

	for {
		countDummies := 0
		S := make(DummySet)

		for i := 0; i < lambda; i++ {
			b := ring.RandUniform(prng, 2, 1)
			if b == 1 {
				countDummies += 1
				S[i] = true
			}
		}
		if countDummies == lambda/2 {
			return S
		}
	}
}
