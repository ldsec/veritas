package vche_1

import (
	"github.com/ldsec/lattigo/v2/rlwe"
	"veritas/vche/vche"
	"hash"
)

type DummySet map[int]bool

type SecretKey struct {
	*rlwe.SecretKey
	H hash.Hash
	K vche.PRFKey // PRF key
	S DummySet    // Set of dummy indices
}

type PublicKey struct {
	*rlwe.PublicKey
}

type SwitchingKey struct {
	*rlwe.SwitchingKey
	H hash.Hash
}

type RelinearizationKey struct {
	*rlwe.RelinearizationKey
	H hash.Hash
}

type RotationKeySet struct {
	*rlwe.RotationKeySet
	H hash.Hash
}

type EvaluationKey struct {
	rlwe.EvaluationKey
	H hash.Hash
}

func Eq(S1, S2 DummySet) bool {
	if (S1 == nil) != (S2 == nil) {
		return false
	} else if len(S1) != len(S2) {
		return false
	} else {
		for i := range S1 {
			if S1[i] != S2[i] {
				return false
			}
		}
		return true
	}
}
