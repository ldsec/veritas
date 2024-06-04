package vche_2

import (
	"github.com/ldsec/lattigo/v2/rlwe"
	"veritas/vche/vche"
)

type SecretKey struct {
	*rlwe.SecretKey
	K        []vche.PRFKey
	Alpha    []uint64
	alphaInv []uint64
}

type PublicKey = rlwe.PublicKey

type SwitchingKey = rlwe.SwitchingKey

type RelinearizationKey = rlwe.RelinearizationKey

type RotationKeySet = rlwe.RotationKeySet

type EvaluationKey = rlwe.EvaluationKey
