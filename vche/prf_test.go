package vche

import (
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPRF(t *testing.T) {
	bfvParamsLiteral := bfv.PN12QP109
	bfvParams, _ := bfv.NewParametersFromLiteral(bfvParamsLiteral)

	N := bfvParams.N()
	T := bfvParams.T()
	K := NewPRFKey(8)
	xof := NewXOF(K.K1)

	tags := GetRandomTags(N)

	ys1 := make([]uint64, N)
	for i := range ys1 {
		ys1[i] = PRF(xof, T, tags[i])
	}

	ys2 := make([]uint64, N)
	for i := range ys2 {
		ys2[i] = PRF(xof, T, tags[i])
	}
	require.Equal(t, ys1, ys2)

	ys3 := make([]uint64, N)
	for i := range ys3 {
		tagNew := Tag{tags[i][0], tags[i][1][1:]}
		ys3[i] = PRF(xof, T, tagNew)
	}
	require.NotEqual(t, ys1, ys3)
}
