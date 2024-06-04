package vche

import "github.com/ldsec/lattigo/v2/ring"

type EncoderPlaintext interface {
	Encode(tags []Tag, p *ring.Poly)
	EncodeNew(tags []Tag) (p *ring.Poly)
	PRF(replicationIndex int, xs ...interface{}) uint64
}
