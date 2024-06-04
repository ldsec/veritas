package vche_1

import (
	"encoding/binary"
	"github.com/ldsec/lattigo/v2/ring"
	"veritas/vche/vche"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
	"hash"
	"math/big"
)

type EvaluatorPlaintext interface {
	CopyNew(op *TaggedPoly) *TaggedPoly
	Add(op0, op1 *TaggedPoly, out *TaggedPoly)
	AddNew(op0, op1 *TaggedPoly) (out *TaggedPoly)
	AddNoMod(op0, op1 *TaggedPoly, out *TaggedPoly)
	AddNoModNew(op0, op1 *TaggedPoly) (out *TaggedPoly)
	Sub(op0, op1 *TaggedPoly, out *TaggedPoly)
	SubNew(op0, op1 *TaggedPoly) (out *TaggedPoly)
	SubNoMod(op0, op1 *TaggedPoly, out *TaggedPoly)
	SubNoModNew(op0, op1 *TaggedPoly) (out *TaggedPoly)
	Neg(op *TaggedPoly, out *TaggedPoly)
	NegNew(op *TaggedPoly) (out *TaggedPoly)
	Reduce(op *TaggedPoly, out *TaggedPoly)
	ReduceNew(op *TaggedPoly) (out *TaggedPoly)
	MulScalar(op *TaggedPoly, scalar uint64, out *TaggedPoly)
	MulScalarNew(op *TaggedPoly, scalar uint64) (out *TaggedPoly)
	Mul(op0, op1 *TaggedPoly, out *TaggedPoly)
	MulNew(op0, op1 *TaggedPoly) (out *TaggedPoly)
	Relinearize(op *TaggedPoly, out *TaggedPoly)
	RelinearizeNew(op *TaggedPoly) (out *TaggedPoly)
	SwitchKeys(op *TaggedPoly, switchKey *SwitchingKey, out *TaggedPoly)
	SwitchKeysNew(op *TaggedPoly, switchkey *SwitchingKey) (out *TaggedPoly)
	RotateColumns(op *TaggedPoly, k int, out *TaggedPoly)
	RotateColumnsNew(op *TaggedPoly, k int) (out *TaggedPoly)
	RotateRows(op *TaggedPoly, out *TaggedPoly)
	RotateRowsNew(op *TaggedPoly) (out *TaggedPoly)
	InnerSum(op *TaggedPoly, out *TaggedPoly)
}

type evaluatorPlaintext struct {
	vche.EvaluatorPlaintext
	params Parameters
	H      hash.Hash
}

func NewEvaluatorPlaintext(parameters Parameters, H hash.Hash) EvaluatorPlaintext {
	return &evaluatorPlaintext{vche.NewEvaluatorPlaintext(parameters), parameters, H}
}

func (eval *evaluatorPlaintext) hash(ins ...[][]byte) [][]byte {
	NTags := len(ins[0])

	if len(ins) > 1 {
		for _, in := range ins {
			require.Equal(nil, NTags, len(in))
		}
	}

	eval.H.Reset()
	hashed := make([][]byte, NTags)
	for i := 0; i < NTags; i++ {
		for _, in := range ins {
			eval.H.Write(in[i])
		}

		hashed[i] = eval.H.Sum(make([]byte, 0))
	}
	return hashed
}

func (eval *evaluatorPlaintext) liftBinOp(op func(*ring.Poly, *ring.Poly, *ring.Poly)) (verifOp func(*TaggedPoly, *TaggedPoly, *TaggedPoly)) {
	return func(op0, op1, out *TaggedPoly) {
		op(op0.Poly, op1.Poly, out.Poly)
		out.tags = eval.hash(op0.tags, op1.tags)
	}
}

func (eval *evaluatorPlaintext) CopyNew(op *TaggedPoly) *TaggedPoly {
	return &TaggedPoly{op.Poly.CopyNew(), op.tags}
}

func (eval *evaluatorPlaintext) Add(op0, op1 *TaggedPoly, out *TaggedPoly) {
	eval.liftBinOp(eval.EvaluatorPlaintext.Add)(op0, op1, out)
}

func (eval *evaluatorPlaintext) AddNew(op0, op1 *TaggedPoly) (out *TaggedPoly) {
	out = NewTaggedPoly(eval.params)
	eval.Add(op0, op1, out)
	return out
}

func (eval *evaluatorPlaintext) AddNoMod(op0, op1 *TaggedPoly, out *TaggedPoly) {
	eval.liftBinOp(eval.EvaluatorPlaintext.AddNoMod)(op0, op1, out)
}

func (eval *evaluatorPlaintext) AddNoModNew(op0, op1 *TaggedPoly) (out *TaggedPoly) {
	out = NewTaggedPoly(eval.params)
	eval.AddNoMod(op0, op1, out)
	return out
}

func (eval *evaluatorPlaintext) Sub(op0, op1 *TaggedPoly, out *TaggedPoly) {
	eval.liftBinOp(eval.EvaluatorPlaintext.Sub)(op0, op1, out)
}

func (eval *evaluatorPlaintext) SubNew(op0, op1 *TaggedPoly) (out *TaggedPoly) {
	out = NewTaggedPoly(eval.params)
	eval.Sub(op0, op1, out)
	return out
}

func (eval *evaluatorPlaintext) SubNoMod(op0, op1 *TaggedPoly, out *TaggedPoly) {
	eval.liftBinOp(eval.EvaluatorPlaintext.SubNoMod)(op0, op1, out)
}

func (eval *evaluatorPlaintext) SubNoModNew(op0, op1 *TaggedPoly) (out *TaggedPoly) {
	out = NewTaggedPoly(eval.params)
	eval.SubNoMod(op0, op1, out)
	return out
}

func (eval *evaluatorPlaintext) Neg(op *TaggedPoly, out *TaggedPoly) {
	eval.EvaluatorPlaintext.Neg(op.Poly, out.Poly)
	out.tags = eval.hash(op.tags)
}

func (eval *evaluatorPlaintext) NegNew(op *TaggedPoly) (out *TaggedPoly) {
	out = NewTaggedPoly(eval.params)
	eval.Neg(op, out)
	return out
}

func (eval *evaluatorPlaintext) Reduce(op *TaggedPoly, out *TaggedPoly) {
	eval.EvaluatorPlaintext.Reduce(op.Poly, out.Poly)
	out.tags = eval.hash(op.tags)
}

func (eval *evaluatorPlaintext) ReduceNew(op *TaggedPoly) (out *TaggedPoly) {
	out = NewTaggedPoly(eval.params)
	eval.Reduce(op, out)
	return out
}

func (eval *evaluatorPlaintext) MulScalar(op *TaggedPoly, scalar uint64, out *TaggedPoly) {
	eval.EvaluatorPlaintext.MulScalar(op.Poly, scalar, out.Poly)

	scalarBytes := make([][]byte, len(op.tags))
	for i := range scalarBytes {
		scalarBytes[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(scalarBytes[i], scalar)

	}
	out.tags = eval.hash(op.tags, scalarBytes)
}

func (eval *evaluatorPlaintext) MulScalarNew(op *TaggedPoly, scalar uint64) (out *TaggedPoly) {
	out = NewTaggedPoly(eval.params)
	eval.MulScalar(op, scalar, out)
	return out
}

func (eval *evaluatorPlaintext) Mul(op0, op1 *TaggedPoly, out *TaggedPoly) {
	eval.EvaluatorPlaintext.Mul(op0.Poly, op1.Poly, out.Poly)
	out.tags = eval.hash(op0.tags, op1.tags)
}

func (eval *evaluatorPlaintext) MulNew(op0, op1 *TaggedPoly) (out *TaggedPoly) {
	out = NewTaggedPoly(eval.params)
	eval.Mul(op0, op1, out)
	return out
}

func (eval *evaluatorPlaintext) Relinearize(op *TaggedPoly, out *TaggedPoly) {
	eval.EvaluatorPlaintext.Relinearize(op.Poly, out.Poly)
	out.tags = eval.hash(op.tags)
}

func (eval *evaluatorPlaintext) RelinearizeNew(op *TaggedPoly) (out *TaggedPoly) {
	out = NewTaggedPoly(eval.params)
	eval.Relinearize(op, out)
	return out
}

func (eval *evaluatorPlaintext) SwitchKeys(op *TaggedPoly, switchKey *SwitchingKey, out *TaggedPoly) {
	eval.EvaluatorPlaintext.SwitchKeys(op.Poly, switchKey.SwitchingKey, out.Poly)
	out.tags = eval.hash(op.tags)
}

func (eval *evaluatorPlaintext) SwitchKeysNew(op *TaggedPoly, switchKey *SwitchingKey) (out *TaggedPoly) {
	out = NewTaggedPoly(eval.params)
	eval.SwitchKeys(op, switchKey, out)
	return out
}

func (eval *evaluatorPlaintext) RotateColumns(op *TaggedPoly, k int, out *TaggedPoly) {
	eval.EvaluatorPlaintext.RotateColumns(op.Poly, k, out.Poly)

	kBytes := make([][]byte, len(op.tags))
	for i := range kBytes {
		kBytes[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(kBytes[i], uint64(k))

	}
	out.tags = eval.hash(op.tags, kBytes)
}
func (eval *evaluatorPlaintext) RotateColumnsNew(op *TaggedPoly, k int) (out *TaggedPoly) {
	out = NewTaggedPoly(eval.params)
	eval.RotateColumns(op, k, out)
	return out
}

func (eval *evaluatorPlaintext) RotateRows(op *TaggedPoly, out *TaggedPoly) {
	eval.EvaluatorPlaintext.RotateRows(op.Poly, out.Poly)
	out.tags = eval.hash(op.tags)
}

func (eval *evaluatorPlaintext) RotateRowsNew(op *TaggedPoly) (out *TaggedPoly) {
	out = NewTaggedPoly(eval.params)
	eval.RotateRows(op, out)
	return out
}

func (eval *evaluatorPlaintext) InnerSum(op *TaggedPoly, out *TaggedPoly) {
	v := op.Poly.Coeffs[0]
	sums := make([]*big.Int, eval.params.NumReplications)
	for i := range sums {
		sums[i] = big.NewInt(0)
	}
	bigT := big.NewInt(0).SetUint64(eval.params.T())
	for i := 0; i < eval.params.NSlots; i++ {
		for j := 0; j < eval.params.NumReplications; j++ {
			sums[j].Add(sums[j], big.NewInt(0).SetUint64(v[i*eval.params.NumReplications+j]))
			sums[j].Mod(sums[j], bigT)
		}
	}

	vOut := make([]uint64, len(v))
	for i := 0; i < eval.params.NSlots; i++ {
		for j := 0; j < eval.params.NumReplications; j++ {
			vOut[i*eval.params.NumReplications+j] = sums[j].Uint64()
		}
	}
	eval.params.RingT().SetCoefficientsUint64(vOut, out.Poly)

	out.tags = eval.hash(op.tags)
}

type EncoderPlaintext interface {
	Encode(tags []vche.Tag, p *TaggedPoly)
	EncodeNew(tags []vche.Tag) (p *TaggedPoly)
	PRF(xs ...interface{}) uint64
}

type encoderPlaintext struct {
	params Parameters
	K      vche.PRFKey
	xof1   blake2b.XOF
}

func NewEncoderPlaintext(parameters Parameters, K vche.PRFKey) EncoderPlaintext {
	return encoderPlaintext{parameters, K, vche.NewXOF(K.K1)}
}

func (enc encoderPlaintext) Encode(tags []vche.Tag, p *TaggedPoly) {
	N := enc.params.N()
	lambda := enc.params.NumReplications
	NSlots := enc.params.NSlots

	// Set plaintext slots to duplicated messages or dummy values
	coeffs := make([]uint64, N)
	for i := 0; i < NSlots; i++ {
		for j := 0; j < lambda; j++ {
			idx := i*lambda + j
			coeffs[idx] = enc.PRF(tags[i], uint64(j))
		}
	}
	enc.params.RingT().SetCoefficientsUint64(coeffs, p.Poly)

	// Set randomness used from the tags for each message
	vs := make([][]byte, len(tags))
	for i, tI := range tags {
		vs[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(vs[i], enc.PRF(tI))
	}
	p.tags = vs
}

func (enc encoderPlaintext) EncodeNew(tags []vche.Tag) (p *TaggedPoly) {
	p = NewTaggedPoly(enc.params)
	enc.Encode(tags, p)
	return p
}

func (enc encoderPlaintext) PRF(xs ...interface{}) uint64 {
	return vche.PRF(enc.xof1, enc.params.T(), xs...)
}
