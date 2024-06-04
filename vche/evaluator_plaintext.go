package vche

import (
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/utils"
	"math/big"
)

type EvaluatorPlaintext interface {
	CopyNew(op *ring.Poly) *ring.Poly
	Add(op0, op1 *ring.Poly, out *ring.Poly)
	AddNew(op0, op1 *ring.Poly) (out *ring.Poly)
	AddNoMod(op0, op1 *ring.Poly, out *ring.Poly)
	AddNoModNew(op0, op1 *ring.Poly) (out *ring.Poly)
	Sub(op0, op1 *ring.Poly, out *ring.Poly)
	SubNew(op0, op1 *ring.Poly) (out *ring.Poly)
	SubNoMod(op0, op1 *ring.Poly, out *ring.Poly)
	SubNoModNew(op0, op1 *ring.Poly) (out *ring.Poly)
	Neg(op *ring.Poly, out *ring.Poly)
	NegNew(op *ring.Poly) (out *ring.Poly)
	Reduce(op *ring.Poly, out *ring.Poly)
	ReduceNew(op *ring.Poly) (out *ring.Poly)
	MulScalar(op *ring.Poly, scalar uint64, out *ring.Poly)
	MulScalarNew(op *ring.Poly, scalar uint64) (out *ring.Poly)
	Mul(op0, op1 *ring.Poly, out *ring.Poly)
	MulNew(op0, op1 *ring.Poly) (out *ring.Poly)
	Relinearize(op *ring.Poly, out *ring.Poly)
	RelinearizeNew(op *ring.Poly) (out *ring.Poly)
	SwitchKeys(op *ring.Poly, switchKey interface{}, out *ring.Poly)
	SwitchKeysNew(op *ring.Poly, switchkey interface{}) (out *ring.Poly)
	RotateColumns(op *ring.Poly, k int, out *ring.Poly)
	RotateColumnsNew(op *ring.Poly, k int) (out *ring.Poly)
	RotateRows(op *ring.Poly, out *ring.Poly)
	RotateRowsNew(op *ring.Poly) (out *ring.Poly)
	InnerSum(op *ring.Poly, out *ring.Poly)
}

type evaluatorPlaintext struct {
	params Parameters
}

func NewEvaluatorPlaintext(params Parameters) EvaluatorPlaintext {
	return &evaluatorPlaintext{params}
}

func (eval *evaluatorPlaintext) CopyNew(op *ring.Poly) *ring.Poly {
	return op.CopyNew()
}

func (eval *evaluatorPlaintext) Add(op0, op1 *ring.Poly, out *ring.Poly) {
	eval.params.RingT().Add(op0, op1, out)
}

func (eval *evaluatorPlaintext) AddNew(op0, op1 *ring.Poly) (out *ring.Poly) {
	out = eval.params.RingT().NewPoly()
	eval.Add(op0, op1, out)
	return out
}

func (eval *evaluatorPlaintext) AddNoMod(op0, op1 *ring.Poly, out *ring.Poly) {
	eval.params.RingT().AddNoMod(op0, op1, out)
}

func (eval *evaluatorPlaintext) AddNoModNew(op0, op1 *ring.Poly) (out *ring.Poly) {
	out = eval.params.RingT().NewPoly()
	eval.AddNoMod(op0, op1, out)
	return out
}

func (eval *evaluatorPlaintext) Sub(op0, op1 *ring.Poly, out *ring.Poly) {
	eval.params.RingT().Sub(op0, op1, out)
}

func (eval *evaluatorPlaintext) SubNew(op0, op1 *ring.Poly) (out *ring.Poly) {
	out = eval.params.RingT().NewPoly()
	eval.Sub(op0, op1, out)
	return out
}

func (eval *evaluatorPlaintext) SubNoMod(op0, op1 *ring.Poly, out *ring.Poly) {
	eval.params.RingT().SubNoMod(op0, op1, out)

}

func (eval *evaluatorPlaintext) SubNoModNew(op0, op1 *ring.Poly) (out *ring.Poly) {
	out = eval.params.RingT().NewPoly()
	eval.SubNoMod(op0, op1, out)
	return out
}

func (eval *evaluatorPlaintext) Neg(op *ring.Poly, out *ring.Poly) {
	eval.params.RingT().Neg(op, out)
	eval.params.RingT().Reduce(out, out)
}

func (eval *evaluatorPlaintext) NegNew(op *ring.Poly) (out *ring.Poly) {
	out = eval.params.RingT().NewPoly()
	eval.Neg(op, out)
	return out
}

func (eval *evaluatorPlaintext) Reduce(op *ring.Poly, out *ring.Poly) {
	eval.params.RingT().Reduce(op, out)
}

func (eval *evaluatorPlaintext) ReduceNew(op *ring.Poly) (out *ring.Poly) {
	out = eval.params.RingT().NewPoly()
	eval.Reduce(op, out)
	return out
}

func (eval *evaluatorPlaintext) MulScalar(op *ring.Poly, scalar uint64, out *ring.Poly) {
	eval.params.RingT().MulScalar(op, scalar, out)

}

func (eval *evaluatorPlaintext) MulScalarNew(op *ring.Poly, scalar uint64) (out *ring.Poly) {
	out = eval.params.RingT().NewPoly()
	eval.MulScalar(op, scalar, out)
	return out
}

func (eval *evaluatorPlaintext) Mul(op0, op1 *ring.Poly, out *ring.Poly) {
	eval.params.RingT().MulCoeffs(op0, op1, out)
}

func (eval *evaluatorPlaintext) MulNew(op0, op1 *ring.Poly) (out *ring.Poly) {
	out = eval.params.RingT().NewPoly()
	eval.Mul(op0, op1, out)
	return out
}

func (eval *evaluatorPlaintext) Relinearize(op *ring.Poly, out *ring.Poly) {
	out.Copy(op)
}

func (eval *evaluatorPlaintext) RelinearizeNew(op *ring.Poly) (out *ring.Poly) {
	out = eval.params.RingT().NewPoly()
	eval.Relinearize(op, out)
	return out
}

func (eval *evaluatorPlaintext) SwitchKeys(op *ring.Poly, _ interface{}, out *ring.Poly) {
	out.Copy(op)
}

func (eval *evaluatorPlaintext) SwitchKeysNew(op *ring.Poly, switchKey interface{}) (out *ring.Poly) {
	out = eval.params.RingT().NewPoly()
	eval.SwitchKeys(op, switchKey, out)
	return out
}

func (eval *evaluatorPlaintext) RotateColumns(op *ring.Poly, k int, out *ring.Poly) {
	out.Coeffs[0] = utils.RotateUint64Slots(op.Coeffs[0], k*eval.params.NumReplications)
}

func (eval *evaluatorPlaintext) RotateColumnsNew(op *ring.Poly, k int) (out *ring.Poly) {
	out = eval.params.RingT().NewPoly()
	eval.RotateColumns(op, k, out)
	return out
}

func (eval *evaluatorPlaintext) RotateRows(op *ring.Poly, out *ring.Poly) {
	out.Coeffs[0] = append(op.Coeffs[0][eval.params.RingT().N>>1:], op.Coeffs[0][:eval.params.RingT().N>>1]...)
}

func (eval *evaluatorPlaintext) RotateRowsNew(op *ring.Poly) (out *ring.Poly) {
	out = eval.params.RingT().NewPoly()
	eval.RotateRows(op, out)
	return out
}

func (eval *evaluatorPlaintext) InnerSum(op *ring.Poly, out *ring.Poly) {
	v := op.Coeffs[0]
	sums := make([]*big.Int, eval.params.NumReplications)
	for j := 0; j < eval.params.NumReplications; j++ {
		sums[j] = big.NewInt(0)
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
	eval.params.RingT().SetCoefficientsUint64(vOut, out)
}
