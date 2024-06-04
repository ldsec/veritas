package vche_2

import (
	"github.com/ldsec/lattigo/v2/ring"
	"veritas/vche/vche"
	"golang.org/x/crypto/blake2b"
)

type EvaluatorPlaintext interface {
	CopyNew(op *Poly) *Poly
	Add(op0, op1 *Poly, out *Poly)
	AddNew(op0, op1 *Poly) (out *Poly)
	AddNoMod(op0, op1 *Poly, out *Poly)
	AddNoModNew(op0, op1 *Poly) (out *Poly)
	Sub(op0, op1 *Poly, out *Poly)
	SubNew(op0, op1 *Poly) (out *Poly)
	SubNoMod(op0, op1 *Poly, out *Poly)
	SubNoModNew(op0, op1 *Poly) (out *Poly)
	Neg(op *Poly, out *Poly)
	NegNew(op *Poly) (out *Poly)
	Reduce(op *Poly, out *Poly)
	ReduceNew(op *Poly) (out *Poly)
	MulScalar(op *Poly, scalar uint64, out *Poly)
	MulScalarNew(op *Poly, scalar uint64) (out *Poly)
	Mul(op0, op1 *Poly, out *Poly)
	MulNew(op0, op1 *Poly) (out *Poly)
	Relinearize(op *Poly, out *Poly)
	RelinearizeNew(op *Poly) (out *Poly)
	SwitchKeys(op *Poly, switchKey *SwitchingKey, out *Poly)
	SwitchKeysNew(op *Poly, switchkey *SwitchingKey) (out *Poly)
	RotateColumns(op *Poly, k int, out *Poly)
	RotateColumnsNew(op *Poly, k int) (out *Poly)
	RotateRows(op *Poly, out *Poly)
	RotateRowsNew(op *Poly) (out *Poly)
	InnerSum(op *Poly, out *Poly)
}

type evaluatorPlaintext struct {
	vche.EvaluatorPlaintext
	params    Parameters
	useRequad bool
}

func NewEvaluatorPlaintext(parameters Parameters) EvaluatorPlaintext {
	return &evaluatorPlaintext{vche.NewEvaluatorPlaintext(parameters), parameters, false}
}

func NewEvaluatorPlaintextRequad(parameters Parameters) EvaluatorPlaintext {
	return &evaluatorPlaintext{vche.NewEvaluatorPlaintext(parameters), parameters, true}
}

func (e *evaluatorPlaintext) newPoly() *Poly {
	var shift *ring.Poly = nil
	if e.useRequad {
		shift = e.params.RingT().NewPoly()
	}
	return &Poly{
		Poly:  e.params.RingT().NewPoly(),
		Shift: shift,
	}
}

func (e *evaluatorPlaintext) CopyNew(op *Poly) *Poly {
	var shiftCopy *ring.Poly = nil
	if e.useRequad {
		shiftCopy = e.EvaluatorPlaintext.CopyNew(op.Shift)
	}
	return &Poly{
		Poly:  e.EvaluatorPlaintext.CopyNew(op.Poly),
		Shift: shiftCopy,
	}
}

func (e *evaluatorPlaintext) Add(op0, op1 *Poly, out *Poly) {
	e.EvaluatorPlaintext.Add(op0.Poly, op1.Poly, out.Poly)
	if e.useRequad {
		e.EvaluatorPlaintext.Add(op0.Shift, op1.Shift, out.Shift)
	}
}

func (e *evaluatorPlaintext) AddNew(op0, op1 *Poly) (out *Poly) {
	out = e.newPoly()
	e.Add(op0, op1, out)
	return out
}

func (e *evaluatorPlaintext) AddNoMod(op0, op1 *Poly, out *Poly) {
	e.EvaluatorPlaintext.AddNoMod(op0.Poly, op1.Poly, out.Poly)
	if e.useRequad {
		e.EvaluatorPlaintext.AddNoMod(op0.Shift, op1.Shift, out.Shift)
	}
}

func (e *evaluatorPlaintext) AddNoModNew(op0, op1 *Poly) (out *Poly) {
	out = e.newPoly()
	e.AddNoMod(op0, op1, out)
	return out
}

func (e *evaluatorPlaintext) Sub(op0, op1 *Poly, out *Poly) {
	e.EvaluatorPlaintext.Sub(op0.Poly, op1.Poly, out.Poly)
	if e.useRequad {
		e.EvaluatorPlaintext.Sub(op0.Shift, op1.Shift, out.Shift)
	}
}

func (e *evaluatorPlaintext) SubNew(op0, op1 *Poly) (out *Poly) {
	out = e.newPoly()
	e.Sub(op0, op1, out)
	return out
}

func (e *evaluatorPlaintext) SubNoMod(op0, op1 *Poly, out *Poly) {
	e.EvaluatorPlaintext.SubNoMod(op0.Poly, op1.Poly, out.Poly)
	if e.useRequad {
		e.EvaluatorPlaintext.SubNoMod(op0.Shift, op1.Shift, out.Shift)
	}
}

func (e *evaluatorPlaintext) SubNoModNew(op0, op1 *Poly) (out *Poly) {
	out = e.newPoly()
	e.SubNoMod(op0, op1, out)
	return out
}

func (e *evaluatorPlaintext) Neg(op *Poly, out *Poly) {
	e.EvaluatorPlaintext.Neg(op.Poly, out.Poly)
	if e.useRequad {
		e.EvaluatorPlaintext.Neg(op.Shift, out.Shift)
	}
}

func (e *evaluatorPlaintext) NegNew(op *Poly) (out *Poly) {
	out = e.newPoly()
	e.Neg(op, out)
	return out
}

func (e *evaluatorPlaintext) Reduce(op *Poly, out *Poly) {
	e.EvaluatorPlaintext.Reduce(op.Poly, out.Poly)
	if e.useRequad {
		e.EvaluatorPlaintext.Reduce(op.Shift, out.Shift)
	}
}

func (e *evaluatorPlaintext) ReduceNew(op *Poly) (out *Poly) {
	out = e.newPoly()
	e.Reduce(op, out)
	return out
}

func (e *evaluatorPlaintext) MulScalar(op *Poly, scalar uint64, out *Poly) {
	e.EvaluatorPlaintext.MulScalar(op.Poly, scalar, out.Poly)
	if e.useRequad {
		e.EvaluatorPlaintext.MulScalar(op.Shift, scalar, out.Shift)
	}
}

func (e *evaluatorPlaintext) MulScalarNew(op *Poly, scalar uint64) (out *Poly) {
	out = e.newPoly()
	e.MulScalar(op, scalar, out)
	return out
}

func (e *evaluatorPlaintext) Mul(op0, op1 *Poly, out *Poly) {
	e.EvaluatorPlaintext.Mul(op0.Poly, op1.Poly, out.Poly)
	if e.useRequad {
		R := e.params.RingT()
		outShift := R.NewPoly()
		R.MulCoeffs(op0.Shift, op1.Shift, outShift)
		R.MulCoeffsAndAdd(op0.Shift, op1.Poly, outShift)
		R.MulCoeffsAndAdd(op1.Shift, op0.Poly, outShift)

		out.Shift = outShift
	}
}

func (e *evaluatorPlaintext) MulNew(op0, op1 *Poly) (out *Poly) {
	out = e.newPoly()
	e.Mul(op0, op1, out)
	return out
}

func (e *evaluatorPlaintext) Relinearize(op *Poly, out *Poly) {
	e.EvaluatorPlaintext.Relinearize(op.Poly, out.Poly)
	if e.useRequad {
		e.EvaluatorPlaintext.Relinearize(op.Shift, out.Shift)
	}
}

func (e *evaluatorPlaintext) RelinearizeNew(op *Poly) (out *Poly) {
	out = e.newPoly()
	e.Relinearize(op, out)
	return out
}

func (e *evaluatorPlaintext) SwitchKeys(op *Poly, switchKey *SwitchingKey, out *Poly) {
	e.EvaluatorPlaintext.SwitchKeys(op.Poly, switchKey, out.Poly)
	if e.useRequad {
		e.EvaluatorPlaintext.SwitchKeys(op.Shift, switchKey, out.Shift)
	}
}

func (e *evaluatorPlaintext) SwitchKeysNew(op *Poly, switchkey *SwitchingKey) (out *Poly) {
	out = e.newPoly()
	e.SwitchKeys(op, switchkey, out)
	return out
}

func (e *evaluatorPlaintext) RotateColumns(op *Poly, k int, out *Poly) {
	e.EvaluatorPlaintext.RotateColumns(op.Poly, k, out.Poly)
	if e.useRequad {
		e.EvaluatorPlaintext.RotateColumns(op.Shift, k, out.Shift)
	}
}

func (e *evaluatorPlaintext) RotateColumnsNew(op *Poly, k int) (out *Poly) {
	out = e.newPoly()
	e.RotateColumns(op, k, out)
	return out
}

func (e *evaluatorPlaintext) RotateRows(op *Poly, out *Poly) {
	e.EvaluatorPlaintext.RotateRows(op.Poly, out.Poly)
	if e.useRequad {
		e.EvaluatorPlaintext.RotateRows(op.Shift, out.Shift)
	}
}

func (e *evaluatorPlaintext) RotateRowsNew(op *Poly) (out *Poly) {
	out = e.newPoly()
	e.RotateRows(op, out)
	return out
}

func (e *evaluatorPlaintext) InnerSum(op *Poly, out *Poly) {
	e.EvaluatorPlaintext.InnerSum(op.Poly, out.Poly)
	if e.useRequad {
		e.EvaluatorPlaintext.InnerSum(op.Shift, out.Shift)
	}
}

type EncoderPlaintext interface {
	Encode(tags []vche.Tag, p *Poly)
	EncodeNew(tags []vche.Tag) (p *Poly)
	PRF(replicationIndex int, xs ...interface{}) uint64
}

type encoderPlaintext struct {
	Params    Parameters
	K         []vche.PRFKey
	useRequad bool
	xofs1     []blake2b.XOF
}

func NewEncoderPlaintext(parameters Parameters, K []vche.PRFKey) EncoderPlaintext {
	xofs1 := make([]blake2b.XOF, len(K))
	for i := range xofs1 {
		xofs1[i] = vche.NewXOF(K[i].K1)
	}
	return &encoderPlaintext{parameters, K, false, xofs1}
}

func NewEncoderPlaintextRequad(parameters Parameters, K []vche.PRFKey) EncoderPlaintext {
	xofs1 := make([]blake2b.XOF, len(K))
	for i := range xofs1 {
		xofs1[i] = vche.NewXOF(K[i].K1)
	}
	return &encoderPlaintext{parameters, K, true, xofs1}
}

func (enc encoderPlaintext) Encode(tags []vche.Tag, p *Poly) {
	rs := make([]uint64, enc.Params.N())
	for i := range tags {
		for j := 0; j < enc.Params.NumReplications; j++ {
			idx := i*enc.Params.NumReplications + j
			rs[idx] = enc.PRF(j, tags[i])
		}

	}
	enc.Params.RingT().SetCoefficientsUint64(rs, p.Poly)
	if enc.useRequad {
		p.Shift = enc.Params.RingT().NewPoly()
	}
}

func (enc encoderPlaintext) EncodeNew(tags []vche.Tag) (p *Poly) {
	p = NewPoly(enc.Params)
	enc.Encode(tags, p)
	return p
}

func (enc encoderPlaintext) PRF(replicationIndex int, xs ...interface{}) uint64 {
	return vche.PRF(enc.xofs1[replicationIndex], enc.Params.T(), xs...)
}
