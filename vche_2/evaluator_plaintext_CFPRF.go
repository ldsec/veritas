package vche_2

import (
	"fmt"
	"github.com/ldsec/lattigo/v2/ring"
	"veritas/vche/vche"
	"golang.org/x/crypto/blake2b"
)

type VerifPlaintext struct {
	*vche.VerifPlaintext
	Shift *vche.VerifPlaintext
}

func NewVerifPlaintext(params Parameters) *VerifPlaintext {
	return &VerifPlaintext{vche.NewVerifPlaintext(params), vche.NewVerifPlaintext(params)}
}

func (v *VerifPlaintext) CopyNew() *VerifPlaintext {
	return &VerifPlaintext{
		v.VerifPlaintext.CopyNew(),
		v.Shift.CopyNew(),
	}
}

type EvaluatorPlaintextCFPRF interface {
	CopyNew(op *VerifPlaintext) *VerifPlaintext
	Add(op0, op1 *VerifPlaintext, out *VerifPlaintext)
	AddNew(op0, op1 *VerifPlaintext) (out *VerifPlaintext)
	AddNoMod(op0, op1 *VerifPlaintext, out *VerifPlaintext)
	AddNoModNew(op0, op1 *VerifPlaintext) (out *VerifPlaintext)
	Sub(op0, op1 *VerifPlaintext, out *VerifPlaintext)
	SubNew(op0, op1 *VerifPlaintext) (out *VerifPlaintext)
	SubNoMod(op0, op1 *VerifPlaintext, out *VerifPlaintext)
	SubNoModNew(op0, op1 *VerifPlaintext) (out *VerifPlaintext)
	Neg(op *VerifPlaintext, out *VerifPlaintext)
	NegNew(op *VerifPlaintext) (out *VerifPlaintext)
	Reduce(op *VerifPlaintext, out *VerifPlaintext)
	ReduceNew(op *VerifPlaintext) (out *VerifPlaintext)
	MulScalar(op *VerifPlaintext, scalar uint64, out *VerifPlaintext)
	MulScalarNew(op *VerifPlaintext, scalar uint64) (out *VerifPlaintext)
	Mul(op0, op1 *VerifPlaintext, out *VerifPlaintext)
	MulNew(op0, op1 *VerifPlaintext) (out *VerifPlaintext)
	Relinearize(op *VerifPlaintext, out *VerifPlaintext)
	RelinearizeNew(op *VerifPlaintext) (out *VerifPlaintext)
	SwitchKeys(op *VerifPlaintext, switchKey interface{}, out *VerifPlaintext)
	SwitchKeysNew(op *VerifPlaintext, switchKey interface{}) (out *VerifPlaintext)
	RotateColumns(op *VerifPlaintext, k int, out *VerifPlaintext)
	RotateColumnsNew(op *VerifPlaintext, k int) (out *VerifPlaintext)
	RotateRows(op *VerifPlaintext, out *VerifPlaintext)
	RotateRowsNew(op *VerifPlaintext) (out *VerifPlaintext)
	InnerSum(op *VerifPlaintext, out *VerifPlaintext)
	Eval(op *VerifPlaintext) *Poly
	ComputeMemo(op *VerifPlaintext)
}

type evaluatorPlaintextCFPRF struct {
	vche.EvaluatorPlaintextCFPRF
	ShiftEval vche.EvaluatorPlaintextCFPRF
	params    Parameters
	useRequad bool
}

func NewEvaluatorPlaintextCFPRF(parameters Parameters) EvaluatorPlaintextCFPRF {
	return &evaluatorPlaintextCFPRF{vche.NewEvaluatorPlaintextCFPRF(parameters), nil, parameters, false}
}

func NewEvaluatorPlaintextCFPRFRequad(parameters Parameters) EvaluatorPlaintextCFPRF {
	return &evaluatorPlaintextCFPRF{vche.NewEvaluatorPlaintextCFPRF(parameters), vche.NewEvaluatorPlaintextCFPRF(parameters), parameters, true}
}

func (e *evaluatorPlaintextCFPRF) newVerifPlaintext() *VerifPlaintext {
	var shift *vche.VerifPlaintext = nil
	if e.useRequad {
		shift = vche.NewVerifPlaintext(e.params)
	}
	return &VerifPlaintext{
		VerifPlaintext: vche.NewVerifPlaintext(e.params),
		Shift:          shift,
	}
}

func (e evaluatorPlaintextCFPRF) CopyNew(op *VerifPlaintext) *VerifPlaintext {
	var shift *vche.VerifPlaintext = nil
	if e.useRequad {
		shift = e.ShiftEval.CopyNew(op.Shift)
	}
	return &VerifPlaintext{
		e.EvaluatorPlaintextCFPRF.CopyNew(op.VerifPlaintext),
		shift,
	}
}

func (e evaluatorPlaintextCFPRF) Add(op0, op1 *VerifPlaintext, out *VerifPlaintext) {
	e.EvaluatorPlaintextCFPRF.Add(op0.VerifPlaintext, op1.VerifPlaintext, out.VerifPlaintext)
	if e.useRequad {
		e.ShiftEval.Add(op0.Shift, op1.Shift, out.Shift)
	}
}

func (e evaluatorPlaintextCFPRF) AddNew(op0, op1 *VerifPlaintext) (out *VerifPlaintext) {
	out = e.newVerifPlaintext()
	e.Add(op0, op1, out)
	return out
}

func (e evaluatorPlaintextCFPRF) AddNoMod(op0, op1 *VerifPlaintext, out *VerifPlaintext) {
	e.EvaluatorPlaintextCFPRF.AddNoMod(op0.VerifPlaintext, op1.VerifPlaintext, out.VerifPlaintext)
	if e.useRequad {
		e.ShiftEval.AddNoMod(op0.Shift, op1.Shift, out.Shift)
	}
}

func (e evaluatorPlaintextCFPRF) AddNoModNew(op0, op1 *VerifPlaintext) (out *VerifPlaintext) {
	out = e.newVerifPlaintext()
	e.AddNoMod(op0, op1, out)
	return out
}

func (e evaluatorPlaintextCFPRF) Sub(op0, op1 *VerifPlaintext, out *VerifPlaintext) {
	e.EvaluatorPlaintextCFPRF.Sub(op0.VerifPlaintext, op1.VerifPlaintext, out.VerifPlaintext)
	if e.useRequad {
		e.ShiftEval.Sub(op0.Shift, op1.Shift, out.Shift)
	}
}

func (e evaluatorPlaintextCFPRF) SubNew(op0, op1 *VerifPlaintext) (out *VerifPlaintext) {
	out = e.newVerifPlaintext()
	e.Sub(op0, op1, out)
	return out
}

func (e evaluatorPlaintextCFPRF) SubNoMod(op0, op1 *VerifPlaintext, out *VerifPlaintext) {
	e.EvaluatorPlaintextCFPRF.SubNoMod(op0.VerifPlaintext, op1.VerifPlaintext, out.VerifPlaintext)
	if e.useRequad {
		e.ShiftEval.SubNoMod(op0.Shift, op1.Shift, out.Shift)
	}
}

func (e evaluatorPlaintextCFPRF) SubNoModNew(op0, op1 *VerifPlaintext) (out *VerifPlaintext) {
	out = e.newVerifPlaintext()
	e.SubNoMod(op0, op1, out)
	return out
}

func (e evaluatorPlaintextCFPRF) Neg(op *VerifPlaintext, out *VerifPlaintext) {
	e.EvaluatorPlaintextCFPRF.Neg(op.VerifPlaintext, out.VerifPlaintext)
	if e.useRequad {
		e.ShiftEval.Neg(op.Shift, out.Shift)
	}
}

func (e evaluatorPlaintextCFPRF) NegNew(op *VerifPlaintext) (out *VerifPlaintext) {
	out = e.newVerifPlaintext()
	e.Neg(op, out)
	return out
}

func (e evaluatorPlaintextCFPRF) Reduce(op *VerifPlaintext, out *VerifPlaintext) {
	e.EvaluatorPlaintextCFPRF.Reduce(op.VerifPlaintext, out.VerifPlaintext)
	if e.useRequad {
		e.ShiftEval.Reduce(op.Shift, out.Shift)
	}
}

func (e evaluatorPlaintextCFPRF) ReduceNew(op *VerifPlaintext) (out *VerifPlaintext) {
	out = e.newVerifPlaintext()
	e.Reduce(op, out)
	return out
}

func (e evaluatorPlaintextCFPRF) MulScalar(op *VerifPlaintext, scalar uint64, out *VerifPlaintext) {
	e.EvaluatorPlaintextCFPRF.MulScalar(op.VerifPlaintext, scalar, out.VerifPlaintext)
	if e.useRequad {
		e.ShiftEval.MulScalar(op.Shift, scalar, out.Shift)
	}
}

func (e evaluatorPlaintextCFPRF) MulScalarNew(op *VerifPlaintext, scalar uint64) (out *VerifPlaintext) {
	out = e.newVerifPlaintext()
	e.MulScalar(op, scalar, out)
	return out
}

func (e evaluatorPlaintextCFPRF) Mul(op0, op1 *VerifPlaintext, out *VerifPlaintext) {
	e.EvaluatorPlaintextCFPRF.Mul(op0.VerifPlaintext, op1.VerifPlaintext, out.VerifPlaintext)
	if e.useRequad {
		outShift := e.ShiftEval.MulNew(op0.Shift, op1.Shift)
		tmp := e.ShiftEval.MulNew(op0.Shift, op1.VerifPlaintext)
		e.ShiftEval.Add(tmp, outShift, outShift)
		tmp = e.ShiftEval.MulNew(op0.VerifPlaintext, op1.Shift)
		e.ShiftEval.Add(tmp, outShift, outShift)

		out.Shift = outShift
	}
}

func (e evaluatorPlaintextCFPRF) MulNew(op0, op1 *VerifPlaintext) (out *VerifPlaintext) {
	out = e.newVerifPlaintext()
	e.Mul(op0, op1, out)
	return out
}

func (e evaluatorPlaintextCFPRF) Relinearize(op *VerifPlaintext, out *VerifPlaintext) {
	e.EvaluatorPlaintextCFPRF.Relinearize(op.VerifPlaintext, out.VerifPlaintext)
	if e.useRequad {
		e.ShiftEval.Relinearize(op.Shift, out.Shift)
	}
}

func (e evaluatorPlaintextCFPRF) RelinearizeNew(op *VerifPlaintext) (out *VerifPlaintext) {
	out = e.newVerifPlaintext()
	e.Relinearize(op, out)
	return out
}

func (e evaluatorPlaintextCFPRF) SwitchKeys(op *VerifPlaintext, switchKey interface{}, out *VerifPlaintext) {
	e.EvaluatorPlaintextCFPRF.SwitchKeys(op.VerifPlaintext, switchKey, out.VerifPlaintext)
	if e.useRequad {
		e.ShiftEval.SwitchKeys(op.Shift, switchKey, out.Shift)
	}
}

func (e evaluatorPlaintextCFPRF) SwitchKeysNew(op *VerifPlaintext, switchKey interface{}) (out *VerifPlaintext) {
	out = e.newVerifPlaintext()
	e.SwitchKeys(op, switchKey, out)
	return out
}

func (e evaluatorPlaintextCFPRF) RotateColumns(op *VerifPlaintext, k int, out *VerifPlaintext) {
	e.EvaluatorPlaintextCFPRF.RotateColumns(op.VerifPlaintext, k, out.VerifPlaintext)
	if e.useRequad {
		e.ShiftEval.RotateColumns(op.Shift, k, out.Shift)
	}
}

func (e evaluatorPlaintextCFPRF) RotateColumnsNew(op *VerifPlaintext, k int) (out *VerifPlaintext) {
	out = e.newVerifPlaintext()
	e.RotateColumns(op, k, out)
	return out
}

func (e evaluatorPlaintextCFPRF) RotateRows(op *VerifPlaintext, out *VerifPlaintext) {
	e.EvaluatorPlaintextCFPRF.RotateRows(op.VerifPlaintext, out.VerifPlaintext)
	if e.useRequad {
		e.ShiftEval.RotateRows(op.Shift, out.Shift)
	}
}

func (e evaluatorPlaintextCFPRF) RotateRowsNew(op *VerifPlaintext) (out *VerifPlaintext) {
	out = e.newVerifPlaintext()
	e.RotateRows(op, out)
	return out
}

func (e evaluatorPlaintextCFPRF) InnerSum(op *VerifPlaintext, out *VerifPlaintext) {
	e.EvaluatorPlaintextCFPRF.InnerSum(op.VerifPlaintext, out.VerifPlaintext)
	if e.useRequad {
		e.ShiftEval.InnerSum(op.Shift, out.Shift)
	}
}

func (e *evaluatorPlaintextCFPRF) ComputeMemo(op *VerifPlaintext) {
	e.EvaluatorPlaintextCFPRF.ComputeMemo(op.VerifPlaintext)
	if e.useRequad {
		e.ShiftEval.ComputeMemo(op.Shift)
	}
}

func (e *evaluatorPlaintextCFPRF) Eval(op *VerifPlaintext) *Poly {
	var shift *ring.Poly = nil
	if e.useRequad {
		shift = e.ShiftEval.Eval(op.Shift)
	}
	return &Poly{
		e.EvaluatorPlaintextCFPRF.Eval(op.VerifPlaintext),
		shift,
	}
}

type EncoderPlaintextCFPRF interface {
	Encode(tags []vche.Tag, p *VerifPlaintext)
	EncodeNew(tags []vche.Tag) (p *VerifPlaintext)
	CFPRF(replicationIndex int, xs ...interface{}) (uint64, uint64, uint64, uint64)
}

type encoderPlaintextCFPRF struct {
	params       Parameters
	K            []vche.PRFKey
	u            *ring.Poly
	v            *ring.Poly
	useRequad    bool
	xofs1, xofs2 []blake2b.XOF
}

func NewEncoderPlaintextCFPRF(parameters Parameters, K []vche.PRFKey) EncoderPlaintextCFPRF {
	xofs1, xofs2 := make([]blake2b.XOF, len(K)), make([]blake2b.XOF, len(K))
	for i := range xofs1 {
		xofs1[i] = vche.NewXOF(K[i].K1)
		xofs2[i] = vche.NewXOF(K[i].K2)
	}
	return &encoderPlaintextCFPRF{parameters, K, nil, nil, false, xofs1, xofs2}
}

func NewEncoderPlaintextCFPRFRequad(parameters Parameters, K []vche.PRFKey) EncoderPlaintextCFPRF {
	xofs1, xofs2 := make([]blake2b.XOF, len(K)), make([]blake2b.XOF, len(K))
	for i := range xofs1 {
		xofs1[i] = vche.NewXOF(K[i].K1)
		xofs2[i] = vche.NewXOF(K[i].K2)
	}
	return &encoderPlaintextCFPRF{parameters, K, nil, nil, true, xofs1, xofs2}
}

func (enc encoderPlaintextCFPRF) Encode(tags []vche.Tag, p *VerifPlaintext) {
	a := make([]uint64, enc.params.NumDistinctPRFKeys)
	b := make([]uint64, enc.params.NumDistinctPRFKeys)

	if enc.u == nil { // Memoize
		enc.u = enc.params.RingT().NewPoly()
		enc.v = enc.params.RingT().NewPoly()

		for i := range tags {
			for j := 0; j < enc.params.NumReplications; j++ {
				aI, bI, uI, vI := enc.CFPRF(j, tags[i])
				if i == 0 {
					a[j] = aI
					b[j] = bI
				} else {
					if a[j] != aI || b[j] != bI {
						panic(fmt.Errorf("mismatched PRF outputs at position %d, the dataset tag should be the same for the entire plaintext", i))
					}
				}
				idx := i*enc.params.NumDistinctPRFKeys + j
				enc.u.Coeffs[0][idx] = uI
				enc.v.Coeffs[0][idx] = vI
			}
		}
	} else { // Read from memo
		// We assume the dataset tags are the same across the entire array (a check would be too expensive)
		for j := 0; j < enc.params.NumReplications; j++ {
			aI, bI, _, _ := enc.CFPRF(j, tags[0])
			a[j] = aI
			b[j] = bI
		}
	}

	bps := make([]vche.BivariatePoly, enc.params.NumDistinctPRFKeys)
	for i := 0; i < enc.params.NumReplications; i++ {
		bps[i] = vche.NewBivariatePoly(1, enc.params.T())
		bps[i].SetCoeff(1, 0, a[i])
		bps[i].SetCoeff(0, 1, b[i])
	}

	p.VerifPlaintext.U = enc.u
	p.VerifPlaintext.V = enc.v
	p.VerifPlaintext.Poly = map[vche.RotInfo][]vche.BivariatePoly{vche.NoRot: bps}
	if enc.useRequad {
		p.Shift.U = enc.u
		p.Shift.V = enc.v
		p.Shift.Poly = map[vche.RotInfo][]vche.BivariatePoly{vche.NoRot: {vche.NewBivariatePoly(1, enc.params.T())}}
	}
}

func (enc encoderPlaintextCFPRF) EncodeNew(tags []vche.Tag) (p *VerifPlaintext) {
	p = NewVerifPlaintext(enc.params)
	enc.Encode(tags, p)
	return p
}

func (enc encoderPlaintextCFPRF) CFPRF(replicationIndex int, xs ...interface{}) (uint64, uint64, uint64, uint64) {
	return vche.CFPRF(enc.xofs1[replicationIndex], enc.xofs2[replicationIndex], enc.params.T(), xs...)
}

func (enc encoderPlaintextCFPRF) U() *ring.Poly {
	return enc.u
}

func (enc encoderPlaintextCFPRF) V() *ring.Poly {
	return enc.v
}
