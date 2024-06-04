package vche

import (
	"fmt"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/utils"
	"log"
)

var DEBUG = false

type VerifPlaintext struct {
	U    *ring.Poly
	V    *ring.Poly
	Poly map[RotInfo][]BivariatePoly
}

func (vp *VerifPlaintext) Len() int {
	return len(vp.Poly)
}

func (vp *VerifPlaintext) CopyNew() *VerifPlaintext {
	cp := &VerifPlaintext{nil, nil, nil}
	CopyUV(vp, cp)
	CopyPoly(vp, cp)
	return cp
}

type RotInfo struct {
	numRots     int
	rotatedRows bool
}

var NoRot = RotInfo{0, false}

func NewVerifPlaintext(params Parameters) *VerifPlaintext {
	bps := make([]BivariatePoly, params.NumDistinctPRFKeys)
	for i := 0; i < params.NumDistinctPRFKeys; i++ {
		bps[i] = NewBivariatePoly(1, params.T())
	}
	return &VerifPlaintext{
		params.RingT().NewPoly(),
		params.RingT().NewPoly(),
		map[RotInfo][]BivariatePoly{NoRot: bps},
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
	Eval(op *VerifPlaintext) *ring.Poly
	ComputeMemo(op *VerifPlaintext)
}

type evaluatorPlaintextCFPRF struct {
	params  Parameters
	memoPow map[RotInfo][][]*ring.Poly
}

func NewEvaluatorPlaintextCFPRF(params Parameters) EvaluatorPlaintextCFPRF {
	return &evaluatorPlaintextCFPRF{params, nil}
}

func copyMapBivariatePoly(m map[RotInfo][]BivariatePoly) map[RotInfo][]BivariatePoly {
	res := map[RotInfo][]BivariatePoly{}
	for k, v := range m {
		res[k] = v
	}
	return res
}

func CopyUV(op, out *VerifPlaintext) { // Don't copy read-only polynomials, assign them instead
	out.U = op.U
	out.V = op.V
}

func CopyPoly(op, out *VerifPlaintext) {
	out.Poly = copyMapBivariatePoly(op.Poly)
}

func copyUV2(op0, op1, out *VerifPlaintext) { // Don't copy read-only polynomials, assign them instead
	if DEBUG {
		if !op0.U.Equals(op1.U) {
			panic("PRF vectors u are different in source operands, make sure to use the same index tags for all inputs")
		}
		if !op0.V.Equals(op1.V) {
			panic("PRF vectors v are different in source operands, make sure to use the same index tags for all inputs")
		}
	}
	out.U = op0.U
	out.V = op0.V
}

func (eval *evaluatorPlaintextCFPRF) CopyNew(op *VerifPlaintext) *VerifPlaintext {
	cp := NewVerifPlaintext(eval.params)
	CopyUV(op, cp)
	CopyPoly(op, cp)
	return cp
}

func (eval *evaluatorPlaintextCFPRF) Add(op0, op1 *VerifPlaintext, out *VerifPlaintext) {
	copyUV2(op0, op1, out)

	outPolys := map[RotInfo][]BivariatePoly{}
	for i := range op0.Poly {
		if _, ok := op1.Poly[i]; !ok {
			outPolys[i] = op0.Poly[i]
		} else {
			outPolys[i] = BivariatePolyAdd(op0.Poly[i], op1.Poly[i])
		}
	}
	for i := range op1.Poly {
		if _, ok := op0.Poly[i]; !ok {
			outPolys[i] = op1.Poly[i]
		}

	}
	out.Poly = outPolys
}

func (eval *evaluatorPlaintextCFPRF) AddNew(op0, op1 *VerifPlaintext) (out *VerifPlaintext) {
	out = NewVerifPlaintext(eval.params)
	eval.Add(op0, op1, out)
	return out
}

func (eval *evaluatorPlaintextCFPRF) AddNoMod(op0, op1 *VerifPlaintext, out *VerifPlaintext) {
	copyUV2(op0, op1, out)

	outPolys := map[RotInfo][]BivariatePoly{}
	for i := range op0.Poly {
		if _, ok := op1.Poly[i]; !ok {
			outPolys[i] = op0.Poly[i]
		} else {
			outPolys[i] = BivariatePolyAddNoMod(op0.Poly[i], op1.Poly[i])
		}
	}
	for i := range op1.Poly {
		if _, ok := op0.Poly[i]; !ok {
			outPolys[i] = op1.Poly[i]
		}

	}
	out.Poly = outPolys
}

func (eval *evaluatorPlaintextCFPRF) AddNoModNew(op0, op1 *VerifPlaintext) (out *VerifPlaintext) {
	out = NewVerifPlaintext(eval.params)
	eval.AddNoMod(op0, op1, out)
	return out
}

func (eval *evaluatorPlaintextCFPRF) Sub(op0, op1 *VerifPlaintext, out *VerifPlaintext) {
	copyUV2(op0, op1, out)

	outPolys := map[RotInfo][]BivariatePoly{}
	for i := range op0.Poly {
		if _, ok := op1.Poly[i]; !ok {
			outPolys[i] = op0.Poly[i]
		} else {
			outPolys[i] = BivariatePolySub(op0.Poly[i], op1.Poly[i])
		}
	}
	for i := range op1.Poly {
		if _, ok := op0.Poly[i]; !ok {
			outPolys[i] = BivariatePolyNeg(op1.Poly[i])
		}

	}
	out.Poly = outPolys
}

func (eval *evaluatorPlaintextCFPRF) SubNew(op0, op1 *VerifPlaintext) (out *VerifPlaintext) {
	out = NewVerifPlaintext(eval.params)
	eval.Sub(op0, op1, out)
	return out
}

func (eval *evaluatorPlaintextCFPRF) SubNoMod(op0, op1 *VerifPlaintext, out *VerifPlaintext) {
	copyUV2(op0, op1, out)

	outPolys := map[RotInfo][]BivariatePoly{}
	for i := range op0.Poly {
		if _, ok := op1.Poly[i]; !ok {
			outPolys[i] = op0.Poly[i]
		} else {
			outPolys[i] = BivariatePolySubNoMod(op0.Poly[i], op1.Poly[i])
		}
	}
	for i := range op1.Poly {
		if _, ok := op0.Poly[i]; !ok {
			outPolys[i] = BivariatePolyNeg(op1.Poly[i])
		}

	}
	out.Poly = outPolys
}

func (eval *evaluatorPlaintextCFPRF) SubNoModNew(op0, op1 *VerifPlaintext) (out *VerifPlaintext) {
	out = NewVerifPlaintext(eval.params)
	eval.SubNoMod(op0, op1, out)
	return out
}

func (eval *evaluatorPlaintextCFPRF) Neg(op *VerifPlaintext, out *VerifPlaintext) {
	CopyUV(op, out)

	outPolys := map[RotInfo][]BivariatePoly{}
	for i := range op.Poly {
		outPolys[i] = BivariatePolyNeg(op.Poly[i])
	}
	out.Poly = outPolys
}

func (eval *evaluatorPlaintextCFPRF) NegNew(op *VerifPlaintext) (out *VerifPlaintext) {
	out = NewVerifPlaintext(eval.params)
	eval.Neg(op, out)
	return out
}

func (eval *evaluatorPlaintextCFPRF) Reduce(op *VerifPlaintext, out *VerifPlaintext) {
	CopyUV(op, out)
	CopyPoly(op, out)
}

func (eval *evaluatorPlaintextCFPRF) ReduceNew(op *VerifPlaintext) (out *VerifPlaintext) {
	out = NewVerifPlaintext(eval.params)
	eval.Reduce(op, out)
	return out
}

func (eval *evaluatorPlaintextCFPRF) MulScalar(op *VerifPlaintext, scalar uint64, out *VerifPlaintext) {
	CopyUV(op, out)

	outPolys := map[RotInfo][]BivariatePoly{}
	for i := range op.Poly {
		outPolys[i] = BivariatePolyMulScalar(op.Poly[i], scalar)
	}
	out.Poly = outPolys
}

func (eval *evaluatorPlaintextCFPRF) MulScalarNew(op *VerifPlaintext, scalar uint64) (out *VerifPlaintext) {
	out = NewVerifPlaintext(eval.params)
	eval.MulScalar(op, scalar, out)
	return out
}

func (eval *evaluatorPlaintextCFPRF) Mul(op0, op1 *VerifPlaintext, out *VerifPlaintext) {
	copyUV2(op0, op1, out)

	outPolys := map[RotInfo][]BivariatePoly{}
	for i := range op0.Poly {
		if _, ok := op1.Poly[i]; ok {
			outPolys[i] = BivariatePolyMul(op0.Poly[i], op1.Poly[i])
		} else {
			log.Fatalln("unsupported operation: this implementation cannot multiply two VerifPlaintext aggregating different rotations")
		}
	}
	for i := range op1.Poly {
		if _, ok := op0.Poly[i]; !ok {
			log.Fatalln("unsupported operation: this implementation cannot multiply two VerifPlaintext aggregating different rotations")
		}
	}
	out.Poly = outPolys
}

func (eval *evaluatorPlaintextCFPRF) MulNew(op0, op1 *VerifPlaintext) (out *VerifPlaintext) {
	out = NewVerifPlaintext(eval.params)
	eval.Mul(op0, op1, out)
	return out
}

func (eval *evaluatorPlaintextCFPRF) Relinearize(op *VerifPlaintext, out *VerifPlaintext) {
	CopyUV(op, out)
	CopyPoly(op, out)
}

func (eval *evaluatorPlaintextCFPRF) RelinearizeNew(op *VerifPlaintext) (out *VerifPlaintext) {
	out = NewVerifPlaintext(eval.params)
	eval.Relinearize(op, out)
	return out
}

func (eval *evaluatorPlaintextCFPRF) SwitchKeys(op *VerifPlaintext, _ interface{}, out *VerifPlaintext) {
	CopyUV(op, out)
	CopyPoly(op, out)
}

func (eval *evaluatorPlaintextCFPRF) SwitchKeysNew(op *VerifPlaintext, switchKey interface{}) (out *VerifPlaintext) {
	out = NewVerifPlaintext(eval.params)
	eval.SwitchKeys(op, switchKey, out)
	return out
}

func (eval *evaluatorPlaintextCFPRF) RotateColumns(op *VerifPlaintext, k int, out *VerifPlaintext) {
	CopyUV(op, out)
	k = (k * eval.params.NumReplications) % eval.params.N()

	outPolys := map[RotInfo][]BivariatePoly{}
	for i := range op.Poly {
		newI := RotInfo{(i.numRots + k) % eval.params.RingT().N, i.rotatedRows}
		outPolys[newI] = op.Poly[i]
	}

	out.Poly = outPolys
}

func (eval *evaluatorPlaintextCFPRF) RotateColumnsNew(op *VerifPlaintext, k int) (out *VerifPlaintext) {
	out = NewVerifPlaintext(eval.params)
	eval.RotateColumns(op, k, out)
	return out
}

func (eval *evaluatorPlaintextCFPRF) RotateRows(op *VerifPlaintext, out *VerifPlaintext) {
	CopyUV(op, out)
	outPolys := map[RotInfo][]BivariatePoly{}
	for i := range op.Poly {
		newI := RotInfo{i.numRots, !i.rotatedRows}
		outPolys[newI] = op.Poly[i]
	}

	out.Poly = outPolys
}

func (eval *evaluatorPlaintextCFPRF) RotateRowsNew(op *VerifPlaintext) (out *VerifPlaintext) {
	out = NewVerifPlaintext(eval.params)
	eval.RotateRows(op, out)
	return out
}

func (eval *evaluatorPlaintextCFPRF) InnerSum(op *VerifPlaintext, out *VerifPlaintext) {
	res := NewVerifPlaintext(eval.params)
	CopyUV(op, res)
	CopyPoly(op, res)

	tmp := NewVerifPlaintext(eval.params)

	for i := 1; i < eval.params.NSlots>>1; i <<= 1 {
		eval.RotateColumns(res, i, tmp)
		eval.Add(tmp, res, res)
	}

	eval.RotateRows(res, tmp)
	eval.Add(res, tmp, res)

	out.Poly = res.Poly
}

func (eval *evaluatorPlaintextCFPRF) applyRot(x *ring.Poly, rot RotInfo) *ring.Poly {
	res := x.CopyNew()
	res.SetCoefficients([][]uint64{utils.RotateUint64Slots(res.Coeffs[0], rot.numRots)})
	if rot.rotatedRows {
		res.SetCoefficients([][]uint64{append(res.Coeffs[0][eval.params.RingT().N>>1:], res.Coeffs[0][:eval.params.RingT().N>>1]...)})
	}
	return res
}

func (eval *evaluatorPlaintextCFPRF) ComputeMemo(op *VerifPlaintext) {
	u, v, p := op.U, op.V, op.Poly

	//if eval.memoU != nil && eval.memoV != nil {
	//	log.Println("memo for powers and rotations of u, v are already computed, skipping")
	//	return
	//}

	eval.memoPow = make(map[RotInfo][][]*ring.Poly, len(p))

	for rot := range p {
		uRot := eval.applyRot(u, rot)
		vRot := eval.applyRot(v, rot)

		uTmp := uRot.CopyNew()
		vTmp := vRot.CopyNew()

		nCoeffs := len(op.Poly[rot][0].Coeffs)
		eval.memoPow[rot] = make([][]*ring.Poly, nCoeffs)
		for i := 0; i < nCoeffs; i++ {
			eval.memoPow[rot][i] = make([]*ring.Poly, nCoeffs, nCoeffs)
		}

		for _, pi := range op.Poly[rot] {
			coeffs := pi.Coeffs

			eval.memoPow[rot][0][1] = vTmp.CopyNew()
			eval.memoPow[rot][1][0] = uTmp.CopyNew()

			for i := 2; i < len(coeffs); i++ {
				eval.params.RingT().MulCoeffs(uRot, uTmp, uTmp)
				eval.params.RingT().MulCoeffs(vRot, vTmp, vTmp)

				eval.memoPow[rot][0][i] = vTmp.CopyNew()
				eval.memoPow[rot][i][0] = uTmp.CopyNew()
			}

			for powU := 1; powU < len(coeffs); powU++ {
				for powV := 1; powV < len(coeffs); powV++ {
					eval.memoPow[rot][powU][powV] = eval.params.RingT().NewPoly()
					eval.params.RingT().MulCoeffs(eval.memoPow[rot][powU][0], eval.memoPow[rot][0][powV], eval.memoPow[rot][powU][powV])
				}
			}
		}
	}
}

func (eval *evaluatorPlaintextCFPRF) Eval(op *VerifPlaintext) *ring.Poly {
	if eval.params.NumDistinctPRFKeys != 1 {
		panic(fmt.Errorf("NumDistinctPRFKeys must be 1 for this optimised implementation to be correct, was, %d", eval.params.NumDistinctPRFKeys))
	}

	R := eval.params.RingT()
	res := R.NewPoly()
	tmp := R.NewPoly()

	for rot := range op.Poly {
		p := op.Poly[rot][0]

		for idxU := range p.Coeffs {
			for idxV, coeff := range p.Coeffs[idxU] {
				if coeff == 0 {
					continue
				}
				if idxU == 0 && idxV == 0 {
					R.AddScalar(res, coeff, res)
				} else {
					R.MulScalar(eval.memoPow[rot][idxU][idxV], coeff, tmp)
					R.Add(res, tmp, res)
				}
			}
		}
	}
	return res
}

type EncoderPlaintextCFPRF interface {
	Encode(tags []Tag, p *VerifPlaintext)
	EncodeNew(tags []Tag) (p *VerifPlaintext)
	CFPRF(replicationIndex int, xs ...interface{}) (uint64, uint64, uint64, uint64)
	U() *ring.Poly
	V() *ring.Poly
}
