package vche_2

import (
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/utils"
	"veritas/vche/vche"
)

type Operand interface {
	Operands() []bfv.Operand
	Len() int
	BfvDegree() int
}

// Check that Plaintext and Ciphertext are bfv.Operand
var _ Operand = Plaintext{}
var _ Operand = Ciphertext{}

// Evaluator is an interface implementing the public methods of the eval.
type Evaluator interface {
	CopyNew(op Operand) Operand
	Add(op0, op1 Operand, ctOut *Ciphertext)
	AddNew(op0, op1 Operand) (ctOut *Ciphertext)
	AddNoMod(op0, op1 Operand, ctOut *Ciphertext)
	AddNoModNew(op0, op1 Operand) (ctOut *Ciphertext)
	Sub(op0, op1 Operand, ctOut *Ciphertext)
	SubNew(op0, op1 Operand) (ctOut *Ciphertext)
	SubNoMod(op0, op1 Operand, ctOut *Ciphertext)
	SubNoModNew(op0, op1 Operand) (ctOut *Ciphertext)
	Neg(op Operand, ctOut *Ciphertext)
	NegNew(op Operand) (ctOut *Ciphertext)
	Reduce(op Operand, ctOut *Ciphertext)
	ReduceNew(op Operand) (ctOut *Ciphertext)
	MulScalar(op Operand, scalar uint64, ctOut *Ciphertext)
	MulScalarNew(op Operand, scalar uint64) (ctOut *Ciphertext)
	Mul(op0 *Ciphertext, op1 Operand, ctOut *Ciphertext)
	MulNew(op0 *Ciphertext, op1 Operand) (ctOut *Ciphertext)
	Relinearize(ct0 *Ciphertext, ctOut *Ciphertext)
	RelinearizeNew(ct0 *Ciphertext) (ctOut *Ciphertext)
	SwitchKeys(ct0 *Ciphertext, switchKey *SwitchingKey, ctOut *Ciphertext)
	SwitchKeysNew(ct0 *Ciphertext, switchkey *SwitchingKey) (ctOut *Ciphertext)
	RotateColumns(ct0 *Ciphertext, k int, ctOut *Ciphertext)
	RotateColumnsNew(ct0 *Ciphertext, k int) (ctOut *Ciphertext)
	RotateRows(ct0 *Ciphertext, ctOut *Ciphertext)
	RotateRowsNew(ct0 *Ciphertext) (ctOut *Ciphertext)
	InnerSum(ct0 *Ciphertext, ctOut *Ciphertext)
	ShallowCopy() Evaluator
	WithKey(evk EvaluationKey) Evaluator
}

type evaluator struct {
	vche.Evaluator
	params Parameters
	shift  *ring.Poly
}

// NewEvaluator creates a new Evaluator, that can be used to do homomorphic
// operations on ciphertexts and/or plaintexts. It stores a small pool of polynomials
// and ciphertexts that will be used for intermediate values.
func NewEvaluator(params Parameters, evaluationKey *EvaluationKey) Evaluator {
	return &evaluator{vche.NewEvaluator(params, *evaluationKey), params, params.RingT().NewPoly()}
}

// NewEvaluators creates n evaluators sharing the same read-only data-structures.
func NewEvaluators(params Parameters, evaluationKey *EvaluationKey, n int) []Evaluator {
	if n <= 0 {
		return []Evaluator{}
	}
	evas := make([]Evaluator, n, n)
	for i := range evas {
		if i == 0 {
			evas[0] = NewEvaluator(params, evaluationKey)
		} else {
			evas[i] = evas[i-1].ShallowCopy()
		}
	}
	return evas
}

func (eval *evaluator) CopyNew(op Operand) Operand {
	switch el := op.(type) {
	case *Plaintext:
		plaintexts := make([]*bfv.Plaintext, op.Len())
		for i := range plaintexts {
			plaintexts[i] = bfv.NewPlaintext(eval.params.Parameters)
			plaintexts[i].Plaintext.Copy(el.Plaintexts[i].Plaintext)
		}
		return &Plaintext{plaintexts}
	case *Ciphertext:
		return el.CopyNew()
	default:
		panic(fmt.Errorf("unsupported type %T", el))
	}
}

func (eval *evaluator) Add(op0, op1 Operand, ctOut *Ciphertext) {
	d0 := op0.Len()
	d1 := op1.Len()
	d := utils.MaxInt(d0, d1)

	ops0 := op0.Operands()
	ops1 := op1.Operands()

	ctOut.Ciphertexts = make([]*bfv.Ciphertext, d)
	for i := range ctOut.Ciphertexts {
		if i < d0 && i < d1 {
			ctOut.Ciphertexts[i] = eval.Evaluator.AddNew(ops0[i], ops1[i])
		} else if i < d0 {
			ctOut.Ciphertexts[i] = eval.Evaluator.CopyNew(ops0[i]).(*bfv.Ciphertext)
		} else if i < d1 {
			ctOut.Ciphertexts[i] = eval.Evaluator.CopyNew(ops1[i]).(*bfv.Ciphertext)
		}
	}
}

func (eval *evaluator) AddNew(op0, op1 Operand) (ctOut *Ciphertext) {
	ctOut = &Ciphertext{}
	eval.Add(op0, op1, ctOut)
	return ctOut
}

func (eval *evaluator) AddNoMod(op0, op1 Operand, ctOut *Ciphertext) {
	d0 := op0.Len()
	d1 := op1.Len()
	d := utils.MaxInt(d0, d1)

	ops0 := op0.Operands()
	ops1 := op1.Operands()

	ctOut.Ciphertexts = make([]*bfv.Ciphertext, d)
	for i := range ctOut.Ciphertexts {
		if i < d0 && i < d1 {
			ctOut.Ciphertexts[i] = eval.Evaluator.AddNoModNew(ops0[i], ops1[i])
		} else if i < d0 {
			ctOut.Ciphertexts[i] = eval.Evaluator.CopyNew(ops0[i]).(*bfv.Ciphertext)
		} else if i < d1 {
			ctOut.Ciphertexts[i] = eval.Evaluator.CopyNew(ops1[i]).(*bfv.Ciphertext)
		}
	}
}

func (eval *evaluator) AddNoModNew(op0, op1 Operand) (ctOut *Ciphertext) {
	ctOut = &Ciphertext{}
	eval.AddNoMod(op0, op1, ctOut)
	return ctOut
}

func (eval *evaluator) Sub(op0, op1 Operand, ctOut *Ciphertext) {
	d0 := op0.Len()
	d1 := op1.Len()
	d := utils.MaxInt(d0, d1)

	ops0 := op0.Operands()
	ops1 := op1.Operands()

	ctOut.Ciphertexts = make([]*bfv.Ciphertext, d)
	for i := range ctOut.Ciphertexts {
		if i < d0 && i < d1 {
			ctOut.Ciphertexts[i] = eval.Evaluator.SubNew(ops0[i], ops1[i])
		} else if i < d0 {
			ctOut.Ciphertexts[i] = eval.Evaluator.CopyNew(ops0[i]).(*bfv.Ciphertext)
		} else if i < d1 {
			ctOut.Ciphertexts[i] = eval.Evaluator.NegNew(ops1[i])
		}
	}
}

func (eval *evaluator) SubNew(op0, op1 Operand) (ctOut *Ciphertext) {
	ctOut = &Ciphertext{}
	eval.Sub(op0, op1, ctOut)
	return ctOut
}

func (eval *evaluator) SubNoMod(op0, op1 Operand, ctOut *Ciphertext) {
	d0 := op0.Len()
	d1 := op1.Len()
	d := utils.MaxInt(d0, d1)

	ops0 := op0.Operands()
	ops1 := op1.Operands()

	ctOut.Ciphertexts = make([]*bfv.Ciphertext, d)
	for i := range ctOut.Ciphertexts {
		if i < d0 && i < d1 {
			ctOut.Ciphertexts[i] = eval.Evaluator.SubNoModNew(ops0[i], ops1[i])
		} else if i < d0 {
			ctOut.Ciphertexts[i] = eval.Evaluator.CopyNew(ops0[i]).(*bfv.Ciphertext)
		} else if i < d1 {
			ctOut.Ciphertexts[i] = eval.Evaluator.NegNew(ops1[i])
		}
	}
}

func (eval *evaluator) SubNoModNew(op0, op1 Operand) (ctOut *Ciphertext) {
	ctOut = &Ciphertext{}
	eval.SubNoMod(op0, op1, ctOut)
	return ctOut
}

func (eval *evaluator) Neg(op Operand, ctOut *Ciphertext) {
	d := op.Len()
	ops := op.Operands()
	ctOut.Ciphertexts = make([]*bfv.Ciphertext, d)
	for i := range ctOut.Ciphertexts {
		ctOut.Ciphertexts[i] = eval.Evaluator.NegNew(ops[i])
	}
}

func (eval *evaluator) NegNew(op Operand) (ctOut *Ciphertext) {
	ctOut = &Ciphertext{}
	eval.Neg(op, ctOut)
	return ctOut
}

func (eval *evaluator) Reduce(op Operand, ctOut *Ciphertext) {
	d := op.Len()
	ops := op.Operands()
	ctOut.Ciphertexts = make([]*bfv.Ciphertext, d)
	for i := range ctOut.Ciphertexts {
		ctOut.Ciphertexts[i] = eval.Evaluator.ReduceNew(ops[i])
	}
}

func (eval *evaluator) ReduceNew(op Operand) (ctOut *Ciphertext) {
	ctOut = &Ciphertext{}
	eval.Reduce(op, ctOut)
	return ctOut
}

func (eval *evaluator) MulScalar(op Operand, scalar uint64, ctOut *Ciphertext) {
	d := op.Len()
	ops := op.Operands()
	ctOut.Ciphertexts = make([]*bfv.Ciphertext, d)
	for i := range ctOut.Ciphertexts {
		ctOut.Ciphertexts[i] = eval.Evaluator.MulScalarNew(ops[i], scalar)
	}
}

func (eval *evaluator) MulScalarNew(op Operand, scalar uint64) (ctOut *Ciphertext) {
	ctOut = &Ciphertext{}
	eval.MulScalar(op, scalar, ctOut)
	return ctOut
}

func (eval *evaluator) MulKaratsubaNew(a *Ciphertext, b *Ciphertext) *Ciphertext {
	if a.Len() == 1 {
		ctxts := make([]*bfv.Ciphertext, b.Len())
		for i := range ctxts {
			ctxts[i] = eval.Evaluator.MulNew(a.Ciphertexts[0], b.Ciphertexts[i])
		}
		return &Ciphertext{ctxts}
	} else if b.Len() == 1 {
		ctxts := make([]*bfv.Ciphertext, a.Len())
		for i := range ctxts {
			ctxts[i] = eval.Evaluator.MulNew(a.Ciphertexts[i], b.Ciphertexts[0])
		}
		return &Ciphertext{ctxts}
	}

	m := utils.MaxInt(a.Len(), b.Len())
	cut := m / 2
	a0, a1 := &Ciphertext{a.Ciphertexts[:cut]}, &Ciphertext{a.Ciphertexts[cut:]}
	b0, b1 := &Ciphertext{b.Ciphertexts[:cut]}, &Ciphertext{b.Ciphertexts[cut:]}

	a0b0 := eval.MulKaratsubaNew(a0, b0)
	a1b1 := eval.MulKaratsubaNew(a1, b1)

	aSum := eval.AddNew(a0, a1)
	bSum := eval.AddNew(b0, b1)
	aSumbSum := eval.MulKaratsubaNew(aSum, bSum)

	z := eval.AddNew(a0b0, a1b1)
	eval.Sub(aSumbSum, z, z)

	ctxts := make([]*bfv.Ciphertext, (a.Len()-1)+(b.Len()-1)+1)
	for i, c := range a0b0.Ciphertexts {
		ctxts[i] = c
	}

	for i, c := range z.Ciphertexts {
		if ctxts[i+cut] == nil {
			ctxts[i+cut] = c
		} else {
			eval.Evaluator.Add(ctxts[i+cut], c, ctxts[i+cut])
		}
	}

	for i, c := range a1b1.Ciphertexts {
		if ctxts[i+2*cut] == nil {
			ctxts[i+2*cut] = c
		} else {
			eval.Evaluator.Add(ctxts[i+2*cut], c, ctxts[i+2*cut])
		}
	}
	return &Ciphertext{ctxts}
}

func (eval *evaluator) MulNaiveNew(op0 *Ciphertext, op1 Operand) *Ciphertext {
	d0 := op0.Len()
	d1 := op1.Len()
	d := (d0 - 1) + (d1 - 1) + 1

	ops0 := op0.Ciphertexts
	ops1 := op1.Operands()

	ciphertexts := make([]*bfv.Ciphertext, d)
	for k := range ciphertexts {
		for i := 0; i <= k; i++ {
			if i < d0 && k-i < d1 {
				ctxtTmp := eval.Evaluator.MulNew(ops0[i], ops1[k-i])
				if ciphertexts[k] == nil {
					ciphertexts[k] = ctxtTmp
				} else {
					eval.Evaluator.Add(ciphertexts[k], ctxtTmp, ciphertexts[k])
				}
			}
		}
	}
	return &Ciphertext{ciphertexts}
}

func (eval *evaluator) Mul(op0 *Ciphertext, op1 Operand, ctOut *Ciphertext) {
	switch el1 := op1.(type) {
	case *Ciphertext:
		allDeg1 := true
		for _, c := range op0.Ciphertexts {
			if c.Degree() != 1 {
				allDeg1 = false
				break
			}
		}
		for _, c := range el1.Ciphertexts {
			if c.Degree() != 1 {
				allDeg1 = false
				break
			}
		}
		if allDeg1 {
			ctOut.Ciphertexts = eval.Convolve(op0.Ciphertexts, el1.Ciphertexts)
		} else {
			ctOut.Ciphertexts = eval.MulKaratsubaNew(op0, el1).Ciphertexts
			//ctOut.Ciphertexts = eval.MulNaiveNew(op0, el1).Ciphertexts
		}
	default:
		ctOut.Ciphertexts = eval.MulNaiveNew(op0, el1).Ciphertexts
	}
}

func (eval *evaluator) MulNew(op0 *Ciphertext, op1 Operand) (ctOut *Ciphertext) {
	ctOut = &Ciphertext{}
	eval.Mul(op0, op1, ctOut)
	return ctOut
}

func (eval *evaluator) Relinearize(ct0 *Ciphertext, ctOut *Ciphertext) {
	d := ct0.Len()
	ops := ct0.Ciphertexts
	ctOut.Ciphertexts = make([]*bfv.Ciphertext, d)
	for i := range ctOut.Ciphertexts {
		ctOut.Ciphertexts[i] = eval.Evaluator.RelinearizeNew(ops[i])
	}
}

func (eval *evaluator) RelinearizeNew(ct0 *Ciphertext) (ctOut *Ciphertext) {
	ctOut = &Ciphertext{}
	eval.Relinearize(ct0, ctOut)
	return ctOut
}

func (eval *evaluator) SwitchKeys(ct0 *Ciphertext, switchKey *SwitchingKey, ctOut *Ciphertext) {
	d := ct0.Len()
	ops := ct0.Ciphertexts
	ctOut.Ciphertexts = make([]*bfv.Ciphertext, d)
	for i := range ctOut.Ciphertexts {
		ctOut.Ciphertexts[i] = eval.Evaluator.SwitchKeysNew(ops[i], switchKey)
	}
}

func (eval *evaluator) SwitchKeysNew(ct0 *Ciphertext, switchkey *SwitchingKey) (ctOut *Ciphertext) {
	ctOut = &Ciphertext{}
	eval.SwitchKeys(ct0, switchkey, ctOut)
	return ctOut
}

// RotateColumns rotates the columns of ct0 by k positions to the left and returns the result in ctOut.
func (eval *evaluator) RotateColumns(ct0 *Ciphertext, k int, ctOut *Ciphertext) {
	d := ct0.Len()
	ops := ct0.Ciphertexts
	ctOut.Ciphertexts = make([]*bfv.Ciphertext, d)
	for i := range ctOut.Ciphertexts {
		ctOut.Ciphertexts[i] = eval.Evaluator.RotateColumnsNew(ops[i], k)
	}
}

func (eval *evaluator) RotateColumnsNew(ct0 *Ciphertext, k int) (ctOut *Ciphertext) {
	ctOut = &Ciphertext{}
	eval.RotateColumns(ct0, k, ctOut)
	return ctOut
}

func (eval *evaluator) RotateRows(ct0 *Ciphertext, ctOut *Ciphertext) {
	d := ct0.Len()
	ops := ct0.Ciphertexts
	ctOut.Ciphertexts = make([]*bfv.Ciphertext, d)
	for i := range ctOut.Ciphertexts {
		ctOut.Ciphertexts[i] = eval.Evaluator.RotateRowsNew(ops[i])
	}
}

func (eval *evaluator) RotateRowsNew(ct0 *Ciphertext) (ctOut *Ciphertext) {
	ctOut = &Ciphertext{}
	eval.RotateRows(ct0, ctOut)
	return ctOut
}

func (eval *evaluator) InnerSum(ct0 *Ciphertext, ctOut *Ciphertext) {
	d := ct0.Len()
	ops := ct0.Ciphertexts
	ctOut.Ciphertexts = make([]*bfv.Ciphertext, d)
	for i := range ctOut.Ciphertexts {
		ctOut.Ciphertexts[i] = bfv.NewCiphertext(eval.params.Parameters, ops[i].Degree())
		eval.Evaluator.InnerSum(ops[i], ctOut.Ciphertexts[i])
	}
}

func (eval *evaluator) ShallowCopy() Evaluator {
	return &evaluator{eval.Evaluator.ShallowCopy(), eval.params, eval.shift.CopyNew()}
}

func (eval *evaluator) WithKey(evk EvaluationKey) Evaluator {
	return &evaluator{eval.Evaluator.WithKey(evk), eval.params, eval.shift.CopyNew()}
}
