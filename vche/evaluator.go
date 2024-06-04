package vche

import (
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/rlwe"
)

type Operand = bfv.Operand
type Ciphertext = bfv.Ciphertext
type Plaintext = bfv.Plaintext
type SwitchingKey = rlwe.SwitchingKey
type EvaluationKey = rlwe.EvaluationKey

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
	Convolve(polyCt0, polyCt1 []*Ciphertext) (polyCt2 []*Ciphertext)
}

type evaluator struct {
	bfv.Evaluator
	params Parameters
	*evaluatorBuffers
}
type evaluatorBuffers struct {
	poolQ    [][]*ring.Poly
	poolQmul [][]*ring.Poly
}

func newEvaluatorBuffer(params Parameters) *evaluatorBuffers {
	evb := new(evaluatorBuffers)
	evb.poolQ = make([][]*ring.Poly, 4)
	evb.poolQmul = make([][]*ring.Poly, 4)
	for i := 0; i < 4; i++ {
		evb.poolQ[i] = make([]*ring.Poly, 6)
		evb.poolQmul[i] = make([]*ring.Poly, 6)
		for j := 0; j < 6; j++ {
			evb.poolQ[i][j] = params.RingQ().NewPoly()
			evb.poolQmul[i][j] = params.RingQMul().NewPoly()
		}
	}

	return evb
}

// NewEvaluator creates a new Evaluator, that can be used to do homomorphic
// operations on ciphertexts and/or plaintexts. It stores a small pool of polynomials
// and ciphertexts that will be used for intermediate values.
func NewEvaluator(params Parameters, evaluationKey EvaluationKey) Evaluator {
	evb := newEvaluatorBuffer(params)
	return &evaluator{bfv.NewEvaluator(params.Parameters, evaluationKey), params, evb}
}

// NewEvaluators creates n evaluators sharing the same read-only data-structures.
func NewEvaluators(params Parameters, evaluationKey EvaluationKey, n int) []Evaluator {
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
		cp := bfv.NewPlaintext(eval.params.Parameters)
		cp.Plaintext.Copy(el.Plaintext)
		return el
	case *Ciphertext:
		return el.CopyNew()
	default:
		panic(fmt.Errorf("unsupported type %T", el))
	}
}

// RotateColumns rotates the columns of ct0 by k*lambda positions to the left and returns the result in ctOut.
func (eval *evaluator) RotateColumns(ct0 *Ciphertext, k int, ctOut *Ciphertext) {
	eval.Evaluator.RotateColumns(ct0, (k*eval.params.NumReplications)%eval.params.N(), ctOut)
}

func (eval *evaluator) RotateColumnsNew(ct0 *Ciphertext, k int) (ctOut *Ciphertext) {
	return eval.Evaluator.RotateColumnsNew(ct0, (k*eval.params.NumReplications)%eval.params.N())
}

func (eval *evaluator) InnerSum(ct0 *Ciphertext, ctOut *Ciphertext) {
	if ct0.Degree() != 1 || ctOut.Degree() != 1 {
		panic("cannot InnerSum: input and output must be of degree 1")
	}

	cTmp := bfv.NewCiphertext(eval.params.Parameters, 1)

	ctOut.Copy(ct0.El())

	for i := 1; i < eval.params.NSlots>>1; i <<= 1 {
		eval.RotateColumns(ctOut, i, cTmp)
		eval.Add(cTmp, ctOut, ctOut)
	}

	eval.RotateRows(ctOut, cTmp)
	eval.Add(ctOut, cTmp, ctOut)
}

func (eval *evaluator) ShallowCopy() Evaluator {
	return &evaluator{eval.Evaluator.ShallowCopy(), eval.params, newEvaluatorBuffer(eval.params)}
}

func (eval *evaluator) WithKey(evk EvaluationKey) Evaluator {
	return &evaluator{eval.Evaluator.WithKey(evk), eval.params, eval.evaluatorBuffers}
}

func (eval *evaluator) Convolve(polyCt0, polyCt1 []*Ciphertext) (polyCt2 []*Ciphertext) {
	for i := range polyCt0 {
		if polyCt0[i].Degree() > 1 {
			panic(fmt.Errorf("convolution is only implemented for ciphertexts of (BFV) degree <= 1 (was %d); please relinearize", polyCt0[i].Degree()))
		}
	}
	for i := range polyCt1 {
		if polyCt1[i].Degree() > 1 {
			panic(fmt.Errorf("convolution is only implemented for ciphertexts of (BFV) degree <= 1 (was %d); please relinearize", polyCt1[i].Degree()))
		}
	}

	c1Q1 := make([][]*ring.Poly, len(polyCt1))
	c1Q2 := make([][]*ring.Poly, len(polyCt1))
	c2Q1 := make([][]*ring.Poly, len(polyCt0)+len(polyCt1)-1)
	c2Q2 := make([][]*ring.Poly, len(polyCt0)+len(polyCt1)-1)

	ringQ := eval.params.RingQ()
	ringQMul := eval.params.RingQMul()

	// TODO: use longer arrays of *ring.Poly to support input ciphertexts of degree > 1?
	for i := 0; i < len(polyCt0)+len(polyCt1)-1; i++ {
		c2Q1[i] = []*ring.Poly{ringQ.NewPoly(), ringQ.NewPoly(), ringQ.NewPoly()}
		c2Q2[i] = []*ring.Poly{ringQMul.NewPoly(), ringQMul.NewPoly(), ringQMul.NewPoly()}
	}

	for i := range polyCt1 {
		c1Q1[i] = []*ring.Poly{ringQ.NewPoly(), ringQ.NewPoly()}
		c1Q2[i] = []*ring.Poly{ringQMul.NewPoly(), ringQMul.NewPoly()}
		eval.ModUpAndNTT(polyCt1[i].El(), c1Q1[i], c1Q2[i])
	}

	for i := 0; i < len(polyCt0); i++ {
		eval.ModUpAndNTT(polyCt0[i].El(), eval.poolQ[0], eval.poolQmul[0])

		ringQ.MForm(eval.poolQ[0][0], eval.poolQ[0][0])
		ringQMul.MForm(eval.poolQmul[0][0], eval.poolQmul[0][0])

		ringQ.MForm(eval.poolQ[0][1], eval.poolQ[0][1])
		ringQMul.MForm(eval.poolQmul[0][1], eval.poolQmul[0][1])

		for j := 0; j < len(polyCt1); j++ {
			// c0 = c0[0]*c1[0]
			ringQ.MulCoeffsMontgomeryAndAdd(eval.poolQ[0][0], c1Q1[j][0], c2Q1[i+j][0])
			ringQMul.MulCoeffsMontgomeryAndAdd(eval.poolQmul[0][0], c1Q2[j][0], c2Q2[i+j][0])

			// c1 = c0[0]*c1[1] + c0[1]*c1[0]
			ringQ.MulCoeffsMontgomeryAndAdd(eval.poolQ[0][0], c1Q1[j][1], c2Q1[i+j][1])
			ringQMul.MulCoeffsMontgomeryAndAdd(eval.poolQmul[0][0], c1Q2[j][1], c2Q2[i+j][1])

			ringQ.MulCoeffsMontgomeryAndAdd(eval.poolQ[0][1], c1Q1[j][0], c2Q1[i+j][1])
			ringQMul.MulCoeffsMontgomeryAndAdd(eval.poolQmul[0][1], c1Q2[j][0], c2Q2[i+j][1])

			// c2 = c0[1]*c1[1]
			ringQ.MulCoeffsMontgomeryAndAdd(eval.poolQ[0][1], c1Q1[j][1], c2Q1[i+j][2])
			ringQMul.MulCoeffsMontgomeryAndAdd(eval.poolQmul[0][1], c1Q2[j][1], c2Q2[i+j][2])
		}
	}

	polyCt2 = make([]*Ciphertext, len(polyCt0)+len(polyCt1)-1)
	for i := 0; i < len(polyCt0)+len(polyCt1)-1; i++ {
		polyCt2[i] = bfv.NewCiphertext(eval.params.Parameters, 2)
		eval.Quantize(polyCt2[i].El(), c2Q1[i], c2Q2[i])
	}
	return
}
