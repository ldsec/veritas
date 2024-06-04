package vche

import (
	"fmt"
)

type GenericEvaluator interface {
	CopyNew(op interface{}) interface{}
	Add(op0, op1 interface{}, ctOut interface{})
	AddNew(op0, op1 interface{}) (ctOut interface{})
	AddNoMod(op0, op1 interface{}, ctOut interface{})
	AddNoModNew(op0, op1 interface{}) (ctOut interface{})
	Sub(op0, op1 interface{}, ctOut interface{})
	SubNew(op0, op1 interface{}) (ctOut interface{})
	SubNoMod(op0, op1 interface{}, ctOut interface{})
	SubNoModNew(op0, op1 interface{}) (ctOut interface{})
	Neg(op interface{}, ctOut interface{})
	NegNew(op interface{}) (ctOut interface{})
	Reduce(op interface{}, ctOut interface{})
	ReduceNew(op interface{}) (ctOut interface{})
	MulScalar(op interface{}, scalar uint64, ctOut interface{})
	MulScalarNew(op interface{}, scalar uint64) (ctOut interface{})
	Mul(op0 interface{}, op1 interface{}, ctOut interface{})
	MulNew(op0 interface{}, op1 interface{}) (ctOut interface{})
	Relinearize(ct0 interface{}, ctOut interface{})
	RelinearizeNew(ct0 interface{}) (ctOut interface{})
	SwitchKeys(ct0 interface{}, switchKey interface{}, ctOut interface{})
	SwitchKeysNew(ct0 interface{}, switchkey interface{}) (ctOut interface{})
	RotateColumns(ct0 interface{}, k int, ctOut interface{})
	RotateColumnsNew(ct0 interface{}, k int) (ctOut interface{})
	RotateRows(ct0 interface{}, ctOut interface{})
	RotateRowsNew(ct0 interface{}) (ctOut interface{})
	InnerSum(ct0 interface{}, ctOut interface{})
	ShallowCopy() GenericEvaluator
	WithKey(evk interface{}) GenericEvaluator
}

type genericEvaluator struct {
	Evaluator
}

func NewGenericEvaluator(params Parameters, evaluationKey EvaluationKey) GenericEvaluator {
	return &genericEvaluator{NewEvaluator(params, evaluationKey)}
}

func NewGenericEvaluators(params Parameters, evaluationKey EvaluationKey, n int) []GenericEvaluator {
	if n <= 0 {
		return []GenericEvaluator{}
	}
	evas := make([]GenericEvaluator, n, n)
	for i := range evas {
		if i == 0 {
			evas[0] = NewGenericEvaluator(params, evaluationKey)
		} else {
			evas[i] = evas[i-1].ShallowCopy()
		}
	}
	return evas
}

func ctxt(x interface{}) *Ciphertext {
	switch ctxt := x.(type) {
	case *Ciphertext:
		return ctxt
	default:
		panic(fmt.Errorf("expected *Ciphertext, got %T", ctxt))
	}
}

func operand(x interface{}) Operand {
	switch y := x.(type) {
	case *Ciphertext:
		return y
	case Operand:
		return y
	default:
		panic(fmt.Errorf("expected Operand, got %T", y))
	}
}
func (eval *genericEvaluator) CopyNew(op interface{}) interface{} {
	return eval.Evaluator.CopyNew(operand(op))
}

func (eval *genericEvaluator) Add(op0, op1 interface{}, ctOut interface{}) {
	eval.Evaluator.Add(operand(op0), operand(op1), ctxt(ctOut))
}

func (eval *genericEvaluator) AddNew(op0, op1 interface{}) (ctOut interface{}) {
	return eval.Evaluator.AddNew(operand(op0), operand(op1))
}

func (eval *genericEvaluator) AddNoMod(op0, op1 interface{}, ctOut interface{}) {
	eval.Evaluator.AddNoMod(operand(op0), operand(op1), ctxt(ctOut))
}

func (eval *genericEvaluator) AddNoModNew(op0, op1 interface{}) (ctOut interface{}) {
	return eval.Evaluator.AddNoModNew(operand(op0), operand(op1))
}

func (eval *genericEvaluator) Sub(op0, op1 interface{}, ctOut interface{}) {
	eval.Evaluator.Sub(operand(op0), operand(op1), ctxt(ctOut))
}

func (eval *genericEvaluator) SubNew(op0, op1 interface{}) (ctOut interface{}) {
	return eval.Evaluator.SubNew(operand(op0), operand(op1))
}

func (eval *genericEvaluator) SubNoMod(op0, op1 interface{}, ctOut interface{}) {
	eval.Evaluator.SubNoMod(operand(op0), operand(op1), ctxt(ctOut))
}

func (eval *genericEvaluator) SubNoModNew(op0, op1 interface{}) (ctOut interface{}) {
	return eval.Evaluator.SubNoModNew(operand(op0), operand(op1))
}

func (eval *genericEvaluator) Neg(op interface{}, ctOut interface{}) {
	eval.Evaluator.Neg(operand(op), ctxt(ctOut))
}

func (eval *genericEvaluator) NegNew(op interface{}) (ctOut interface{}) {
	return eval.Evaluator.NegNew(operand(op))
}

func (eval *genericEvaluator) Reduce(op interface{}, ctOut interface{}) {
	eval.Evaluator.Reduce(operand(op), ctxt(ctOut))
}

func (eval *genericEvaluator) ReduceNew(op interface{}) (ctOut interface{}) {
	return eval.Evaluator.ReduceNew(operand(op))
}

func (eval *genericEvaluator) MulScalar(op interface{}, scalar uint64, ctOut interface{}) {
	eval.Evaluator.MulScalar(operand(op), scalar, ctxt(ctOut))
}

func (eval *genericEvaluator) MulScalarNew(op interface{}, scalar uint64) (ctOut interface{}) {
	return eval.Evaluator.MulScalarNew(operand(op), scalar)
}

func (eval *genericEvaluator) Mul(op0 interface{}, op1 interface{}, ctOut interface{}) {
	eval.Evaluator.Mul(ctxt(op0), operand(op1), ctxt(ctOut))
}

func (eval *genericEvaluator) MulNew(op0 interface{}, op1 interface{}) (ctOut interface{}) {
	return eval.Evaluator.MulNew(ctxt(op0), operand(op1))
}

func (eval *genericEvaluator) Relinearize(ct0 interface{}, ctOut interface{}) {
	eval.Evaluator.Relinearize(ctxt(ct0), ctxt(ctOut))
}

func (eval *genericEvaluator) RelinearizeNew(ct0 interface{}) (ctOut interface{}) {
	return eval.Evaluator.RelinearizeNew(ctxt(ct0))
}

func (eval *genericEvaluator) SwitchKeys(ct0 interface{}, switchKey interface{}, ctOut interface{}) {
	eval.Evaluator.SwitchKeys(ctxt(ct0), switchKey.(*SwitchingKey), ctxt(ctOut))
}

func (eval *genericEvaluator) SwitchKeysNew(ct0 interface{}, switchkey interface{}) (ctOut interface{}) {
	return eval.Evaluator.SwitchKeysNew(ctxt(ct0), switchkey.(*SwitchingKey))
}

func (eval *genericEvaluator) RotateRows(ct0 interface{}, ctOut interface{}) {
	eval.Evaluator.RotateRows(ctxt(ct0), ctxt(ctOut))
}

func (eval *genericEvaluator) RotateRowsNew(ct0 interface{}) (ctOut interface{}) {
	return eval.Evaluator.RotateRowsNew(ctxt(ct0))
}

func (eval *genericEvaluator) RotateColumns(ct0 interface{}, k int, ctOut interface{}) {
	eval.Evaluator.RotateColumns(ctxt(ct0), k, ctxt(ctOut))
}

func (eval *genericEvaluator) RotateColumnsNew(ct0 interface{}, k int) (ctOut interface{}) {
	return eval.Evaluator.RotateColumnsNew(ctxt(ct0), k)
}

func (eval *genericEvaluator) InnerSum(ct0 interface{}, ctOut interface{}) {
	eval.Evaluator.InnerSum(ctxt(ct0), ctxt(ctOut))
}

func (eval *genericEvaluator) ShallowCopy() GenericEvaluator {
	return &genericEvaluator{eval.Evaluator.ShallowCopy()}
}

func (eval *genericEvaluator) WithKey(evk interface{}) GenericEvaluator {
	return &genericEvaluator{eval.Evaluator.WithKey(evk.(EvaluationKey))}
}
