package bfv_generic

import (
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/rlwe"
	"veritas/vche/vche"
)

type evaluator struct {
	bfv.Evaluator
	params bfv.Parameters
}

var _ vche.GenericEvaluator = evaluator{}

func ctxt(x interface{}) *bfv.Ciphertext {
	switch ctxt := x.(type) {
	case *bfv.Ciphertext:
		return ctxt
	default:
		panic(fmt.Errorf("expected *Ciphertext, got %T", ctxt))
	}
}

func operand(x interface{}) bfv.Operand {
	switch y := x.(type) {
	case bfv.Operand:
		return y
	default:
		panic(fmt.Errorf("expected Operand, got %T", y))
	}
}

func NewGenericEvaluator(params bfv.Parameters, evaluationKey rlwe.EvaluationKey) vche.GenericEvaluator {
	return &evaluator{bfv.NewEvaluator(params, evaluationKey), params}
}

func (e evaluator) CopyNew(op interface{}) interface{} {
	switch el := op.(type) {
	case *bfv.Plaintext:
		cp := bfv.NewPlaintext(e.params)
		cp.Plaintext.Copy(el.Plaintext)
		return cp
	case *bfv.PlaintextMul:
		cp := bfv.NewPlaintextMul(e.params)
		cp.Plaintext.Copy(el.Plaintext)
		return cp
	case *bfv.Ciphertext:
		return el.CopyNew()
	default:
		panic(fmt.Errorf("unsupported type %T", el))
	}
}

func (e evaluator) Add(op0, op1 interface{}, ctOut interface{}) {
	e.Evaluator.Add(operand(op0), operand(op1), ctxt(ctOut))
}

func (e evaluator) AddNew(op0, op1 interface{}) (ctOut interface{}) {
	return e.Evaluator.AddNew(operand(op0), operand(op1))
}

func (e evaluator) AddNoMod(op0, op1 interface{}, ctOut interface{}) {
	e.Evaluator.AddNoMod(operand(op0), operand(op1), ctxt(ctOut))
}

func (e evaluator) AddNoModNew(op0, op1 interface{}) (ctOut interface{}) {
	return e.Evaluator.AddNoModNew(operand(op0), operand(op1))
}

func (e evaluator) Sub(op0, op1 interface{}, ctOut interface{}) {
	e.Evaluator.Sub(operand(op0), operand(op1), ctxt(ctOut))
}

func (e evaluator) SubNew(op0, op1 interface{}) (ctOut interface{}) {
	return e.Evaluator.SubNew(operand(op0), operand(op1))
}

func (e evaluator) SubNoMod(op0, op1 interface{}, ctOut interface{}) {
	e.Evaluator.SubNoMod(operand(op0), operand(op1), ctxt(ctOut))
}

func (e evaluator) SubNoModNew(op0, op1 interface{}) (ctOut interface{}) {
	return e.Evaluator.SubNoModNew(operand(op0), operand(op1))

}

func (e evaluator) Neg(op interface{}, ctOut interface{}) {
	e.Evaluator.Neg(operand(op), ctxt(ctOut))
}

func (e evaluator) NegNew(op interface{}) (ctOut interface{}) {
	return e.Evaluator.NegNew(operand(op))
}

func (e evaluator) Reduce(op interface{}, ctOut interface{}) {
	e.Evaluator.Reduce(operand(op), ctxt(ctOut))
}

func (e evaluator) ReduceNew(op interface{}) (ctOut interface{}) {
	return e.Evaluator.ReduceNew(operand(op))
}

func (e evaluator) MulScalar(op interface{}, scalar uint64, ctOut interface{}) {
	e.Evaluator.MulScalar(operand(op), scalar, ctxt(ctOut))
}

func (e evaluator) MulScalarNew(op interface{}, scalar uint64) (ctOut interface{}) {
	return e.Evaluator.MulScalarNew(operand(op), scalar)

}

func (e evaluator) Mul(op0 interface{}, op1 interface{}, ctOut interface{}) {
	e.Evaluator.Mul(ctxt(op0), operand(op1), ctxt(ctOut))
}

func (e evaluator) MulNew(op0 interface{}, op1 interface{}) (ctOut interface{}) {
	return e.Evaluator.MulNew(ctxt(op0), operand(op1))
}

func (e evaluator) Relinearize(ct0 interface{}, ctOut interface{}) {
	e.Evaluator.Relinearize(ctxt(ct0), ctxt(ctOut))
}

func (e evaluator) RelinearizeNew(ct0 interface{}) (ctOut interface{}) {
	return e.Evaluator.RelinearizeNew(ctxt(ct0))
}

func (e evaluator) SwitchKeys(ct0 interface{}, switchKey interface{}, ctOut interface{}) {
	e.Evaluator.SwitchKeys(ctxt(ct0), switchKey.(*rlwe.SwitchingKey), ctxt(ctOut))
}

func (e evaluator) SwitchKeysNew(ct0 interface{}, switchKey interface{}) (ctOut interface{}) {
	return e.Evaluator.SwitchKeysNew(ctxt(ct0), switchKey.(*rlwe.SwitchingKey))
}

func (e evaluator) RotateColumns(ct0 interface{}, k int, ctOut interface{}) {
	e.Evaluator.RotateColumns(ctxt(ct0), k, ctxt(ctOut))
}

func (e evaluator) RotateColumnsNew(ct0 interface{}, k int) (ctOut interface{}) {
	return e.Evaluator.RotateColumnsNew(ctxt(ct0), k)
}

func (e evaluator) RotateRows(ct0 interface{}, ctOut interface{}) {
	e.Evaluator.RotateRows(ctxt(ct0), ctxt(ctOut))
}

func (e evaluator) RotateRowsNew(ct0 interface{}) (ctOut interface{}) {
	return e.Evaluator.RotateRowsNew(ctxt(ct0))
}

func (e evaluator) InnerSum(ct0 interface{}, ctOut interface{}) {
	e.Evaluator.InnerSum(ctxt(ct0), ctxt(ctOut))
}

func (e evaluator) ShallowCopy() vche.GenericEvaluator {
	return evaluator{e.Evaluator.ShallowCopy(), e.params}
}

func (e evaluator) WithKey(evk interface{}) vche.GenericEvaluator {
	return evaluator{e.Evaluator.WithKey(evk.(rlwe.EvaluationKey)), e.params}
}
