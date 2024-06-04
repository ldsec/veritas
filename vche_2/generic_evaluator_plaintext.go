package vche_2

import (
	"fmt"
	"veritas/vche/vche"
)

type genericEvaluatorPlaintext struct {
	EvaluatorPlaintext
}

func NewGenericEvaluatorPlaintext(params Parameters) vche.GenericEvaluator {
	return &genericEvaluatorPlaintext{NewEvaluatorPlaintext(params)}
}

func NewGenericEvaluatorsPlaintext(params Parameters, n int) []vche.GenericEvaluator {
	if n <= 0 {
		return []vche.GenericEvaluator{}
	}
	evas := make([]vche.GenericEvaluator, n, n)
	for i := range evas {
		if i == 0 {
			evas[0] = NewGenericEvaluatorPlaintext(params)
		} else {
			evas[i] = evas[i-1].ShallowCopy()
		}
	}
	return evas
}

func ringPoly(x interface{}) *Poly {
	switch poly := x.(type) {
	case *Poly:
		return poly
	default:
		panic(fmt.Errorf("expected *Poly, got %T", poly))
	}
}
func (eval *genericEvaluatorPlaintext) CopyNew(op interface{}) interface{} {
	return eval.EvaluatorPlaintext.CopyNew(ringPoly(op))
}

func (eval *genericEvaluatorPlaintext) Add(op0, op1 interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintext.Add(ringPoly(op0), ringPoly(op1), ringPoly(ctOut))
}

func (eval *genericEvaluatorPlaintext) AddNew(op0, op1 interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintext.AddNew(ringPoly(op0), ringPoly(op1))
}

func (eval *genericEvaluatorPlaintext) AddNoMod(op0, op1 interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintext.AddNoMod(ringPoly(op0), ringPoly(op1), ringPoly(ctOut))
}

func (eval *genericEvaluatorPlaintext) AddNoModNew(op0, op1 interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintext.AddNoModNew(ringPoly(op0), ringPoly(op1))
}

func (eval *genericEvaluatorPlaintext) Sub(op0, op1 interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintext.Sub(ringPoly(op0), ringPoly(op1), ringPoly(ctOut))
}

func (eval *genericEvaluatorPlaintext) SubNew(op0, op1 interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintext.SubNew(ringPoly(op0), ringPoly(op1))
}

func (eval *genericEvaluatorPlaintext) SubNoMod(op0, op1 interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintext.SubNoMod(ringPoly(op0), ringPoly(op1), ringPoly(ctOut))
}

func (eval *genericEvaluatorPlaintext) SubNoModNew(op0, op1 interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintext.SubNoModNew(ringPoly(op0), ringPoly(op1))
}

func (eval *genericEvaluatorPlaintext) Neg(op interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintext.Neg(ringPoly(op), ringPoly(ctOut))
}

func (eval *genericEvaluatorPlaintext) NegNew(op interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintext.NegNew(ringPoly(op))
}

func (eval *genericEvaluatorPlaintext) Reduce(op interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintext.Reduce(ringPoly(op), ringPoly(ctOut))
}

func (eval *genericEvaluatorPlaintext) ReduceNew(op interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintext.ReduceNew(ringPoly(op))
}

func (eval *genericEvaluatorPlaintext) MulScalar(op interface{}, scalar uint64, ctOut interface{}) {
	eval.EvaluatorPlaintext.MulScalar(ringPoly(op), scalar, ringPoly(ctOut))
}

func (eval *genericEvaluatorPlaintext) MulScalarNew(op interface{}, scalar uint64) (ctOut interface{}) {
	return eval.EvaluatorPlaintext.MulScalarNew(ringPoly(op), scalar)
}

func (eval *genericEvaluatorPlaintext) Mul(op0 interface{}, op1 interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintext.Mul(ringPoly(op0), ringPoly(op1), ringPoly(ctOut))
}

func (eval *genericEvaluatorPlaintext) MulNew(op0 interface{}, op1 interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintext.MulNew(ringPoly(op0), ringPoly(op1))
}

func (eval *genericEvaluatorPlaintext) Relinearize(ct0 interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintext.Relinearize(ringPoly(ct0), ringPoly(ctOut))
}

func (eval *genericEvaluatorPlaintext) RelinearizeNew(ct0 interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintext.RelinearizeNew(ringPoly(ct0))
}

func (eval *genericEvaluatorPlaintext) SwitchKeys(ct0 interface{}, switchKey interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintext.SwitchKeys(ringPoly(ct0), switchKey.(*SwitchingKey), ringPoly(ctOut))
}

func (eval *genericEvaluatorPlaintext) SwitchKeysNew(ct0 interface{}, switchkey interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintext.SwitchKeysNew(ringPoly(ct0), switchkey.(*SwitchingKey))
}

func (eval *genericEvaluatorPlaintext) RotateRows(ct0 interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintext.RotateRows(ringPoly(ct0), ringPoly(ctOut))
}

func (eval *genericEvaluatorPlaintext) RotateRowsNew(ct0 interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintext.RotateRowsNew(ringPoly(ct0))
}

func (eval *genericEvaluatorPlaintext) RotateColumns(ct0 interface{}, k int, ctOut interface{}) {
	eval.EvaluatorPlaintext.RotateColumns(ringPoly(ct0), k, ringPoly(ctOut))
}

func (eval *genericEvaluatorPlaintext) RotateColumnsNew(ct0 interface{}, k int) (ctOut interface{}) {
	return eval.EvaluatorPlaintext.RotateColumnsNew(ringPoly(ct0), k)
}

func (eval *genericEvaluatorPlaintext) InnerSum(ct0 interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintext.InnerSum(ringPoly(ct0), ringPoly(ctOut))
}

func (eval *genericEvaluatorPlaintext) ShallowCopy() vche.GenericEvaluator {
	return &genericEvaluatorPlaintext{eval.EvaluatorPlaintext}
}

func (eval *genericEvaluatorPlaintext) WithKey(_ interface{}) vche.GenericEvaluator {
	return &genericEvaluatorPlaintext{eval.EvaluatorPlaintext}
}

type genericEncoderPlaintext struct {
	EncoderPlaintext
}

func NewGenericEncoderPlaintext(parameters Parameters, K []vche.PRFKey) vche.GenericEncoderPlaintext {
	return &genericEncoderPlaintext{NewEncoderPlaintext(parameters, K)}
}

func (enc genericEncoderPlaintext) Encode(tags []vche.Tag, p interface{}) {
	enc.EncoderPlaintext.Encode(tags, ringPoly(p))
}

func (enc genericEncoderPlaintext) EncodeNew(tags []vche.Tag) (p interface{}) {
	return enc.EncoderPlaintext.EncodeNew(tags)
}
