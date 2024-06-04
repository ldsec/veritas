package vche_1

import (
	"fmt"
	"veritas/vche/vche"
	"hash"
)

type genericEvaluatorPlaintext struct {
	EvaluatorPlaintext
}

func NewGenericEvaluatorPlaintext(params Parameters, H hash.Hash) vche.GenericEvaluator {
	return &genericEvaluatorPlaintext{NewEvaluatorPlaintext(params, H)}
}

func NewGenericEvaluatorsPlaintext(params Parameters, H hash.Hash, n int) []vche.GenericEvaluator {
	if n <= 0 {
		return []vche.GenericEvaluator{}
	}
	evas := make([]vche.GenericEvaluator, n, n)
	for i := range evas {
		if i == 0 {
			evas[0] = NewGenericEvaluatorPlaintext(params, H)
		} else {
			evas[i] = evas[i-1].ShallowCopy()
		}
	}
	return evas
}

func taggedPoly(x interface{}) *TaggedPoly {
	switch poly := x.(type) {
	case *TaggedPoly:
		return poly
	default:
		panic(fmt.Errorf("expected *TaggedPoly, got %T", poly))
	}
}
func (eval *genericEvaluatorPlaintext) CopyNew(op interface{}) interface{} {
	return eval.EvaluatorPlaintext.CopyNew(taggedPoly(op))
}

func (eval *genericEvaluatorPlaintext) Add(op0, op1 interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintext.Add(taggedPoly(op0), taggedPoly(op1), taggedPoly(ctOut))
}

func (eval *genericEvaluatorPlaintext) AddNew(op0, op1 interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintext.AddNew(taggedPoly(op0), taggedPoly(op1))
}

func (eval *genericEvaluatorPlaintext) AddNoMod(op0, op1 interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintext.AddNoMod(taggedPoly(op0), taggedPoly(op1), taggedPoly(ctOut))
}

func (eval *genericEvaluatorPlaintext) AddNoModNew(op0, op1 interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintext.AddNoModNew(taggedPoly(op0), taggedPoly(op1))
}

func (eval *genericEvaluatorPlaintext) Sub(op0, op1 interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintext.Sub(taggedPoly(op0), taggedPoly(op1), taggedPoly(ctOut))
}

func (eval *genericEvaluatorPlaintext) SubNew(op0, op1 interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintext.SubNew(taggedPoly(op0), taggedPoly(op1))
}

func (eval *genericEvaluatorPlaintext) SubNoMod(op0, op1 interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintext.SubNoMod(taggedPoly(op0), taggedPoly(op1), taggedPoly(ctOut))
}

func (eval *genericEvaluatorPlaintext) SubNoModNew(op0, op1 interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintext.SubNoModNew(taggedPoly(op0), taggedPoly(op1))
}

func (eval *genericEvaluatorPlaintext) Neg(op interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintext.Neg(taggedPoly(op), taggedPoly(ctOut))
}

func (eval *genericEvaluatorPlaintext) NegNew(op interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintext.NegNew(taggedPoly(op))
}

func (eval *genericEvaluatorPlaintext) Reduce(op interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintext.Reduce(taggedPoly(op), taggedPoly(ctOut))
}

func (eval *genericEvaluatorPlaintext) ReduceNew(op interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintext.ReduceNew(taggedPoly(op))
}

func (eval *genericEvaluatorPlaintext) MulScalar(op interface{}, scalar uint64, ctOut interface{}) {
	eval.EvaluatorPlaintext.MulScalar(taggedPoly(op), scalar, taggedPoly(ctOut))
}

func (eval *genericEvaluatorPlaintext) MulScalarNew(op interface{}, scalar uint64) (ctOut interface{}) {
	return eval.EvaluatorPlaintext.MulScalarNew(taggedPoly(op), scalar)
}

func (eval *genericEvaluatorPlaintext) Mul(op0 interface{}, op1 interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintext.Mul(taggedPoly(op0), taggedPoly(op1), taggedPoly(ctOut))
}

func (eval *genericEvaluatorPlaintext) MulNew(op0 interface{}, op1 interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintext.MulNew(taggedPoly(op0), taggedPoly(op1))
}

func (eval *genericEvaluatorPlaintext) Relinearize(ct0 interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintext.Relinearize(taggedPoly(ct0), taggedPoly(ctOut))
}

func (eval *genericEvaluatorPlaintext) RelinearizeNew(ct0 interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintext.RelinearizeNew(taggedPoly(ct0))
}

func (eval *genericEvaluatorPlaintext) SwitchKeys(ct0 interface{}, switchKey interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintext.SwitchKeys(taggedPoly(ct0), switchKey.(*SwitchingKey), taggedPoly(ctOut))
}

func (eval *genericEvaluatorPlaintext) SwitchKeysNew(ct0 interface{}, switchkey interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintext.SwitchKeysNew(taggedPoly(ct0), switchkey.(*SwitchingKey))
}

func (eval *genericEvaluatorPlaintext) RotateRows(ct0 interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintext.RotateRows(taggedPoly(ct0), taggedPoly(ctOut))
}

func (eval *genericEvaluatorPlaintext) RotateRowsNew(ct0 interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintext.RotateRowsNew(taggedPoly(ct0))
}

func (eval *genericEvaluatorPlaintext) RotateColumns(ct0 interface{}, k int, ctOut interface{}) {
	eval.EvaluatorPlaintext.RotateColumns(taggedPoly(ct0), k, taggedPoly(ctOut))
}

func (eval *genericEvaluatorPlaintext) RotateColumnsNew(ct0 interface{}, k int) (ctOut interface{}) {
	return eval.EvaluatorPlaintext.RotateColumnsNew(taggedPoly(ct0), k)
}

func (eval *genericEvaluatorPlaintext) InnerSum(ct0 interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintext.InnerSum(taggedPoly(ct0), taggedPoly(ctOut))
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

func NewGenericEncoderPlaintext(parameters Parameters, K vche.PRFKey) vche.GenericEncoderPlaintext {
	return &genericEncoderPlaintext{NewEncoderPlaintext(parameters, K)}
}

func (enc genericEncoderPlaintext) Encode(tags []vche.Tag, p interface{}) {
	enc.EncoderPlaintext.Encode(tags, taggedPoly(p))
}

func (enc genericEncoderPlaintext) EncodeNew(tags []vche.Tag) (p interface{}) {
	return enc.EncoderPlaintext.EncodeNew(tags)
}
