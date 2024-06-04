package vche_1

import (
	"fmt"
	"veritas/vche/vche"
	"hash"
)

type genericEvaluatorPlaintextCFPRF struct {
	EvaluatorPlaintextCFPRF
}

func NewGenericEvaluatorPlaintextCFPRF(params Parameters, H hash.Hash) vche.GenericEvaluator {
	return &genericEvaluatorPlaintextCFPRF{NewEvaluatorPlaintextCFPRF(params, H)}
}

func NewGenericEvaluatorsPlaintextCFPRF(params Parameters, H hash.Hash, n int) []vche.GenericEvaluator {
	if n <= 0 {
		return []vche.GenericEvaluator{}
	}
	evas := make([]vche.GenericEvaluator, n, n)
	for i := range evas {
		if i == 0 {
			evas[0] = NewGenericEvaluatorPlaintextCFPRF(params, H)
		} else {
			evas[i] = evas[i-1].ShallowCopy()
		}
	}
	return evas
}

func verifPtxt(x interface{}) *VerifPlaintext {
	switch ptxt := x.(type) {
	case *VerifPlaintext:
		return ptxt
	default:
		panic(fmt.Errorf("expected *VerifPlaintext, got %T", ptxt))
	}
}

func (eval *genericEvaluatorPlaintextCFPRF) CopyNew(op interface{}) interface{} {
	return eval.EvaluatorPlaintextCFPRF.CopyNew(verifPtxt(op))
}

func (eval *genericEvaluatorPlaintextCFPRF) Add(op0, op1 interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintextCFPRF.Add(verifPtxt(op0), verifPtxt(op1), verifPtxt(ctOut))
}

func (eval *genericEvaluatorPlaintextCFPRF) AddNew(op0, op1 interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintextCFPRF.AddNew(verifPtxt(op0), verifPtxt(op1))
}

func (eval *genericEvaluatorPlaintextCFPRF) AddNoMod(op0, op1 interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintextCFPRF.AddNoMod(verifPtxt(op0), verifPtxt(op1), verifPtxt(ctOut))
}

func (eval *genericEvaluatorPlaintextCFPRF) AddNoModNew(op0, op1 interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintextCFPRF.AddNoModNew(verifPtxt(op0), verifPtxt(op1))
}

func (eval *genericEvaluatorPlaintextCFPRF) Sub(op0, op1 interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintextCFPRF.Sub(verifPtxt(op0), verifPtxt(op1), verifPtxt(ctOut))
}

func (eval *genericEvaluatorPlaintextCFPRF) SubNew(op0, op1 interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintextCFPRF.SubNew(verifPtxt(op0), verifPtxt(op1))
}

func (eval *genericEvaluatorPlaintextCFPRF) SubNoMod(op0, op1 interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintextCFPRF.SubNoMod(verifPtxt(op0), verifPtxt(op1), verifPtxt(ctOut))
}

func (eval *genericEvaluatorPlaintextCFPRF) SubNoModNew(op0, op1 interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintextCFPRF.SubNoModNew(verifPtxt(op0), verifPtxt(op1))
}

func (eval *genericEvaluatorPlaintextCFPRF) Neg(op interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintextCFPRF.Neg(verifPtxt(op), verifPtxt(ctOut))
}

func (eval *genericEvaluatorPlaintextCFPRF) NegNew(op interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintextCFPRF.NegNew(verifPtxt(op))
}

func (eval *genericEvaluatorPlaintextCFPRF) Reduce(op interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintextCFPRF.Reduce(verifPtxt(op), verifPtxt(ctOut))
}

func (eval *genericEvaluatorPlaintextCFPRF) ReduceNew(op interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintextCFPRF.ReduceNew(verifPtxt(op))
}

func (eval *genericEvaluatorPlaintextCFPRF) MulScalar(op interface{}, scalar uint64, ctOut interface{}) {
	eval.EvaluatorPlaintextCFPRF.MulScalar(verifPtxt(op), scalar, verifPtxt(ctOut))
}

func (eval *genericEvaluatorPlaintextCFPRF) MulScalarNew(op interface{}, scalar uint64) (ctOut interface{}) {
	return eval.EvaluatorPlaintextCFPRF.MulScalarNew(verifPtxt(op), scalar)
}

func (eval *genericEvaluatorPlaintextCFPRF) Mul(op0 interface{}, op1 interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintextCFPRF.Mul(verifPtxt(op0), verifPtxt(op1), verifPtxt(ctOut))
}

func (eval *genericEvaluatorPlaintextCFPRF) MulNew(op0 interface{}, op1 interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintextCFPRF.MulNew(verifPtxt(op0), verifPtxt(op1))
}

func (eval *genericEvaluatorPlaintextCFPRF) Relinearize(ct0 interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintextCFPRF.Relinearize(verifPtxt(ct0), verifPtxt(ctOut))
}

func (eval *genericEvaluatorPlaintextCFPRF) RelinearizeNew(ct0 interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintextCFPRF.RelinearizeNew(verifPtxt(ct0))
}

func (eval *genericEvaluatorPlaintextCFPRF) SwitchKeys(ct0 interface{}, switchKey interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintextCFPRF.SwitchKeys(verifPtxt(ct0), switchKey.(*SwitchingKey), verifPtxt(ctOut))
}

func (eval *genericEvaluatorPlaintextCFPRF) SwitchKeysNew(ct0 interface{}, switchkey interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintextCFPRF.SwitchKeysNew(verifPtxt(ct0), switchkey.(*SwitchingKey))
}

func (eval *genericEvaluatorPlaintextCFPRF) RotateRows(ct0 interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintextCFPRF.RotateRows(verifPtxt(ct0), verifPtxt(ctOut))
}

func (eval *genericEvaluatorPlaintextCFPRF) RotateRowsNew(ct0 interface{}) (ctOut interface{}) {
	return eval.EvaluatorPlaintextCFPRF.RotateRowsNew(verifPtxt(ct0))
}

func (eval *genericEvaluatorPlaintextCFPRF) RotateColumns(ct0 interface{}, k int, ctOut interface{}) {
	eval.EvaluatorPlaintextCFPRF.RotateColumns(verifPtxt(ct0), k, verifPtxt(ctOut))
}

func (eval *genericEvaluatorPlaintextCFPRF) RotateColumnsNew(ct0 interface{}, k int) (ctOut interface{}) {
	return eval.EvaluatorPlaintextCFPRF.RotateColumnsNew(verifPtxt(ct0), k)
}

func (eval *genericEvaluatorPlaintextCFPRF) InnerSum(ct0 interface{}, ctOut interface{}) {
	eval.EvaluatorPlaintextCFPRF.InnerSum(verifPtxt(ct0), verifPtxt(ctOut))
}

func (eval *genericEvaluatorPlaintextCFPRF) ShallowCopy() vche.GenericEvaluator {
	return &genericEvaluatorPlaintextCFPRF{eval.EvaluatorPlaintextCFPRF}
}

func (eval *genericEvaluatorPlaintextCFPRF) WithKey(_ interface{}) vche.GenericEvaluator {
	return &genericEvaluatorPlaintextCFPRF{eval.EvaluatorPlaintextCFPRF}
}

type genericEncoderPlaintextCFPRF struct {
	EncoderPlaintextCFPRF
}

func NewGenericEncoderPlaintextCFPRF(parameters Parameters, K vche.PRFKey) vche.GenericEncoderPlaintext {
	return &genericEncoderPlaintextCFPRF{NewEncoderPlaintextCFPRF(parameters, K)}
}

func (enc genericEncoderPlaintextCFPRF) Encode(tags []vche.Tag, p interface{}) {
	enc.EncoderPlaintextCFPRF.Encode(tags, verifPtxt(p))
}

func (enc genericEncoderPlaintextCFPRF) EncodeNew(tags []vche.Tag) (p interface{}) {
	return enc.EncoderPlaintextCFPRF.EncodeNew(tags)
}
