package vche_1

import (
	"encoding/binary"
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/rlwe"
	"veritas/vche/vche"
	"hash"
)

type Operand interface {
	El() *rlwe.Ciphertext
	Degree() int
	Tags() [][]byte
}

// Check that Plaintext and Ciphertext are bfv.Operand
var _ bfv.Operand = Plaintext{}
var _ bfv.Operand = Ciphertext{}

// Check that Plaintext and Ciphertext are Operand
var _ Operand = Plaintext{}
var _ Operand = Ciphertext{}
var _ Operand = PlaintextMul{}

// Evaluator is an interface implementing the public methods of the eval.
type Evaluator interface {
	Hash(op ...[][]byte) [][]byte
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
	H      hash.Hash
}

// NewEvaluator creates a new Evaluator, that can be used to do homomorphic
// operations on ciphertexts and/or plaintexts. It stores a small pool of polynomials
// and ciphertexts that will be used for intermediate values.
func NewEvaluator(params Parameters, evaluationKey *EvaluationKey) Evaluator {
	return &evaluator{vche.NewEvaluator(params, evaluationKey.EvaluationKey), params, evaluationKey.H}
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
		cp := NewPlaintext(eval.params)
		cp.Copy(el)
		copy(cp.tags, el.tags)
		return cp
	case *Ciphertext:
		return el.CopyNew()
	default:
		panic(fmt.Errorf("unsupported type %T", el))
	}
}

func (eval *evaluator) Hash(ins ...[][]byte) [][]byte {
	NTags := len(ins[0])

	if len(ins) > 1 {
		for _, in := range ins {
			if NTags != len(in) {
				panic(fmt.Errorf("mismatched tag lengths, expected %d, got %d)", NTags, len(in)))
			}
		}
	}

	eval.H.Reset()
	hashed := make([][]byte, NTags)
	for i := 0; i < NTags; i++ {
		for _, in := range ins {
			eval.H.Write(in[i])
		}

		hashed[i] = eval.H.Sum(make([]byte, 0))
	}
	return hashed
}

//liftOperand converts an Operand to a bfv.Operand, which is needed to use the BFV evaluation code as-is
func liftOperand(op Operand) bfv.Operand {
	switch el := op.(type) {
	case *Plaintext:
		return el.Plaintext
	case *PlaintextMul:
		return el.PlaintextMul
	case *Ciphertext:
		return el.Ciphertext
	default:
		panic(fmt.Errorf("cannot convert operand %T to a bfv.Operand", op))
	}
}

func liftBfvOp(bfvOp func(bfv.Operand, bfv.Operand, *bfv.Ciphertext), hashOp func(...[][]byte) [][]byte) (vcheOp func(Operand, Operand, *Ciphertext)) {
	return func(op0, op1 Operand, ctOut *Ciphertext) {
		bfvOp(liftOperand(op0), liftOperand(op1), ctOut.Ciphertext)
		ctOut.tags = hashOp(op0.Tags(), op1.Tags())
	}
}

func liftBfvOpNew(bfvOpNew func(bfv.Operand, bfv.Operand) *bfv.Ciphertext, hashOp func(...[][]byte) [][]byte) (vcheOp func(Operand, Operand) *Ciphertext) {
	return func(op0, op1 Operand) (ctOut *Ciphertext) {
		return &Ciphertext{bfvOpNew(liftOperand(op0), liftOperand(op1)), hashOp(op0.Tags(), op1.Tags())}
	}
}

func (eval *evaluator) Add(op0, op1 Operand, ctOut *Ciphertext) {
	liftBfvOp(eval.Evaluator.Add, eval.Hash)(op0, op1, ctOut)
}

func (eval *evaluator) AddNew(op0, op1 Operand) (ctOut *Ciphertext) {
	return liftBfvOpNew(eval.Evaluator.AddNew, eval.Hash)(op0, op1)
}

func (eval *evaluator) AddNoMod(op0, op1 Operand, ctOut *Ciphertext) {
	liftBfvOp(eval.Evaluator.AddNoMod, eval.Hash)(op0, op1, ctOut)
}

func (eval *evaluator) AddNoModNew(op0, op1 Operand) (ctOut *Ciphertext) {
	return liftBfvOpNew(eval.Evaluator.AddNoModNew, eval.Hash)(op0, op1)
}

func (eval *evaluator) Sub(op0, op1 Operand, ctOut *Ciphertext) {
	liftBfvOp(eval.Evaluator.Sub, eval.Hash)(op0, op1, ctOut)
}

func (eval *evaluator) SubNew(op0, op1 Operand) (ctOut *Ciphertext) {
	return liftBfvOpNew(eval.Evaluator.SubNew, eval.Hash)(op0, op1)
}

func (eval *evaluator) SubNoMod(op0, op1 Operand, ctOut *Ciphertext) {
	liftBfvOp(eval.Evaluator.SubNoMod, eval.Hash)(op0, op1, ctOut)
}

func (eval *evaluator) SubNoModNew(op0, op1 Operand) (ctOut *Ciphertext) {
	return liftBfvOpNew(eval.Evaluator.SubNoModNew, eval.Hash)(op0, op1)
}
func (eval *evaluator) Neg(op Operand, ctOut *Ciphertext) {
	eval.Evaluator.Neg(liftOperand(op), ctOut.Ciphertext)
	ctOut.tags = eval.Hash(op.Tags())
}

func (eval *evaluator) NegNew(op Operand) (ctOut *Ciphertext) {
	return &Ciphertext{eval.Evaluator.NegNew(liftOperand(op)), eval.Hash(op.Tags())}
}

func (eval *evaluator) Reduce(op Operand, ctOut *Ciphertext) {
	eval.Evaluator.Reduce(liftOperand(op), ctOut.Ciphertext)
	ctOut.tags = eval.Hash(op.Tags())
}

func (eval *evaluator) ReduceNew(op Operand) (ctOut *Ciphertext) {
	return &Ciphertext{eval.Evaluator.ReduceNew(liftOperand(op)), eval.Hash(op.Tags())}
}

func (eval *evaluator) MulScalar(op Operand, scalar uint64, ctOut *Ciphertext) {
	eval.Evaluator.MulScalar(liftOperand(op), scalar, ctOut.Ciphertext)
	scalarBytes := make([][]byte, len(op.Tags()))
	for i := range scalarBytes {
		scalarBytes[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(scalarBytes[i], scalar)

	}
	ctOut.tags = eval.Hash(op.Tags(), scalarBytes)
}

func (eval *evaluator) MulScalarNew(op Operand, scalar uint64) (ctOut *Ciphertext) {
	scalarBytes := make([][]byte, len(op.Tags()))
	for i := range scalarBytes {
		scalarBytes[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(scalarBytes[i], scalar)

	}
	return &Ciphertext{eval.Evaluator.MulScalarNew(liftOperand(op), scalar), eval.Hash(op.Tags(), scalarBytes)}
}

func (eval *evaluator) Mul(op0 *Ciphertext, op1 Operand, ctOut *Ciphertext) {
	if op0.Degree()+op1.Degree() != ctOut.Degree() {
		panic(fmt.Errorf("if the degree of the result ciphertext is not equal to the sum of the degrees of its inputs, you might encounter errors during decryption checks"))
	}
	eval.Evaluator.Mul(op0.Ciphertext, liftOperand(op1), ctOut.Ciphertext)
	ctOut.tags = eval.Hash(op0.Tags(), op1.Tags())
}

func (eval *evaluator) MulNew(op0 *Ciphertext, op1 Operand) (ctOut *Ciphertext) {
	return &Ciphertext{eval.Evaluator.MulNew(op0.Ciphertext, liftOperand(op1)), eval.Hash(op0.Tags(), op1.Tags())}
}

func (eval *evaluator) Relinearize(ct0 *Ciphertext, ctOut *Ciphertext) {
	eval.Evaluator.Relinearize(ct0.Ciphertext, ctOut.Ciphertext)
	ctOut.tags = eval.Hash(ct0.Tags())
}

func (eval *evaluator) RelinearizeNew(ct0 *Ciphertext) (ctOut *Ciphertext) {
	return &Ciphertext{eval.Evaluator.RelinearizeNew(ct0.Ciphertext), eval.Hash(ct0.Tags())}
}

func (eval *evaluator) SwitchKeys(ct0 *Ciphertext, switchKey *SwitchingKey, ctOut *Ciphertext) {
	eval.Evaluator.SwitchKeys(ct0.Ciphertext, switchKey.SwitchingKey, ctOut.Ciphertext)
	ctOut.tags = eval.Hash(ct0.tags)
}

func (eval *evaluator) SwitchKeysNew(ct0 *Ciphertext, switchkey *SwitchingKey) (ctOut *Ciphertext) {
	return &Ciphertext{eval.Evaluator.SwitchKeysNew(ct0.Ciphertext, switchkey.SwitchingKey), eval.Hash(ct0.tags)}
}

// RotateColumns rotates the columns of ct0 by k*lambda positions to the left and returns the result in ctOut.
func (eval *evaluator) RotateColumns(ct0 *Ciphertext, k int, ctOut *Ciphertext) {
	kBytes := make([][]byte, len(ct0.Tags()))
	for i := range kBytes {
		kBytes[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(kBytes[i], uint64(k))

	}
	eval.Evaluator.RotateColumns(ct0.Ciphertext, k, ctOut.Ciphertext)
	ctOut.tags = eval.Hash(ct0.tags, kBytes)
}

func (eval *evaluator) RotateColumnsNew(ct0 *Ciphertext, k int) (ctOut *Ciphertext) {
	kBytes := make([][]byte, len(ct0.Tags()))
	for i := range kBytes {
		kBytes[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(kBytes[i], uint64(k))

	}
	return &Ciphertext{eval.Evaluator.RotateColumnsNew(ct0.Ciphertext, k), eval.Hash(ct0.tags, kBytes)}
}

func (eval *evaluator) RotateRows(ct0 *Ciphertext, ctOut *Ciphertext) {
	eval.Evaluator.RotateRows(ct0.Ciphertext, ctOut.Ciphertext)
	ctOut.tags = eval.Hash(ct0.tags)
}

func (eval *evaluator) RotateRowsNew(ct0 *Ciphertext) (ctOut *Ciphertext) {
	return &Ciphertext{eval.Evaluator.RotateRowsNew(ct0.Ciphertext), eval.Hash(ct0.tags)}
}

func (eval *evaluator) InnerSum(ct0 *Ciphertext, ctOut *Ciphertext) {
	eval.Evaluator.InnerSum(ct0.Ciphertext, ctOut.Ciphertext)
	ctOut.tags = eval.Hash(ct0.tags)
}

func (eval *evaluator) ShallowCopy() Evaluator {
	return &evaluator{eval.Evaluator.ShallowCopy(), eval.params, eval.H}
}

func (eval *evaluator) WithKey(evk EvaluationKey) Evaluator {
	return &evaluator{eval.Evaluator.WithKey(evk.EvaluationKey), eval.params, eval.H}
}
