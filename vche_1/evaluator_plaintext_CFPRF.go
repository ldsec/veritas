package vche_1

import (
	"encoding/binary"
	"fmt"
	"github.com/ldsec/lattigo/v2/ring"
	"veritas/vche/vche"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
	"hash"
	"math/big"
)

type VerifPlaintext struct {
	*vche.VerifPlaintext
	tags [][]byte
}

func NewVerifPlaintext(params Parameters) *VerifPlaintext {
	return &VerifPlaintext{vche.NewVerifPlaintext(params), make([][]byte, params.NSlots)}
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
	SwitchKeys(op *VerifPlaintext, switchKey *SwitchingKey, out *VerifPlaintext)
	SwitchKeysNew(op *VerifPlaintext, switchkey *SwitchingKey) (out *VerifPlaintext)
	RotateColumns(op *VerifPlaintext, k int, out *VerifPlaintext)
	RotateColumnsNew(op *VerifPlaintext, k int) (out *VerifPlaintext)
	RotateRows(op *VerifPlaintext, out *VerifPlaintext)
	RotateRowsNew(op *VerifPlaintext) (out *VerifPlaintext)
	InnerSum(op *VerifPlaintext, out *VerifPlaintext)
	Eval(op *VerifPlaintext) *TaggedPoly
	ComputeMemo(op *VerifPlaintext)
}

type evaluatorPlaintextCFPRF struct {
	vche.EvaluatorPlaintextCFPRF
	params Parameters
	H      hash.Hash
}

func NewEvaluatorPlaintextCFPRF(parameters Parameters, H hash.Hash) EvaluatorPlaintextCFPRF {
	return &evaluatorPlaintextCFPRF{vche.NewEvaluatorPlaintextCFPRF(parameters), parameters, H}
}

func (eval *evaluatorPlaintextCFPRF) hash(ins ...[][]byte) [][]byte {
	NTags := len(ins[0])

	if len(ins) > 1 {
		for _, in := range ins {
			require.Equal(nil, NTags, len(in))
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

func (eval *evaluatorPlaintextCFPRF) liftBinOp(op func(*vche.VerifPlaintext, *vche.VerifPlaintext, *vche.VerifPlaintext)) (verifOp func(*VerifPlaintext, *VerifPlaintext, *VerifPlaintext)) {
	return func(op0, op1, out *VerifPlaintext) {
		op(op0.VerifPlaintext, op1.VerifPlaintext, out.VerifPlaintext)
		out.tags = eval.hash(op0.tags, op1.tags)
	}
}

func (eval *evaluatorPlaintextCFPRF) CopyNew(op *VerifPlaintext) *VerifPlaintext {
	return &VerifPlaintext{eval.EvaluatorPlaintextCFPRF.CopyNew(op.VerifPlaintext), op.tags}
}

func (eval *evaluatorPlaintextCFPRF) Add(op0, op1 *VerifPlaintext, out *VerifPlaintext) {
	eval.liftBinOp(eval.EvaluatorPlaintextCFPRF.Add)(op0, op1, out)
}

func (eval *evaluatorPlaintextCFPRF) AddNew(op0, op1 *VerifPlaintext) (out *VerifPlaintext) {
	out = NewVerifPlaintext(eval.params)
	eval.Add(op0, op1, out)
	return out
}

func (eval *evaluatorPlaintextCFPRF) AddNoMod(op0, op1 *VerifPlaintext, out *VerifPlaintext) {
	eval.liftBinOp(eval.EvaluatorPlaintextCFPRF.AddNoMod)(op0, op1, out)
}

func (eval *evaluatorPlaintextCFPRF) AddNoModNew(op0, op1 *VerifPlaintext) (out *VerifPlaintext) {
	out = NewVerifPlaintext(eval.params)
	eval.AddNoMod(op0, op1, out)
	return out
}

func (eval *evaluatorPlaintextCFPRF) Sub(op0, op1 *VerifPlaintext, out *VerifPlaintext) {
	eval.liftBinOp(eval.EvaluatorPlaintextCFPRF.Sub)(op0, op1, out)
}

func (eval *evaluatorPlaintextCFPRF) SubNew(op0, op1 *VerifPlaintext) (out *VerifPlaintext) {
	out = NewVerifPlaintext(eval.params)
	eval.Sub(op0, op1, out)
	return out
}

func (eval *evaluatorPlaintextCFPRF) SubNoMod(op0, op1 *VerifPlaintext, out *VerifPlaintext) {
	eval.liftBinOp(eval.EvaluatorPlaintextCFPRF.SubNoMod)(op0, op1, out)
}

func (eval *evaluatorPlaintextCFPRF) SubNoModNew(op0, op1 *VerifPlaintext) (out *VerifPlaintext) {
	out = NewVerifPlaintext(eval.params)
	eval.SubNoMod(op0, op1, out)
	return out
}

func (eval *evaluatorPlaintextCFPRF) Neg(op *VerifPlaintext, out *VerifPlaintext) {
	eval.EvaluatorPlaintextCFPRF.Neg(op.VerifPlaintext, out.VerifPlaintext)
	out.tags = eval.hash(op.tags)
}

func (eval *evaluatorPlaintextCFPRF) NegNew(op *VerifPlaintext) (out *VerifPlaintext) {
	out = NewVerifPlaintext(eval.params)
	eval.Neg(op, out)
	return out
}

func (eval *evaluatorPlaintextCFPRF) Reduce(op *VerifPlaintext, out *VerifPlaintext) {
	eval.EvaluatorPlaintextCFPRF.Reduce(op.VerifPlaintext, out.VerifPlaintext)
	out.tags = eval.hash(op.tags)
}

func (eval *evaluatorPlaintextCFPRF) ReduceNew(op *VerifPlaintext) (out *VerifPlaintext) {
	out = NewVerifPlaintext(eval.params)
	eval.Reduce(op, out)
	return out
}

func (eval *evaluatorPlaintextCFPRF) MulScalar(op *VerifPlaintext, scalar uint64, out *VerifPlaintext) {
	eval.EvaluatorPlaintextCFPRF.MulScalar(op.VerifPlaintext, scalar, out.VerifPlaintext)

	scalarBytes := make([][]byte, len(op.tags))
	for i := range scalarBytes {
		scalarBytes[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(scalarBytes[i], scalar)

	}
	out.tags = eval.hash(op.tags, scalarBytes)
}

func (eval *evaluatorPlaintextCFPRF) MulScalarNew(op *VerifPlaintext, scalar uint64) (out *VerifPlaintext) {
	out = NewVerifPlaintext(eval.params)
	eval.MulScalar(op, scalar, out)
	return out
}

func (eval *evaluatorPlaintextCFPRF) Mul(op0, op1 *VerifPlaintext, out *VerifPlaintext) {
	eval.EvaluatorPlaintextCFPRF.Mul(op0.VerifPlaintext, op1.VerifPlaintext, out.VerifPlaintext)
	out.tags = eval.hash(op0.tags, op1.tags)
}

func (eval *evaluatorPlaintextCFPRF) MulNew(op0, op1 *VerifPlaintext) (out *VerifPlaintext) {
	out = NewVerifPlaintext(eval.params)
	eval.Mul(op0, op1, out)
	return out
}

func (eval *evaluatorPlaintextCFPRF) Relinearize(op *VerifPlaintext, out *VerifPlaintext) {
	eval.EvaluatorPlaintextCFPRF.Relinearize(op.VerifPlaintext, out.VerifPlaintext)
	out.tags = eval.hash(op.tags)
}

func (eval *evaluatorPlaintextCFPRF) RelinearizeNew(op *VerifPlaintext) (out *VerifPlaintext) {
	out = NewVerifPlaintext(eval.params)
	eval.Relinearize(op, out)
	return out
}

func (eval *evaluatorPlaintextCFPRF) SwitchKeys(op *VerifPlaintext, switchKey *SwitchingKey, out *VerifPlaintext) {
	eval.EvaluatorPlaintextCFPRF.SwitchKeys(op.VerifPlaintext, switchKey.SwitchingKey, out.VerifPlaintext)
	out.tags = eval.hash(op.tags)
}

func (eval *evaluatorPlaintextCFPRF) SwitchKeysNew(op *VerifPlaintext, switchKey *SwitchingKey) (out *VerifPlaintext) {
	out = NewVerifPlaintext(eval.params)
	eval.SwitchKeys(op, switchKey, out)
	return out
}

func (eval *evaluatorPlaintextCFPRF) RotateColumns(op *VerifPlaintext, k int, out *VerifPlaintext) {
	eval.EvaluatorPlaintextCFPRF.RotateColumns(op.VerifPlaintext, k, out.VerifPlaintext)

	kBytes := make([][]byte, len(op.tags))
	for i := range kBytes {
		kBytes[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(kBytes[i], uint64(k))

	}
	out.tags = eval.hash(op.tags, kBytes)
}
func (eval *evaluatorPlaintextCFPRF) RotateColumnsNew(op *VerifPlaintext, k int) (out *VerifPlaintext) {
	out = NewVerifPlaintext(eval.params)
	eval.RotateColumns(op, k, out)
	return out
}

func (eval *evaluatorPlaintextCFPRF) RotateRows(op *VerifPlaintext, out *VerifPlaintext) {
	eval.EvaluatorPlaintextCFPRF.RotateRows(op.VerifPlaintext, out.VerifPlaintext)
	out.tags = eval.hash(op.tags)
}

func (eval *evaluatorPlaintextCFPRF) RotateRowsNew(op *VerifPlaintext) (out *VerifPlaintext) {
	out = NewVerifPlaintext(eval.params)
	eval.RotateRows(op, out)
	return out
}

func (eval *evaluatorPlaintextCFPRF) InnerSum(op *VerifPlaintext, out *VerifPlaintext) {
	eval.EvaluatorPlaintextCFPRF.InnerSum(op.VerifPlaintext, out.VerifPlaintext)
	out.tags = eval.hash(op.tags)
}

func (eval *evaluatorPlaintextCFPRF) Eval(op *VerifPlaintext) *TaggedPoly {
	return &TaggedPoly{eval.EvaluatorPlaintextCFPRF.Eval(op.VerifPlaintext), op.tags}
}

func (eval *evaluatorPlaintextCFPRF) ComputeMemo(op *VerifPlaintext) {
	eval.EvaluatorPlaintextCFPRF.ComputeMemo(op.VerifPlaintext)
}

type EncoderPlaintextCFPRF interface {
	Encode(tags []vche.Tag, p *VerifPlaintext)
	EncodeNew(tags []vche.Tag) (p *VerifPlaintext)
	CFPRF(xs ...interface{}) (uint64, uint64, uint64, uint64)
}

type encoderPlaintextCFPRF struct {
	params     Parameters
	K          vche.PRFKey
	u          *ring.Poly
	v          *ring.Poly
	xof1, xof2 blake2b.XOF
}

func NewEncoderPlaintextCFPRF(parameters Parameters, K vche.PRFKey) EncoderPlaintextCFPRF {
	return encoderPlaintextCFPRF{parameters, K, nil, nil, vche.NewXOF(K.K1), vche.NewXOF(K.K2)}
}

func (enc encoderPlaintextCFPRF) Encode(tags []vche.Tag, p *VerifPlaintext) {
	var a uint64
	var b uint64

	if enc.u == nil { // Memoize
		enc.u = enc.params.RingT().NewPoly()
		enc.v = enc.params.RingT().NewPoly()

		for i := 0; i < enc.params.NSlots; i++ {
			for j := 0; j < enc.params.NumReplications; j++ {
				idx := i*enc.params.NumReplications + j
				aI, bI, uI, vI := enc.CFPRF(tags[i], uint64(j))
				if i == 0 {
					a = aI
					b = bI
				} else {
					if a != aI || b != bI {
						panic(fmt.Errorf("mismatched PRF outputs at position %d, the dataset tag should be the same for the entire plaintext", i))
					}
				}
				enc.u.Coeffs[0][idx] = uI
				enc.v.Coeffs[0][idx] = vI
			}
		}
	} else { // Read from memo
		a, b, _, _ = enc.CFPRF(tags[0]) // the second argument to the PRF (`j` above) is only used for the index PRF, and is omitted here
	}

	bps := vche.NewBivariatePoly(1, enc.params.T())
	bps.SetCoeff(1, 0, a)
	bps.SetCoeff(0, 1, b)

	p.U = enc.u
	p.V = enc.v
	p.Poly = map[vche.RotInfo][]vche.BivariatePoly{vche.NoRot: {bps}}

	// Set randomness used from the tags for each message
	T := enc.params.T()
	vs := make([][]byte, len(tags))
	for i, tI := range tags {
		vs[i] = make([]byte, 8)
		a, b, u, v := enc.CFPRF(tI)
		// Compute a*u + b*v in Z_t
		bigT := big.NewInt(0).SetUint64(T)
		au := big.NewInt(0)
		au.Mul(big.NewInt(0).SetUint64(a), big.NewInt(0).SetUint64(u))
		au.Mod(au, bigT)

		bv := big.NewInt(0)
		bv.Mul(big.NewInt(0).SetUint64(b), big.NewInt(0).SetUint64(v))
		bv.Mod(bv, bigT)

		res := big.NewInt(0)
		res.Add(au, bv)
		res.Mod(res, bigT)

		binary.BigEndian.PutUint64(vs[i], res.Uint64())
	}
	p.tags = vs
}

func (enc encoderPlaintextCFPRF) EncodeNew(tags []vche.Tag) (p *VerifPlaintext) {
	p = NewVerifPlaintext(enc.params)
	enc.Encode(tags, p)
	return p
}

func (enc encoderPlaintextCFPRF) CFPRF(xs ...interface{}) (uint64, uint64, uint64, uint64) {
	return vche.CFPRF(enc.xof1, enc.xof2, enc.params.T(), xs...)
}
