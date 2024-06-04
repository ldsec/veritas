package vche_2

import (
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/rlwe"
	"github.com/ldsec/lattigo/v2/utils"
	"veritas/vche/vche"
	"math/big"
)

type ScalarCiphertext = bfv.Ciphertext

type Prover interface {
	GetResult(ctxt *Ciphertext) *bfv.Ciphertext        // Returns the result of the computation, y_0
	EvaluateAt(ctxt *Ciphertext, x uint64) *Ciphertext // Return (y_0(x), ..., y_d(x)) for x in xs
	LinearlyCombine(ctxt *Ciphertext, x uint64) *bfv.Ciphertext
	WithKey(evk rlwe.EvaluationKey) Prover
	Params() Parameters
	Pack(HH *bfv.Ciphertext, ws *Ciphertext) *ScalarCiphertext
}

type prover struct {
	params Parameters
	vche.Evaluator
}

func NewProver(params Parameters, evk EvaluationKey) Prover {
	return &prover{params, vche.NewEvaluator(params, evk)}
}

func (p *prover) WithKey(evk EvaluationKey) Prover {
	return &prover{p.params, p.Evaluator.WithKey(evk)}
}

func (p *prover) GetResult(ctxt *Ciphertext) *bfv.Ciphertext {
	return ctxt.Ciphertexts[0]
}

func (p *prover) Params() Parameters {
	return p.params
}

func (p *prover) EvaluateAt(ctxt *Ciphertext, x uint64) *Ciphertext {
	powersOfX := make([]uint64, p.params.N())
	xPowI := big.NewInt(1)
	bigX := big.NewInt(0).SetUint64(x)
	bigT := big.NewInt(0).SetUint64(p.params.T())
	for i := 0; i < p.params.N(); i++ {
		powersOfX[i] = xPowI.Uint64()
		xPowI.Mul(xPowI, bigX)
		xPowI.Mod(xPowI, bigT)
	}

	powersOfXPtxt := bfv.NewPlaintextMul(p.params.Parameters)
	bfv.NewEncoder(p.params.Parameters).EncodeUintMul(powersOfX, powersOfXPtxt)

	res := &Ciphertext{make([]*bfv.Ciphertext, len(ctxt.Ciphertexts))}
	for i := range res.Ciphertexts {
		res.Ciphertexts[i] = p.Evaluator.MulNew(ctxt.Ciphertexts[i].CopyNew(), powersOfXPtxt)
		p.Evaluator.InnerSum(res.Ciphertexts[i], res.Ciphertexts[i])
	}
	return res
}

func (p *prover) LinearlyCombine(ctxt *Ciphertext, x uint64) *bfv.Ciphertext {
	res := ctxt.Ciphertexts[len(ctxt.Ciphertexts)-1].CopyNew()

	for i := len(ctxt.Ciphertexts) - 2; i >= 0; i-- {
		p.Evaluator.MulScalar(res, x, res)                       // res *= x
		p.Evaluator.Add(res, ctxt.Ciphertexts[i].CopyNew(), res) // res += polys[i]
	}
	return res
}

// Pack : (HH, ..., HH), ((w_0, ..., w_0), ..., (w_d, ..., w_d)) -> (HH, d, w_0, ..., w_d)
func (p *prover) Pack(HH *bfv.Ciphertext, ws *Ciphertext) *ScalarCiphertext {
	bfvEncoder := bfv.NewEncoder(p.params.Parameters)
	ptxtMul := bfv.NewPlaintextMul(p.params.Parameters)

	var coeffs []uint64
	var res *ScalarCiphertext = nil

	for i := 0; i < len(ws.Ciphertexts); i++ {
		coeffs = make([]uint64, p.params.N())
		coeffs[i+2] = 1
		bfvEncoder.EncodeUintMul(coeffs, ptxtMul)
		masked := p.Evaluator.MulNew(ws.Ciphertexts[i], ptxtMul)

		if res == nil {
			res = masked
		} else {
			p.Evaluator.Add(res, masked, res)
		}
	}

	coeffs = make([]uint64, p.params.N())
	coeffs[1] = uint64(len(ws.Ciphertexts))
	ptxt := bfv.NewPlaintext(p.params.Parameters)
	bfvEncoder.EncodeUint(coeffs, ptxt)
	p.Evaluator.Add(res, ptxt, res)

	coeffs = make([]uint64, p.params.N())
	coeffs[0] = 1
	bfvEncoder.EncodeUintMul(coeffs, ptxtMul)
	masked := p.Evaluator.MulNew(HH, ptxtMul)
	p.Evaluator.Add(res, masked, res)

	return res
}

type Verifier interface {
	WithDecryptor(decryptor bfv.Decryptor) Verifier
	WithKey(evk rlwe.EvaluationKey) Verifier
	GetRandomPoint() uint64
	GetRandomPoly() *ring.Poly
	EvaluateAt(poly []uint64, x uint64) uint64
	LinearlyCombine(evals []uint64, x uint64) uint64
	CheckEqual(lhs, rhs uint64)
	Unpack(m []uint64) (HH uint64, ws []uint64)
	Dec(ctxt *bfv.Ciphertext) []uint64
	Dec2(ctxt *bfv.Ciphertext, p *bfv.PlaintextRingT)
	Enc(p *bfv.PlaintextRingT) *bfv.Ciphertext
	Enc2(p *bfv.Plaintext) *bfv.Ciphertext
	ComputeRequad(c3, c4 *bfv.Ciphertext, verif *Poly) (c1Out, c2Out *bfv.Ciphertext, verifOut *Poly)
	ComputeRequadCFPRF(c3, c4 *bfv.Ciphertext, verif *VerifPlaintext) (c1Out, c2Out *bfv.Ciphertext, verifOut *VerifPlaintext)
	Params() Parameters
	SK() *SecretKey
}

type verifier struct {
	bfv.Decryptor
	bfv.Encoder
	params Parameters
	*SecretKey
}

func NewVerifier(params Parameters, sk *SecretKey) Verifier {
	return &verifier{bfv.NewDecryptor(params.Parameters, sk.SecretKey), bfv.NewEncoder(params.Parameters), params, sk}
}

func (v *verifier) WithDecryptor(decryptor bfv.Decryptor) Verifier {
	return &verifier{decryptor, v.Encoder, v.params, v.SecretKey}
}

func (v *verifier) WithKey(_ rlwe.EvaluationKey) Verifier {
	return &verifier{v.Decryptor, v.Encoder, v.params, v.SecretKey}
}

func (v *verifier) Params() Parameters {
	return v.params
}

func (v *verifier) SK() *SecretKey {
	return v.SecretKey
}

func (v *verifier) GetRandomPoint() uint64 {
	return vche.GetRandom(v.params.T())
}

func (v *verifier) EvaluateAt(poly []uint64, x uint64) uint64 {
	res := big.NewInt(0).SetUint64(poly[len(poly)-1])
	bigT := big.NewInt(0).SetUint64(v.params.T())
	for i := len(poly) - 2; i >= 0; i-- {
		res.Mul(res, big.NewInt(0).SetUint64(x))
		res.Mod(res, bigT)
		res.Add(res, big.NewInt(0).SetUint64(poly[i]))
		res.Mod(res, bigT)
	}
	return res.Uint64()
}

// LinearlyCombine : ([]{v0, ..., vd}, x) -> v0 + v1 * x + ... + vd * (x ^ d)
func (v *verifier) LinearlyCombine(evals []uint64, x uint64) uint64 {
	res := big.NewInt(0).SetUint64(evals[len(evals)-1])
	bigT := big.NewInt(0).SetUint64(v.params.T())
	for i := len(evals) - 2; i >= 0; i-- {
		res.Mul(res, big.NewInt(0).SetUint64(x))
		res.Mod(res, bigT)
		res.Add(res, big.NewInt(0).SetUint64(evals[i]))
		res.Mod(res, bigT)
	}
	return res.Uint64()
}
func (v *verifier) CheckEqual(lhs, rhs uint64) {
	if lhs != rhs {
		panic("verification failed : equality check failed")
	}
}

func (v *verifier) Dec(ctxt *bfv.Ciphertext) []uint64 {
	return v.Encoder.DecodeUintNew(v.Decryptor.DecryptNew(ctxt))
}
func (v *verifier) Dec2(ctxt *bfv.Ciphertext, p *bfv.PlaintextRingT) {
	bfvEncoder := bfv.NewEncoder(v.params.Parameters)
	bfvEncoder.DecodeRingT(v.Decryptor.DecryptNew(ctxt), p)
}

func (v *verifier) Enc(pT *bfv.PlaintextRingT) *bfv.Ciphertext {
	p := bfv.NewPlaintext(v.params.Parameters)
	bfvEncoder := bfv.NewEncoder(v.params.Parameters)
	bfvEncoder.ScaleUp(pT, p)
	bfvEncryptor := bfv.NewEncryptor(v.params.Parameters, v.SK().SecretKey)
	return bfvEncryptor.EncryptNew(p)
}

func (v *verifier) Enc2(p *bfv.Plaintext) *bfv.Ciphertext {
	bfvEncryptor := bfv.NewEncryptor(v.params.Parameters, v.SK().SecretKey)
	return bfvEncryptor.EncryptNew(p)
}

func (v *verifier) Unpack(m []uint64) (HH uint64, ws []uint64) {
	HH = m[0]
	l := m[1]
	ws = m[2 : l+2]
	return HH, ws
}

func (v *verifier) GetRandomPoly() *ring.Poly {
	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}
	uSampler := ring.NewUniformSampler(prng, v.params.RingT())
	return uSampler.ReadNew()
}

func (v *verifier) ComputeRequad(c3, c4 *bfv.Ciphertext, verif *Poly) (c1Out, c2Out *bfv.Ciphertext, verifOut *Poly) {
	p3 := bfv.NewPlaintextRingT(v.Params().Parameters)
	v.Dec2(c3, p3)
	var p4 *bfv.PlaintextRingT = nil
	if c4 != nil {
		p4 = bfv.NewPlaintextRingT(v.Params().Parameters)
		v.Dec2(c4, p4)
	}

	// V: Compute p3_bar, p4_bar
	k1, k2 := v.GetRandomPoint(), v.GetRandomPoint()
	r, rBar := v.GetRandomPoly(), v.GetRandomPoly()
	rPtxt, rBarPtxt := bfv.NewPlaintextRingT(v.Params().Parameters), bfv.NewPlaintextRingT(v.Params().Parameters)
	prevShiftPoly := bfv.NewPlaintextRingT(v.Params().Parameters)
	bfvEncoder := bfv.NewEncoder(v.Params().Parameters)
	bfvEncoder.EncodeUintRingT(r.Coeffs[0], rPtxt)
	bfvEncoder.EncodeUintRingT(rBar.Coeffs[0], rBarPtxt)
	bfvEncoder.EncodeUintRingT(verif.Shift.Coeffs[0], prevShiftPoly)

	alpha := v.SK().Alpha[0]
	T := v.Params().T()
	R := v.Params().RingT()

	p1Bar, p2Bar := bfv.NewPlaintextRingT(v.Params().Parameters), bfv.NewPlaintextRingT(v.Params().Parameters)
	tmp := bfv.NewPlaintextRingT(v.Params().Parameters)

	p3Poly := p3.Value
	tmpPoly := tmp.Value
	p1BarPoly, p2BarPoly := p1Bar.Value, p2Bar.Value

	bigT := big.NewInt(0).SetUint64(T)
	bigAlpha := big.NewInt(0).SetUint64(alpha)
	tmpBig := big.NewInt(0)

	// alpha * k1
	tmpBig.Mul(big.NewInt(0).SetUint64(k1), bigAlpha)
	tmpBig.Mod(tmpBig, bigT)
	alphaK1 := tmpBig.Uint64()

	// alpha * alpha
	alpha2Big := big.NewInt(0)
	alpha2Big.Mul(bigAlpha, bigAlpha)
	alpha2Big.Mod(alpha2Big, bigT)
	alpha2 := alpha2Big.Uint64()

	// alpha * alpha * k2
	tmpBig.Mul(alpha2Big, big.NewInt(0).SetUint64(k2))
	tmpBig.Mod(tmpBig, bigT)
	alpha2K2 := tmpBig.Uint64()

	// alpha * alpha * alpha
	tmpBig.Mul(alpha2Big, bigAlpha)
	tmpBig.Mod(tmpBig, bigT)
	alpha3 := tmpBig.Uint64()

	R.MulScalar(p3Poly, alphaK1, tmpPoly)
	p2Bar.Plaintext.Copy(tmp.Plaintext)
	if p4 != nil {
		R.MulScalar(p4.Value, alpha2K2, tmpPoly)
		R.Add(p2BarPoly, tmpPoly, p2BarPoly)
	}
	R.Add(p2BarPoly, rPtxt.Value, p2BarPoly)

	if p4 != nil {
		R.MulScalar(p4.Value, alpha3, tmpPoly)
		p1Bar.Plaintext.Copy(tmp.Plaintext)
		R.MulScalar(p3Poly, alpha2, tmpPoly)
		R.Add(p1BarPoly, tmpPoly, p1BarPoly)
	} else {
		R.MulScalar(p3Poly, alpha2, tmpPoly)
		p1Bar.Plaintext.Copy(tmp.Plaintext)
	}
	R.MulScalar(p2BarPoly, alpha, tmpPoly)
	R.Sub(p1BarPoly, tmpPoly, p1BarPoly)
	R.MulScalar(prevShiftPoly.Value, v.alphaInv[0], prevShiftPoly.Value)
	R.Sub(p1BarPoly, prevShiftPoly.Value, p1BarPoly)
	R.Add(p1BarPoly, rBarPtxt.Value, p1BarPoly)

	// V: Encrypt to c1_bar, c2_bar
	c1Bar, c2Bar := v.Enc(p1Bar), v.Enc(p2Bar)

	// V: Store Shift
	shift := rBar.CopyNew()
	R.MulScalar(shift, v.SK().Alpha[0], shift)

	resV := &Poly{
		Poly:  verif.CopyNew(),
		Shift: shift,
	}

	return c1Bar, c2Bar, resV
}

func (v *verifier) ComputeRequadCFPRF(c3, c4 *bfv.Ciphertext, verif *VerifPlaintext) (c1Out, c2Out *bfv.Ciphertext, verifOut *VerifPlaintext) {
	evalPtxt := vche.NewEvaluatorPlaintextCFPRF(v.Params())

	p3 := bfv.NewPlaintextRingT(v.Params().Parameters)
	v.Dec2(c3, p3)
	var p4 *bfv.PlaintextRingT = nil
	if c4 != nil {
		p4 = bfv.NewPlaintextRingT(v.Params().Parameters)
		v.Dec2(c4, p4)
	}

	// V: Compute p3_bar, p4_bar
	k1, k2 := v.GetRandomPoint(), v.GetRandomPoint()
	r := v.GetRandomPoly()
	rPtxt, rBarPtxt := bfv.NewPlaintextRingT(v.Params().Parameters), bfv.NewPlaintextRingT(v.Params().Parameters)
	// Generate random rBar (using CF-PRF representation)
	rBarA, rBarB := 1+vche.GetRandom(v.params.T()-1), 1+vche.GetRandom(v.params.T()-1) // u.a.r. in Z_t^*

	rBarPoly := vche.NewBivariatePoly(1, v.params.T())
	rBarPoly.SetCoeff(0, 1, rBarA)
	rBarPoly.SetCoeff(1, 0, rBarB)

	rBarVerifPtxt := &vche.VerifPlaintext{
		U:    verif.VerifPlaintext.U,
		V:    verif.VerifPlaintext.V,
		Poly: map[vche.RotInfo][]vche.BivariatePoly{vche.NoRot: {rBarPoly}},
	}

	evalPtxt.ComputeMemo(rBarVerifPtxt) // TODO: don't call this every time
	rBar := evalPtxt.Eval(rBarVerifPtxt)

	evalPtxt.ComputeMemo(verif.Shift)
	prevShift := evalPtxt.Eval(verif.Shift)

	prevShiftPoly := bfv.NewPlaintextRingT(v.Params().Parameters)
	bfvEncoder := bfv.NewEncoder(v.Params().Parameters)
	bfvEncoder.EncodeUintRingT(r.Coeffs[0], rPtxt)
	bfvEncoder.EncodeUintRingT(rBar.Coeffs[0], rBarPtxt)
	bfvEncoder.EncodeUintRingT(prevShift.Coeffs[0], prevShiftPoly)

	alpha := v.SK().Alpha[0]
	T := v.Params().T()
	R := v.Params().RingT()

	p1Bar, p2Bar := bfv.NewPlaintextRingT(v.Params().Parameters), bfv.NewPlaintextRingT(v.Params().Parameters)
	tmp := bfv.NewPlaintextRingT(v.Params().Parameters)

	p3Poly := p3.Value
	tmpPoly := tmp.Value
	p1BarPoly, p2BarPoly := p1Bar.Value, p2Bar.Value

	bigT := big.NewInt(0).SetUint64(T)
	bigAlpha := big.NewInt(0).SetUint64(alpha)
	tmpBig := big.NewInt(0)

	// alpha * k1
	tmpBig.Mul(big.NewInt(0).SetUint64(k1), bigAlpha)
	tmpBig.Mod(tmpBig, bigT)
	alphaK1 := tmpBig.Uint64()

	// alpha * alpha
	alpha2Big := big.NewInt(0)
	alpha2Big.Mul(bigAlpha, bigAlpha)
	alpha2Big.Mod(alpha2Big, bigT)
	alpha2 := alpha2Big.Uint64()

	// alpha * alpha * k2
	tmpBig.Mul(alpha2Big, big.NewInt(0).SetUint64(k2))
	tmpBig.Mod(tmpBig, bigT)
	alpha2K2 := tmpBig.Uint64()

	// alpha * alpha * alpha
	tmpBig.Mul(alpha2Big, bigAlpha)
	tmpBig.Mod(tmpBig, bigT)
	alpha3 := tmpBig.Uint64()

	R.MulScalar(p3Poly, alphaK1, tmpPoly)
	p2Bar.Plaintext.Copy(tmp.Plaintext)
	if p4 != nil {
		R.MulScalar(p4.Value, alpha2K2, tmpPoly)
		R.Add(p2BarPoly, tmpPoly, p2BarPoly)
	}
	R.Add(p2BarPoly, rPtxt.Value, p2BarPoly)

	if p4 != nil {
		R.MulScalar(p4.Value, alpha3, tmpPoly)
		p1Bar.Plaintext.Copy(tmp.Plaintext)
		R.MulScalar(p3Poly, alpha2, tmpPoly)
		R.Add(p1BarPoly, tmpPoly, p1BarPoly)
	} else {
		R.MulScalar(p3Poly, alpha2, tmpPoly)
		p1Bar.Plaintext.Copy(tmp.Plaintext)
	}
	R.MulScalar(p2BarPoly, alpha, tmpPoly)
	R.Sub(p1BarPoly, tmpPoly, p1BarPoly)
	R.MulScalar(prevShiftPoly.Value, v.alphaInv[0], prevShiftPoly.Value)
	R.Sub(p1BarPoly, prevShiftPoly.Value, p1BarPoly)
	R.Add(p1BarPoly, rBarPtxt.Value, p1BarPoly)

	// V: Encrypt to c1_bar, c2_bar
	c1Bar, c2Bar := v.Enc(p1Bar), v.Enc(p2Bar)

	// V: Store Shift
	shift := rBarVerifPtxt
	shift.Poly[vche.NoRot] = vche.BivariatePolyMulScalar(shift.Poly[vche.NoRot], v.SK().Alpha[0])

	resV := &VerifPlaintext{
		VerifPlaintext: verif.VerifPlaintext.CopyNew(),
		Shift:          shift,
	}

	return c1Bar, c2Bar, resV
}

func NewProverVerifier(params Parameters, sk *SecretKey, innerSumRotKeys *RotationKeySet) (Prover, Verifier) {
	prover := NewProver(params, EvaluationKey{Rlk: nil, Rtks: innerSumRotKeys})
	verifier := NewVerifier(params, sk)
	return prover, verifier
}
