package vche_2

import (
	"fmt"
	"log"
	"testing"
)

func runPolynomialProtocol(p Prover, v Verifier, ctxt *Ciphertext, verif *Poly) []uint64 {
	if !p.Params().Equals(v.Params()) {
		panic(fmt.Errorf("prover and verifier must agree on parameters"))
	}
	if p.Params().NumReplications > 1 || p.Params().NumDistinctPRFKeys > 1 {
		panic(fmt.Errorf("the current polynomial protocol implementation does not suppport replication"))
	}

	// P -> V: y_0
	y0Ctxt := p.GetResult(ctxt)
	y0 := v.Dec(y0Ctxt)

	// P <- V: delta, beta
	// P -> V: HH, (w_0, ..., w_d)
	// V: Check w_0 ?= y_0(delta)
	// V: Check HH ?= w_0 + w_1 * beta + ... + w_d * (beta ^ d)
	beta, delta := v.GetRandomPoint(), v.GetRandomPoint()

	wsCtxt := p.EvaluateAt(ctxt, delta)
	HHCtxt := p.LinearlyCombine(wsCtxt, beta)

	m2Ctxt := p.Pack(HHCtxt, wsCtxt)

	m2 := v.Dec(m2Ctxt)
	HH, ws := v.Unpack(m2)

	lhs2 := ws[0]
	rhs2 := v.EvaluateAt(y0, delta)
	v.CheckEqual(lhs2, rhs2)

	lhs3 := HH
	rhs3 := v.LinearlyCombine(ws, beta)
	v.CheckEqual(lhs3, rhs3)

	// V: Check rho(delta) ?= w_0 + w_1 * alpha + ... + w_d * (alpha ^ d)
	lhs5 := v.LinearlyCombine(ws, v.SK().Alpha[0])
	rhs5 := v.EvaluateAt(verif.Coeffs[0], delta)
	v.CheckEqual(lhs5, rhs5)

	if VERBOSE {
		log.Println("verification successful")
	}

	return y0
}

func BenchmarkPolynomialProtocolProver(p Prover, v Verifier, ctxt *Ciphertext, verif *Poly, b *testing.B) []uint64 {
	if !p.Params().Equals(v.Params()) {
		panic(fmt.Errorf("prover and verifier must agree on parameters"))
	}
	if p.Params().NumReplications > 1 || p.Params().NumDistinctPRFKeys > 1 {
		panic(fmt.Errorf("the current polynomial protocol implementation does not suppport replication"))
	}

	// P -> V: y_0
	b.StartTimer()
	y0Ctxt := p.GetResult(ctxt)
	b.StopTimer()
	y0 := v.Dec(y0Ctxt)

	// P <- V: delta, beta
	// P -> V: HH, (w_0, ..., w_d)
	// V: Check w_0 ?= y_0(delta)
	// V: Check HH ?= w_0 + w_1 * beta + ... + w_d * (beta ^ d)
	beta, delta := v.GetRandomPoint(), v.GetRandomPoint()

	b.StartTimer()
	wsCtxt := p.EvaluateAt(ctxt, delta)
	HHCtxt := p.LinearlyCombine(wsCtxt, beta)

	m2Ctxt := p.Pack(HHCtxt, wsCtxt)
	b.StopTimer()

	m2 := v.Dec(m2Ctxt)
	HH, ws := v.Unpack(m2)

	lhs2 := ws[0]
	rhs2 := v.EvaluateAt(y0, delta)
	v.CheckEqual(lhs2, rhs2)

	lhs3 := HH
	rhs3 := v.LinearlyCombine(ws, beta)
	v.CheckEqual(lhs3, rhs3)

	// V: Check rho(delta) ?= w_0 + w_1 * alpha + ... + w_d * (alpha ^ d)
	lhs5 := v.LinearlyCombine(ws, v.SK().Alpha[0])
	rhs5 := v.EvaluateAt(verif.Coeffs[0], delta)
	v.CheckEqual(lhs5, rhs5)

	if VERBOSE {
		log.Println("verification successful")
	}

	return y0
}

func BenchmarkPolynomialProtocolVerifier(p Prover, v Verifier, ctxt *Ciphertext, verif *Poly, b *testing.B) []uint64 {
	if !p.Params().Equals(v.Params()) {
		panic(fmt.Errorf("prover and verifier must agree on parameters"))
	}
	if p.Params().NumReplications > 1 || p.Params().NumDistinctPRFKeys > 1 {
		panic(fmt.Errorf("the current polynomial protocol implementation does not suppport replication"))
	}

	// P -> V: y_0
	y0Ctxt := p.GetResult(ctxt)
	b.StartTimer()
	y0 := v.Dec(y0Ctxt)
	b.StopTimer()

	// P <- V: delta, beta
	// P -> V: HH, (w_0, ..., w_d)
	// V: Check w_0 ?= y_0(delta)
	// V: Check HH ?= w_0 + w_1 * beta + ... + w_d * (beta ^ d)
	b.StartTimer()
	beta, delta := v.GetRandomPoint(), v.GetRandomPoint()
	b.StopTimer()

	wsCtxt := p.EvaluateAt(ctxt, delta)
	HHCtxt := p.LinearlyCombine(wsCtxt, beta)

	m2Ctxt := p.Pack(HHCtxt, wsCtxt)

	b.StartTimer()
	m2 := v.Dec(m2Ctxt)
	HH, ws := v.Unpack(m2)

	lhs2 := ws[0]
	rhs2 := v.EvaluateAt(y0, delta)
	v.CheckEqual(lhs2, rhs2)

	lhs3 := HH
	rhs3 := v.LinearlyCombine(ws, beta)
	v.CheckEqual(lhs3, rhs3)

	// V: Check rho(delta) ?= w_0 + w_1 * alpha + ... + w_d * (alpha ^ d)
	lhs5 := v.LinearlyCombine(ws, v.SK().Alpha[0])
	rhs5 := v.EvaluateAt(verif.Coeffs[0], delta)
	v.CheckEqual(lhs5, rhs5)
	b.StopTimer()

	if VERBOSE {
		log.Println("verification successful")
	}
	return y0
}

func RunPolynomialProtocolUint(p Prover, v Verifier, ctxt *Ciphertext, verif *Poly) []uint64 {
	return runPolynomialProtocol(p, v, ctxt, verif)
}

func RunPolynomialProtocolInt(p Prover, v Verifier, ctxt *Ciphertext, verif *Poly) []int64 {
	resUint := runPolynomialProtocol(p, v, ctxt, verif)
	resInt := make([]int64, len(resUint))
	modulusHalf := p.Params().T() >> 1
	for i := range resUint {
		if resUint[i] >= modulusHalf {
			resInt[i] = int64(resUint[i] - modulusHalf)
		} else {
			resInt[i] = int64(resUint[i])
		}
	}
	return resInt
}
