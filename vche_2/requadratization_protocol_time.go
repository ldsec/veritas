package vche_2

import (
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/rlwe"
	"log"
	"testing"
)

func BenchmarkRequadratizationProtocolProver(p Prover, v Verifier, ctxt *Ciphertext, verif *Poly, b *testing.B) (*Ciphertext, *Poly) {
	b.StopTimer()
	// P->V: c3, c4
	var c3, c4 *bfv.Ciphertext
	if ctxt.Len() <= 3 {
		if VERBOSE {
			log.Printf("requadratization is a no-op for ciphertext %v with outer degree %d < 3", ctxt, ctxt.Len()-1)
		}
		return ctxt, verif
	} else if ctxt.Len() == 4 {
		c3 = ctxt.Ciphertexts[3]
		c4 = nil
	} else if ctxt.Len() == 5 {
		c3, c4 = ctxt.Ciphertexts[3], ctxt.Ciphertexts[4]
	} else {
		panic(fmt.Errorf("cannot requadratize the ciphertext %v with outer degree %d > 4", ctxt, ctxt.Len()-1))
	}

	// V: Compute c1_bar, c2_bar; Update state
	c1Bar, c2Bar, resV := v.ComputeRequad(c3, c4, verif)

	// P <- V: c1_bar, c2_bar

	// P: Compute ctxt = (c0, c1 + c1_bar, c2 + c2_bar)
	b.StartTimer()
	eval := bfv.NewEvaluator(v.Params().Parameters, rlwe.EvaluationKey{}) // TODO: get from prover
	res := &Ciphertext{make([]*bfv.Ciphertext, 3)}
	res.Ciphertexts[0] = ctxt.Ciphertexts[0].CopyNew()
	res.Ciphertexts[1] = ctxt.Ciphertexts[1].CopyNew()
	res.Ciphertexts[2] = ctxt.Ciphertexts[2].CopyNew()

	eval.Add(res.Ciphertexts[1], c1Bar, res.Ciphertexts[1])
	eval.Add(res.Ciphertexts[2], c2Bar, res.Ciphertexts[2])
	b.StopTimer()

	return res, resV
}

func BenchmarkRequadratizationProtocolVerifier(p Prover, v Verifier, ctxt *Ciphertext, verif *Poly, b *testing.B) (*Ciphertext, *Poly) {
	b.StopTimer()
	// P->V: c3, c4
	var c3, c4 *bfv.Ciphertext
	if ctxt.Len() <= 3 {
		if VERBOSE {
			log.Printf("requadratization is a no-op for ciphertext %v with outer degree %d < 3", ctxt, ctxt.Len()-1)
		}
		return ctxt, verif
	} else if ctxt.Len() == 4 {
		c3 = ctxt.Ciphertexts[3]
		c4 = nil
	} else if ctxt.Len() == 5 {
		c3, c4 = ctxt.Ciphertexts[3], ctxt.Ciphertexts[4]
	} else {
		panic(fmt.Errorf("cannot requadratize the ciphertext %v with outer degree %d > 4", ctxt, ctxt.Len()-1))
	}

	// V: Compute c1_bar, c2_bar; Update state
	b.StartTimer()
	c1Bar, c2Bar, resV := v.ComputeRequad(c3, c4, verif)
	b.StopTimer()

	// P <- V: c1_bar, c2_bar

	// P: Compute ctxt = (c0, c1 + c1_bar, c2 + c2_bar)
	eval := bfv.NewEvaluator(v.Params().Parameters, rlwe.EvaluationKey{}) // TODO: get from prover
	res := &Ciphertext{make([]*bfv.Ciphertext, 3)}
	res.Ciphertexts[0] = ctxt.Ciphertexts[0].CopyNew()
	res.Ciphertexts[1] = ctxt.Ciphertexts[1].CopyNew()
	res.Ciphertexts[2] = ctxt.Ciphertexts[2].CopyNew()

	eval.Add(res.Ciphertexts[1], c1Bar, res.Ciphertexts[1])
	eval.Add(res.Ciphertexts[2], c2Bar, res.Ciphertexts[2])

	return res, resV
}
