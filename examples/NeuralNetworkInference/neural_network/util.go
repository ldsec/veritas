package neural_network

import (
	"encoding/csv"
	"fmt"
	"veritas/vche/vche"
	"veritas/vche/vche_2"
	"math"
	"os"
	"strconv"
	"testing"
)

type Model interface {
	// Hack to cope with Go's lack of generics
	// Encryption / Decryption
	Encryptor() vche.GenericEncryptor
	Decryptor() vche.GenericDecryptor
	// Encoding / Decoding
	Encoder() vche.GenericEncoder
	EncoderPlaintext() vche.GenericEncoderPlaintext
	// Evaluation
	Evaluator() vche.GenericEvaluator
	EvaluatorPlaintext() vche.GenericEvaluator
	// Other methods
	Parameters() vche.Parameters
	EncodeLayer() Layer
	EvalLayers() []Layer
}

type ModelParams struct {
	Encryptor          vche.GenericEncryptor
	Decryptor          vche.GenericDecryptor
	Encoder            vche.GenericEncoder
	EncoderVerif       vche.GenericEncoderPlaintext
	Evaluator          vche.GenericEvaluator
	EvaluatorPlaintext vche.GenericEvaluator
	Parameters         vche.Parameters
}

func Encode(model Model, img [][]uint64, tags [][]vche.Tag) []interface{} {
	in := struct {
		img [][]uint64
		tag [][]vche.Tag
	}{img, tags}
	var x interface{} = in
	x = model.EncodeLayer().Eval(x)
	return x.([]interface{})
}

func Eval(model Model, x interface{}) []interface{} {
	for _, l := range model.EvalLayers() {
		x = l.Eval(x)
	}
	return x.([]interface{})
}

func BenchEvalRequadProver(model Model, prover vche_2.Prover, verifier vche_2.Verifier, ctxt interface{}, verif interface{}, b *testing.B) (ctxt2 interface{}, verif2 interface{}, numCtxtsC_SP, numCtxtsSP_C int) {
	numCtxtsC_SP = 0
	numCtxtsSP_C = 0
	b.StartTimer()
	for _, layer := range model.EvalLayers() {
		switch l := layer.(type) {
		case Square:
			ctxt = l.Eval(ctxt)

			b.StopTimer()
			verif = l.Verif(verif)

			c := ctxt.(*vche_2.Ciphertext)
			if len(c.Ciphertexts) > 3 {
				numCtxtsSP_C += len(c.Ciphertexts) - 3
				numCtxtsC_SP += 2
			}
			b.StartTimer()

			ctxt, verif = vche_2.BenchmarkRequadratizationProtocolProver(prover, verifier, ctxt.(*vche_2.Ciphertext), verif.(*vche_2.Poly), b)
			b.StartTimer()
		default:
			ctxt = l.Eval(ctxt)
			b.StopTimer()
			verif = l.Verif(verif)
			b.StartTimer()
		}
	}
	return ctxt, verif, numCtxtsC_SP, numCtxtsSP_C
}

func BenchEvalRequadVerifier(model Model, prover vche_2.Prover, verifier vche_2.Verifier, ctxt interface{}, verif interface{}, b *testing.B) (interface{}, interface{}) {
	b.StartTimer()
	for _, layer := range model.EvalLayers() {
		switch l := layer.(type) {
		case Square:
			b.StopTimer()
			ctxt = l.Eval(ctxt)
			b.StartTimer()

			verif = l.Verif(verif)

			ctxt, verif = vche_2.BenchmarkRequadratizationProtocolVerifier(prover, verifier, ctxt.(*vche_2.Ciphertext), verif.(*vche_2.Poly), b)
			b.StartTimer()
		default:
			b.StopTimer()
			ctxt = l.Eval(ctxt)
			b.StartTimer()

			verif = l.Verif(verif)
		}
	}
	return ctxt, verif
}

func EncVerif(model Model, tags [][]vche.Tag) []interface{} {
	var x interface{} = tags
	x = model.EncodeLayer().Verif(x)
	return x.([]interface{})
}

func Verif(model Model, x interface{}) []interface{} {
	for _, l := range model.EvalLayers() {
		x = l.Verif(x)
	}
	return x.([]interface{})
}

func Dec(model Model, ctxts []interface{}, verif []interface{}) []float64 {
	preds := make([]float64, len(ctxts))

	outScale := model.EvalLayers()[len(model.EvalLayers())-1].OutputScale()
	sum := 0.0
	for i := range ctxts {
		ptxt := model.Decryptor().DecryptNew(ctxts[i])
		var currVerif interface{}
		if verif != nil {
			currVerif = verif[i]
		}
		vals := model.Encoder().DecodeIntNew(ptxt, currVerif)
		preds[i] = float64(vals[0]) / float64(outScale)
		sum += preds[i]
	}
	return preds
}

func DecPolyProtocol(model Model, prover vche_2.Prover, verifier vche_2.Verifier, ctxts []interface{}, verif []interface{}) []float64 {
	preds := make([]float64, len(ctxts))

	outScale := model.EvalLayers()[len(model.EvalLayers())-1].OutputScale()
	sum := 0.0
	for i := range ctxts {
		var currVerif interface{}
		if verif != nil {
			currVerif = verif[i]
		}

		vals := vche_2.RunPolynomialProtocolUint(prover, verifier, ctxts[i].(*vche_2.Ciphertext), currVerif.(*vche_2.Poly))

		preds[i] = float64(vals[0]) / float64(outScale)
		sum += preds[i]
	}
	return preds
}

func Reshape2D(v []uint64, m, n int) [][]uint64 {
	if len(v) != m*n {
		panic("mismatch in lengths")
	}
	res := make([][]uint64, m)
	for i := range res {
		res[i] = make([]uint64, n)
		copy(res[i], v[i*n:(i+1)*n])
	}
	return res
}

func Reshape3D(v []uint64, l, m, n int) [][][]uint64 {
	if len(v) != l*m*n {
		panic("mismatch in lengths")
	}
	res := make([][][]uint64, l)
	for i := range res {
		res[i] = make([][]uint64, m)
		for j := range res[i] {
			res[i][j] = make([]uint64, n)
			copy(res[i][j], v[i*m*n+j*n:i*m*n+(j+1)*n])
		}
	}
	return res
}

func Rescale(params vche.Parameters, v []float64, scale uint64) []uint64 {
	res := make([]uint64, len(v))
	modulusHalf := params.T() >> 1
	for i := range v {
		scaled := int64(float64(scale) * v[i]) // TODO: correct rounding
		if scaled < 0 {
			if scaled < -int64(modulusHalf) {
				panic("encoding error")
			}
			res[i] = uint64(int64(params.T()) + scaled)
		} else {
			if scaled > int64(modulusHalf) {
				panic("encoding error")
			}
			res[i] = uint64(scaled)
		}
	}
	return res
}

func Transpose(v []float64, inSize, outMaps int) []float64 {
	res := make([]float64, len(v))
	for i := 0; i < inSize; i++ {
		for j := 0; j < outMaps; j++ {
			res[i+inSize*j] = v[outMaps*i+j]
		}
	}
	return res
}

func GetImage() [][]uint64 {
	return [][]uint64{
		{0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 12, 7, 0, 0, 12, 0, 0, 1, 6, 0, 0, 5, 3, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 15, 7, 0, 0, 14, 16, 0, 0, 0, 2, 3, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 7, 1, 0, 0, 8, 12, 0, 1, 0, 12, 1, 0, 0, 6, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 1, 6, 0, 0, 9, 0, 0, 19, 0, 9, 4, 0, 0, 2, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 17, 20, 55, 145, 159, 129, 24, 0, 0, 11, 4, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 15, 0, 15, 129, 249, 255, 249, 255, 241, 131, 8, 0, 6, 4, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 74, 228, 255, 251, 209, 217, 226, 255, 229, 45, 0, 0, 0, 4, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 138, 229, 255, 226, 136, 18, 0, 165, 246, 255, 55, 1, 5, 0, 0, 0, 0, 0, 0},
		{1, 0, 4, 0, 0, 2, 0, 0, 0, 215, 246, 250, 62, 0, 0, 3, 154, 251, 248, 62, 6, 3, 0, 0, 0, 0, 0, 0},
		{0, 0, 3, 0, 1, 3, 0, 9, 115, 249, 253, 99, 0, 9, 4, 0, 170, 255, 248, 41, 15, 0, 5, 5, 0, 0, 0, 0},
		{0, 0, 2, 1, 4, 3, 0, 32, 224, 253, 180, 10, 0, 10, 1, 0, 83, 224, 255, 180, 16, 3, 6, 0, 0, 0, 0, 0},
		{0, 0, 0, 2, 3, 2, 0, 65, 255, 245, 66, 11, 5, 1, 0, 0, 4, 174, 248, 255, 36, 3, 0, 5, 0, 0, 0, 0},
		{0, 2, 0, 2, 1, 0, 0, 109, 255, 222, 14, 1, 0, 0, 7, 0, 7, 152, 255, 240, 172, 12, 0, 11, 0, 0, 0, 0},
		{0, 4, 0, 2, 0, 0, 3, 162, 247, 137, 11, 0, 0, 0, 0, 2, 10, 99, 255, 254, 243, 23, 9, 0, 0, 0, 0, 0},
		{0, 5, 0, 2, 0, 4, 17, 213, 249, 60, 3, 0, 11, 0, 0, 9, 1, 47, 251, 255, 169, 1, 13, 0, 0, 0, 0, 0},
		{0, 5, 0, 3, 0, 8, 28, 246, 255, 57, 0, 6, 0, 1, 1, 0, 0, 55, 255, 246, 162, 5, 1, 0, 0, 0, 0, 0},
		{0, 4, 0, 8, 1, 0, 0, 171, 255, 123, 10, 0, 0, 12, 5, 0, 14, 36, 255, 242, 163, 7, 0, 5, 0, 0, 0, 0},
		{0, 8, 0, 2, 0, 0, 6, 166, 251, 207, 5, 0, 0, 3, 0, 5, 0, 62, 234, 255, 84, 7, 0, 0, 0, 0, 0, 0},
		{0, 9, 0, 0, 0, 2, 5, 130, 255, 244, 71, 0, 14, 0, 0, 13, 2, 71, 255, 233, 31, 0, 6, 0, 0, 0, 0, 0},
		{0, 6, 0, 3, 2, 4, 0, 68, 245, 255, 174, 3, 0, 8, 19, 0, 22, 244, 242, 154, 19, 0, 0, 8, 0, 0, 0, 0},
		{0, 4, 0, 2, 6, 6, 0, 20, 223, 255, 222, 154, 45, 0, 0, 56, 165, 248, 242, 35, 0, 0, 13, 0, 0, 0, 0, 0},
		{4, 2, 0, 0, 4, 5, 0, 5, 86, 249, 255, 255, 245, 224, 233, 223, 253, 219, 33, 1, 0, 13, 0, 0, 0, 0, 0, 0},
		{4, 0, 0, 1, 0, 0, 5, 2, 0, 139, 216, 252, 253, 230, 255, 252, 208, 37, 0, 0, 3, 11, 0, 0, 0, 0, 0, 0},
		{0, 0, 3, 7, 0, 0, 3, 0, 9, 0, 10, 109, 137, 255, 229, 127, 12, 0, 0, 7, 0, 0, 0, 9, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}
}

func readWeights(path string, res []float64) []float64 {
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		panic(err)
	}
	if len(records) > 1 {
		panic(fmt.Errorf("expected a single line from CSV file"))
	}

	if len(records[0]) != len(res) {
		panic(fmt.Errorf("mismatched number of parameters read from %s: expected %d, got %d", path, len(res), len(records[0])))
	}
	for i := range res {
		res[i], err = strconv.ParseFloat(records[0][i], 64)
		if err != nil {
			panic(err)
		}
	}
	return res
}

func nextPow2(x int) int {
	return 1 << uint(math.Ceil(math.Log2(float64(x))))
}
