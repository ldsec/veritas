package vche

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/blake2b"
	"math/big"
	"math/bits"
)

type Tag [2][]byte // A tag is a tuple (Delta, tau) in ({0,1}^*)^2

type PRFKey struct {
	K1 []byte
	K2 []byte
}

func NewPRFKey(keyLen int) PRFKey {
	K1 := make([]byte, keyLen)
	_, err := rand.Read(K1)
	if err != nil {
		panic(err)
	}

	K2 := make([]byte, keyLen)
	_, err = rand.Read(K2)
	if err != nil {
		panic(err)
	}

	return PRFKey{K1, K2}
}

func NewXOF(K []byte) blake2b.XOF {
	xof, err := blake2b.NewXOF(8, K)
	if err != nil {
		panic(err)
	}
	return xof
}

func PRF(xof blake2b.XOF, T uint64, xs ...interface{}) uint64 {
	maxValue := T
	var err interface{}
	mask := uint64(1<<uint64(bits.Len64(maxValue))) - 1
	b := make([]byte, 8)

	for round := uint64(0); ; round++ {
		xof.Reset()

		for _, x := range xs {
			switch tmp := x.(type) {
			case uint64:
				binary.BigEndian.PutUint64(b, tmp)
				_, err = xof.Write(b)
				if err != nil {
					panic(err)
				}
			case []byte:
				_, err = xof.Write(tmp)
				if err != nil {
					panic(err)
				}
			case Tag:
				_, err = xof.Write(tmp[0])
				if err != nil {
					panic(err)
				}
				_, err = xof.Write(tmp[1])
				if err != nil {
					panic(err)
				}
			case nil:
				continue
			default:
				panic(fmt.Errorf("unsupported PRF argument %p of type %t", x, x))
			}
		}

		binary.BigEndian.PutUint64(b, round) // Append current round to get fresh output
		_, err = xof.Write(b)
		if err != nil {
			panic(err)
		}

		_, err = xof.Read(b)
		if err != nil {
			panic(err)
		}

		r := mask & binary.BigEndian.Uint64(b)
		if r < maxValue {
			return r
		}
	}
}

func PRFEfficient(xof1, xof2 blake2b.XOF, T uint64, xs ...interface{}) uint64 {
	a, b, u, v := CFPRF(xof1, xof2, T, xs...)

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

	return res.Uint64()
}

func CFPRF(xof1, xof2 blake2b.XOF, T uint64, xs ...interface{}) (uint64, uint64, uint64, uint64) {
	// Split tags up
	v1 := make([]interface{}, len(xs)) // Input for PRF_1 (index tag)
	v2 := make([]interface{}, len(xs)) // Input for PRF_2 (dataset tag)
	for i, x := range xs {
		switch tmp := x.(type) {
		case Tag:
			v1[i] = tmp[1]
			v2[i] = tmp[0]
		case uint64:
			// secondary indexes (like in approach 1) are added to the index PRF and ignored by the dataset PRFs
			v1[i] = tmp
			v2[i] = nil
		default:
			panic(fmt.Errorf("unsupported PRF argument %p of type %t", tmp, tmp))
		}
	}

	argsU := make([]interface{}, len(v1), len(v1)+1)
	copy(argsU, v1)
	argsU = append(argsU, []byte("u"))
	u := PRF(xof1, T, argsU...) // u in Z_T

	argsV := make([]interface{}, len(v1), len(v1)+1)
	copy(argsV, v1)
	argsV = append(argsV, []byte("v"))
	v := PRF(xof1, T, argsV...) // v in Z_T

	argsA := make([]interface{}, len(v2), len(v2)+1)
	copy(argsA, v2)
	argsA = append(argsA, []byte("a"))
	a := PRF(xof2, T-1, argsA...) + 1 // a in Z_T^*

	argsB := make([]interface{}, len(v2), len(v2)+1)
	copy(argsB, v2)
	argsB = append(argsB, []byte("b"))
	b := PRF(xof1, T-1, argsB...) + 1 // b in Z_T^*

	return a, b, u, v
}
