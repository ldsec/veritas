package vche

import (
	"github.com/ldsec/lattigo/v2/utils"
	"math/big"
)

type BivariatePoly struct {
	Coeffs [][]uint64
	T      uint64
}

func NewBivariatePoly(degree int, T uint64) BivariatePoly {
	coeffs := make([][]uint64, degree+1)
	for i := range coeffs {
		coeffs[i] = make([]uint64, degree+1)
	}
	return BivariatePoly{coeffs, T}
}

func (p BivariatePoly) GetCoeff(i, j int) uint64 {
	return p.Coeffs[i][j]
}

func (p BivariatePoly) SetCoeff(i, j int, val uint64) {
	p.Coeffs[i][j] = val
}

func (p BivariatePoly) Degree() int {
	return len(p.Coeffs) - 1
}

func (p BivariatePoly) Copy() BivariatePoly {
	res := NewBivariatePoly(p.Degree(), p.T)
	for i := range p.Coeffs {
		for j, val := range p.Coeffs[i] {
			res.SetCoeff(i, j, val)
		}
	}
	return res
}

func BivariatePolyAdd(p0, p1 []BivariatePoly) []BivariatePoly {
	outDegree := utils.MaxInt(p0[0].Degree(), p1[0].Degree())
	outPoly := make([]BivariatePoly, len(p0))
	T := p0[0].T
	for i := range outPoly {
		outPoly[i] = NewBivariatePoly(outDegree, T)
		for idxU := range p0[i].Coeffs {
			for idxV, val := range p0[i].Coeffs[idxU] {
				outPoly[i].SetCoeff(idxU, idxV, val)
			}
		}
		for idxU := range p1[i].Coeffs {
			for idxV, val := range p1[i].Coeffs[idxU] {
				newCoeff := big.NewInt(0)
				newCoeff.Add(
					big.NewInt(0).SetUint64(val),
					big.NewInt(0).SetUint64(outPoly[i].GetCoeff(idxU, idxV)))
				newCoeff.Mod(newCoeff, big.NewInt(0).SetUint64(T))
				outPoly[i].SetCoeff(idxU, idxV, newCoeff.Uint64())
			}
		}
	}
	return outPoly
}

func BivariatePolyAddNoMod(p0, p1 []BivariatePoly) []BivariatePoly {
	outDegree := utils.MaxInt(p0[0].Degree(), p1[0].Degree())
	outPoly := make([]BivariatePoly, len(p0))
	T := p0[0].T
	for i := range outPoly {
		outPoly[i] = NewBivariatePoly(outDegree, T)
		for idxU := range p0[i].Coeffs {
			for idxV, val := range p0[i].Coeffs[idxU] {
				outPoly[i].SetCoeff(idxU, idxV, val)
			}
		}
		for idxU := range p1[i].Coeffs {
			for idxV, val := range p1[i].Coeffs[idxU] {
				newCoeff := big.NewInt(0)
				newCoeff.Add(
					big.NewInt(0).SetUint64(val),
					big.NewInt(0).SetUint64(outPoly[i].GetCoeff(idxU, idxV)))
				outPoly[i].SetCoeff(idxU, idxV, newCoeff.Uint64())
			}
		}
	}
	return outPoly
}

func BivariatePolySub(p0, p1 []BivariatePoly) []BivariatePoly {
	outDegree := utils.MaxInt(p0[0].Degree(), p1[0].Degree())
	outPoly := make([]BivariatePoly, len(p0))
	T := p0[0].T
	for i := range outPoly {
		outPoly[i] = NewBivariatePoly(outDegree, T)
		for idxU := range p0[i].Coeffs {
			for idxV, val := range p0[i].Coeffs[idxU] {
				outPoly[i].SetCoeff(idxU, idxV, val)
			}
		}
		for idxU := range p1[i].Coeffs {
			for idxV, val := range p1[i].Coeffs[idxU] {
				newCoeff := big.NewInt(0)
				newCoeff.Sub(
					big.NewInt(0).SetUint64(outPoly[i].GetCoeff(idxU, idxV)),
					big.NewInt(0).SetUint64(val))
				newCoeff.Mod(newCoeff, big.NewInt(0).SetUint64(T))
				outPoly[i].SetCoeff(idxU, idxV, newCoeff.Uint64())
			}
		}
	}
	return outPoly
}

func BivariatePolySubNoMod(p0, p1 []BivariatePoly) []BivariatePoly {
	outDegree := utils.MaxInt(p0[0].Degree(), p1[0].Degree())
	outPoly := make([]BivariatePoly, len(p0))
	T := p0[0].T
	for i := range outPoly {
		outPoly[i] = NewBivariatePoly(outDegree, T)
		for idxU := range p0[i].Coeffs {
			for idxV, val := range p0[i].Coeffs[idxU] {
				outPoly[i].SetCoeff(idxU, idxV, val)
			}
		}
		for idxU := range p1[i].Coeffs {
			for idxV, val := range p1[i].Coeffs[idxU] {
				var res uint64
				if outPoly[i].GetCoeff(idxU, idxV) < val {
					newCoeff := big.NewInt(0)
					newCoeff.Sub(
						big.NewInt(0).SetUint64(T),
						big.NewInt(0).SetUint64(val))
					newCoeff.Add(
						newCoeff,
						big.NewInt(0).SetUint64(outPoly[i].GetCoeff(idxU, idxV)))
					res = newCoeff.Uint64()
				} else {
					newCoeff := big.NewInt(0)
					newCoeff.Sub(big.NewInt(0).SetUint64(outPoly[i].GetCoeff(idxU, idxV)),
						big.NewInt(0).SetUint64(val))
					res = newCoeff.Uint64()
				}
				outPoly[i].SetCoeff(idxU, idxV, res)
			}
		}
	}
	return outPoly
}

func BivariatePolyNeg(p []BivariatePoly) []BivariatePoly {
	outDegree := p[0].Degree()
	outPoly := make([]BivariatePoly, len(p))
	T := p[0].T
	bigT := big.NewInt(0).SetUint64(T)
	for i := range outPoly {
		outPoly[i] = NewBivariatePoly(outDegree, T)
		for idxU := range p[i].Coeffs {
			for idxV, val := range p[i].Coeffs[idxU] {
				newCoeff := big.NewInt(0)
				newCoeff.Sub(bigT, big.NewInt(0).SetUint64(val))
				newCoeff.Mod(newCoeff, bigT)
				outPoly[i].SetCoeff(idxU, idxV, newCoeff.Uint64())
			}
		}
	}
	return outPoly
}

func BivariatePolyMulScalar(p []BivariatePoly, scalar uint64) []BivariatePoly {
	outDegree := p[0].Degree()
	outPoly := make([]BivariatePoly, len(p))
	T := p[0].T
	for i := range outPoly {
		outPoly[i] = NewBivariatePoly(outDegree, T)
		for idxU := range p[i].Coeffs {
			for idxV, val := range p[i].Coeffs[idxU] {
				newCoeff := big.NewInt(0)
				newCoeff.Mul(big.NewInt(0).SetUint64(scalar), big.NewInt(0).SetUint64(val))
				newCoeff.Mod(newCoeff, big.NewInt(0).SetUint64(T))
				outPoly[i].SetCoeff(idxU, idxV, newCoeff.Uint64())
			}
		}
	}
	return outPoly
}

func BivariatePolyMul(p0, p1 []BivariatePoly) []BivariatePoly {
	outDegree := p0[0].Degree() + p1[0].Degree()
	outPoly := make([]BivariatePoly, len(p0))
	T := p0[0].T
	for idx := range outPoly {
		outPoly[idx] = NewBivariatePoly(outDegree, T)
		for i := 0; i <= outPoly[idx].Degree(); i++ {
			for j := 0; j <= outPoly[idx].Degree(); j++ {
				for k := 0; k <= i; k++ {
					for l := 0; l <= j; l++ {
						if k <= p0[idx].Degree() && i-k <= p1[idx].Degree() && l <= p0[idx].Degree() && j-l <= p1[idx].Degree() {
							newCoeff := big.NewInt(0)
							newCoeff.Mul(
								big.NewInt(0).SetUint64(p0[idx].GetCoeff(k, l)),
								big.NewInt(0).SetUint64(p1[idx].GetCoeff(i-k, j-l)))
							newCoeff.Mod(newCoeff, big.NewInt(0).SetUint64(T))
							newCoeff.Add(newCoeff, big.NewInt(0).SetUint64(outPoly[idx].GetCoeff(i, j)))
							newCoeff.Mod(newCoeff, big.NewInt(0).SetUint64(T))
							outPoly[idx].SetCoeff(i, j, newCoeff.Uint64())
						}
					}
				}
			}
		}
	}
	return outPoly
}
