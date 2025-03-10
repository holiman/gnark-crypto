package bls12381

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/internal/fptower"
)

func GeneratePointNotInG1(f fp.Element) G1Jac {
	return fuzzCofactorOfG1(f)
}

func fuzzCofactorOfG1(f fp.Element) G1Jac {
	var res, jac G1Jac
	aff := MapToCurve1(&f)
	g1Isogeny(&aff)
	jac.FromAffine(&aff)
	// p+x²ϕ(p) = [r]p
	res.phi(&jac).
		mulBySeed(&res).
		mulBySeed(&res).
		AddAssign(&jac)
	return res
}

func GeneratePointNotInG2(f1, f2 fp.Element) G2Jac {
	return fuzzCofactorOfG2(E2{f1, f2})
}

func fuzzCofactorOfG2(f fptower.E2) G2Jac {
	var res, jac G2Jac
	aff := MapToCurve2(&f)
	g2Isogeny(&aff)
	jac.FromAffine(&aff)
	// ψ(p)-[x₀]P = [r]p
	res.mulBySeed(&jac)
	jac.psi(&jac)
	res.AddAssign(&jac)
	return res
}
