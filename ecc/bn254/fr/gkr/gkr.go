// Copyright 2020 ConsenSys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by consensys/gnark-crypto DO NOT EDIT

package gkr

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/sumcheck"
)

// The goal is to prove/verify evaluations of many instances of the same circuit

// Gate must be a low-degree polynomial
type Gate interface {
	Evaluate(...fr.Element) fr.Element
	Degree() int
}

type Wire struct {
	Gate       Gate
	Inputs     []*Wire // if there are no Inputs, the wire is assumed an input wire
	NumOutputs int     // number of other wires using it as input, not counting doubles (i.e. providing two inputs to the same gate counts as one). By convention, equal to 1 for output wires
}
type CircuitLayer []Wire

// TODO: Constructor so that user doesn't have to give layers explicitly.
type Circuit []CircuitLayer

func (w *Wire) IsInput() bool {
	return len(w.Inputs) == 0
}

func (c Circuit) Size() int { //TODO: Worth caching?
	res := len(c[0])
	for i := range c {
		res += len(c[i])
	}
	return res
}

// WireAssignment is assignment of values to the same wire across many instances of the circuit
type WireAssignment map[*Wire]polynomial.MultiLin

type Proof [][]sumcheck.Proof // for each layer, for each wire, a sumcheck (for each variable, a polynomial)

type eqTimesGateEvalSumcheckLazyClaims struct {
	wire               *Wire
	evaluationPoints   [][]fr.Element
	claimedEvaluations []fr.Element
	manager            *claimsManager // WARNING: Circular references
}

func (e *eqTimesGateEvalSumcheckLazyClaims) ClaimsNum() int {
	return len(e.evaluationPoints)
}

func (e *eqTimesGateEvalSumcheckLazyClaims) VarsNum() int {
	return len(e.evaluationPoints[0])
}

func (e *eqTimesGateEvalSumcheckLazyClaims) CombinedSum(a fr.Element) fr.Element {
	evalsAsPoly := polynomial.Polynomial(e.claimedEvaluations)
	return evalsAsPoly.Eval(&a)
}

func (e *eqTimesGateEvalSumcheckLazyClaims) Degree(int) int {
	return 1 + e.wire.Gate.Degree()
}

func (e *eqTimesGateEvalSumcheckLazyClaims) VerifyFinalEval(r []fr.Element, combinationCoeff fr.Element, purportedValue fr.Element, proof interface{}) bool {
	inputEvaluations := proof.([]fr.Element)

	// defer verification, store the new claims
	e.manager.addForInput(e.wire, r, inputEvaluations)

	numClaims := len(e.evaluationPoints)

	evaluation := polynomial.EvalEq(e.evaluationPoints[numClaims-1], r)
	for i := numClaims - 2; i >= 0; i-- {
		evaluation.Mul(&evaluation, &combinationCoeff)
		eq := polynomial.EvalEq(e.evaluationPoints[i], r)
		evaluation.Add(&evaluation, &eq)
	}

	gateEvaluation := e.wire.Gate.Evaluate(inputEvaluations...)
	evaluation.Mul(&evaluation, &gateEvaluation)

	return evaluation.Equal(&purportedValue)
}

type eqTimesGateEvalSumcheckClaims struct {
	wire               *Wire
	evaluationPoints   [][]fr.Element // x in the paper
	claimedEvaluations []fr.Element   // y in the paper
	manager            *claimsManager

	inputPreprocessors []polynomial.MultiLin // P_u in the paper, so that we don't need to pass along all the circuit's evaluations

	eq polynomial.MultiLin // ∑_i τ_i eq(x_i, -)
}

func (c *eqTimesGateEvalSumcheckClaims) Combine(combinationCoeff fr.Element) polynomial.Polynomial {
	varsNum := c.VarsNum()
	eqLength := 1 << varsNum
	claimsNum := c.ClaimsNum()
	// initialize the eq tables
	c.eq = polynomial.Make(eqLength)

	c.eq[0].SetOne()
	c.eq.Eq(c.evaluationPoints[0])

	newEq := polynomial.MultiLin(polynomial.Make(eqLength))
	aI := combinationCoeff

	for k := 1; k < claimsNum; k++ { //TODO: parallelizable?
		// define eq_k = aᵏ eq(x_k1, ..., x_kn, *, ..., *) where x_ki are the evaluation points
		newEq[0].Set(&aI)
		newEq.Eq(c.evaluationPoints[k])

		eqAsPoly := polynomial.Polynomial(c.eq) //just semantics
		eqAsPoly.Add(eqAsPoly, polynomial.Polynomial(newEq))

		if k+1 < claimsNum {
			aI.Mul(&aI, &combinationCoeff) //TODO: Test this. newEq[0] maybe not preserving value?
		}
	}

	// from this point on the claim is a rather simple one: g = E(h) × R_v (P_u0(h), ...) where E and the P_u are multilinear and R_v is of low-degree

	return c.computeGJ()
}

// computeValAndStep returns val : i ↦ m(1, i...) and step : i ↦ m(1, i...) - m(0, i...)
func computeValAndStep(m polynomial.MultiLin) (val polynomial.MultiLin, step polynomial.MultiLin) {
	val = m[len(m)/2:].Clone()
	step = m[:len(m)/2].Clone()

	valAsPoly, stepAsPoly := polynomial.Polynomial(val), polynomial.Polynomial(step)

	stepAsPoly.Sub(valAsPoly, stepAsPoly)
	return
}

// computeGJ: gⱼ = ∑_{0≤i<2ⁿ⁻ʲ} g(r₁, r₂, ..., rⱼ₋₁, Xⱼ, i...) = ∑_{0≤i<2ⁿ⁻ʲ} E(r₁, ..., X_j, i...) R_v( P_u0(r₁, ..., X_j, i...), ... ) where  E = ∑ eq_k
// the polynomial is represented by the evaluations g_j(1), g_j(2), ..., g_j(deg(g_j)).
func (c *eqTimesGateEvalSumcheckClaims) computeGJ() (gJ polynomial.Polynomial) {

	// Let f ∈ { E(r₁, ..., X_j, d...) } ∪ {P_ul(r₁, ..., X_j, d...) }. It is linear in X_j, so f(m) = m×(f(1) - f(0)) + f(0), and f(0), f(1) are easily computed from the bookkeeping tables
	EVal, EStep := computeValAndStep(c.eq)

	puVal := make([]polynomial.MultiLin, len(c.inputPreprocessors))  //TODO: Make a two-dimensional array struct, and index it i-first rather than inputI first: would result in scanning memory access in the "d" loop and obviate the gateInput variable
	puStep := make([]polynomial.MultiLin, len(c.inputPreprocessors)) //TODO, ctd: the greater degGJ, the more this would matter

	for i, puI := range c.inputPreprocessors {
		puVal[i], puStep[i] = computeValAndStep(puI)
	}

	degGJ := 1 + c.wire.Gate.Degree() // guaranteed to be no smaller than the actual deg(g_j)
	gJ = make([]fr.Element, degGJ)

	gateInput := polynomial.Make(len(c.inputPreprocessors))
	for d := 0; d < degGJ; d++ {

		notLastIteration := d+1 < degGJ
		gJ[d].SetZero()

		for i := range EVal {

			for inputI := range puVal {
				gateInput[inputI].Set(&puVal[inputI][i])
				if notLastIteration {
					puVal[inputI][i].Add(&puVal[inputI][i], &puStep[inputI][i])
				}
			}

			// gJAtDI = gJ(d, i...)
			gJAtDI := c.wire.Gate.Evaluate(gateInput...)
			gJAtDI.Mul(&gJAtDI, &EVal[i])

			gJ[d].Add(&gJ[d], &gJAtDI)

			if notLastIteration {
				EVal[i].Add(&EVal[i], &EStep[i])
			}
		}
	}

	polynomial.Dump(EVal, EStep, gateInput)
	for inputI := range puVal {
		polynomial.Dump(puVal[inputI], puStep[inputI])
	}

	return
}

// Next first folds the "preprocessing" and "eq" polynomials then compute the new g_j
func (c *eqTimesGateEvalSumcheckClaims) Next(element fr.Element) polynomial.Polynomial {
	c.eq.Fold(element)
	for i := 0; i < len(c.inputPreprocessors); i++ {
		c.inputPreprocessors[i].Fold(element)
	}
	return c.computeGJ()
}

func (c *eqTimesGateEvalSumcheckClaims) VarsNum() int {
	return len(c.evaluationPoints[0])
}

func (c *eqTimesGateEvalSumcheckClaims) ClaimsNum() int {
	return len(c.claimedEvaluations)
}

func (c *eqTimesGateEvalSumcheckClaims) ProveFinalEval(r []fr.Element) interface{} {

	//defer the proof, return list of claims
	evaluations := make([]fr.Element, len(c.inputPreprocessors))
	for i, puI := range c.inputPreprocessors {
		puI.Fold(r[len(r)-1])

		if len(puI) != 1 {
			panic("must be one") //TODO: Remove
		}

		evaluations[i].Set(&puI[0])
		polynomial.Dump(puI)
	}
	// TODO: Make sure all is dumped
	polynomial.Dump(c.claimedEvaluations, c.eq)

	c.manager.addForInput(c.wire, r, evaluations)

	return evaluations
}

type claimsManager struct {
	claimsMap  map[*Wire]*eqTimesGateEvalSumcheckLazyClaims
	assignment WireAssignment
	numClaims  int
}

func newClaimsManager(c Circuit, assignment WireAssignment) (claims claimsManager) {
	claims.assignment = assignment
	claims.claimsMap = make(map[*Wire]*eqTimesGateEvalSumcheckLazyClaims, c.Size())

	for _, layer := range c {
		for i := 0; i < len(layer); i++ {
			wire := &layer[i]

			claims.claimsMap[wire] = &eqTimesGateEvalSumcheckLazyClaims{
				wire:               wire,
				evaluationPoints:   make([][]fr.Element, 0, wire.NumOutputs),
				claimedEvaluations: polynomial.Make(wire.NumOutputs),
				manager:            &claims,
			}
		}
	}
	return
}

func (m *claimsManager) add(wire *Wire, evaluationPoint []fr.Element, evaluation fr.Element) {
	m.numClaims++
	if m.numClaims%claimsPerLog == 0 {
		//fmt.Println("GKR:", m.numClaims, "total claims")
	}
	if wire.IsInput() {
		wire.Gate = IdentityGate{}
	}
	claim := m.claimsMap[wire]
	i := len(claim.evaluationPoints)
	claim.claimedEvaluations[i] = evaluation
	claim.evaluationPoints = append(claim.evaluationPoints, evaluationPoint)
}

// addForInput claims regarding all inputs to the wire, all evaluated at the same point
func (m *claimsManager) addForInput(wire *Wire, evaluationPoint []fr.Element, evaluations []fr.Element) {
	wiresWithClaims := make(map[*Wire]struct{}) // In case the gate takes the same wire as input multiple times, one claim would suffice

	for inputI, inputWire := range wire.Inputs {
		if _, found := wiresWithClaims[inputWire]; !found { //skip repeated claims
			wiresWithClaims[inputWire] = struct{}{}
			m.add(inputWire, evaluationPoint, evaluations[inputI])
		}
	}
}

func (m *claimsManager) getLazyClaim(wire *Wire) *eqTimesGateEvalSumcheckLazyClaims {
	return m.claimsMap[wire]
}

func (m *claimsManager) getClaim(wire *Wire) *eqTimesGateEvalSumcheckClaims {
	lazy := m.claimsMap[wire]
	res := &eqTimesGateEvalSumcheckClaims{
		wire:               wire,
		evaluationPoints:   lazy.evaluationPoints,
		claimedEvaluations: lazy.claimedEvaluations,
		manager:            m,
	}

	if wire.IsInput() {
		wire.Gate = IdentityGate{} // a bit dirty, modifying data structure given from outside
		res.inputPreprocessors = []polynomial.MultiLin{m.assignment[wire].Clone()}
	} else {
		res.inputPreprocessors = make([]polynomial.MultiLin, len(wire.Inputs))

		for inputI, inputW := range wire.Inputs {
			res.inputPreprocessors[inputI] = m.assignment[inputW].Clone() //will be edited later, so must be deep copied
		}
	}
	return res
}

const claimsPerLog = 2

func (m *claimsManager) deleteClaim(wire *Wire) {
	m.numClaims--
	if m.numClaims%claimsPerLog == 0 {
		//fmt.Println("GKR:", m.numClaims, "total claims")
	}
	delete(m.claimsMap, wire)
}

// Prove consistency of the claimed assignment
func Prove(c Circuit, assignment WireAssignment, transcript sumcheck.ArithmeticTranscript) Proof {
	claims := newClaimsManager(c, assignment)

	outLayer := c[0]

	proof := make(Proof, len(c))
	// firstChallenge called rho in the paper
	firstChallenge := transcript.NextN(assignment[&outLayer[0]].NumVars()) //TODO: Clean way to extract numVars

	for i := range outLayer {
		wire := &outLayer[i]
		claims.add(wire, firstChallenge, assignment[wire].Evaluate(firstChallenge))
	}

	//fmt.Println("GKR: Assigned first claims")

	for layerI, layer := range c {
		proof[layerI] = make([]sumcheck.Proof, len(layer))
		for wireI := 0; wireI < len(layer); wireI++ {
			wire := &layer[wireI]
			claim := claims.getClaim(wire)
			if wire.IsInput() && claim.ClaimsNum() == 1 || claim.ClaimsNum() == 0 { // no proof necessary
				proof[layerI][wireI] = sumcheck.Proof{
					PartialSumPolys: []polynomial.Polynomial{},
					FinalEvalProof:  []fr.Element{},
				}
			} else {
				proof[layerI][wireI] = sumcheck.Prove(claim, transcript)
				if finalEvalProof := proof[layerI][wireI].FinalEvalProof.([]fr.Element); len(finalEvalProof) != 0 {
					transcript.Update(sumcheck.ElementSliceToInterfaceSlice(finalEvalProof)...)
				}
			}
			// the verifier checks a single claim about input wires itself
			claims.deleteClaim(wire)
		}
	}

	return proof
}

// Verify the consistency of the claimed output with the claimed input
// Unlike in Prove, the assignment argument need not be complete
func Verify(c Circuit, assignment WireAssignment, proof Proof, transcript sumcheck.ArithmeticTranscript) bool {
	claims := newClaimsManager(c, assignment)

	outLayer := c[0]

	firstChallenge := transcript.NextN(assignment[&outLayer[0]].NumVars()) //TODO: Clean way to extract numVars

	for i := range outLayer {
		wire := &outLayer[i]
		claims.add(wire, firstChallenge, assignment[wire].Evaluate(firstChallenge))
	}

	for layerI, layer := range c {

		for wireI := range layer {
			wire := &layer[wireI]
			proofW := proof[layerI][wireI]
			finalEvalProof := proofW.FinalEvalProof.([]fr.Element)
			claim := claims.getLazyClaim(wire)
			if claimsNum := claim.ClaimsNum(); wire.IsInput() && claimsNum == 1 || claimsNum == 0 {
				// make sure the proof is empty
				if len(finalEvalProof) != 0 || len(proofW.PartialSumPolys) != 0 {
					return false
				}

				if claimsNum == 1 {
					// simply evaluate and see if it matches
					evaluation := assignment[wire].Evaluate(claim.evaluationPoints[0])
					if !claim.claimedEvaluations[0].Equal(&evaluation) {
						return false
					}
				}
			} else if !sumcheck.Verify(claim, proof[layerI][wireI], transcript) {
				return false //TODO: Any polynomials to dump?
			}
			if len(finalEvalProof) != 0 {
				transcript.Update(sumcheck.ElementSliceToInterfaceSlice(finalEvalProof)...)
			}
			claims.deleteClaim(wire)
		}
	}
	return true
}

type IdentityGate struct{}

func (IdentityGate) Evaluate(input ...fr.Element) fr.Element {
	return input[0]
}

func (IdentityGate) Degree() int {
	return 1
}
