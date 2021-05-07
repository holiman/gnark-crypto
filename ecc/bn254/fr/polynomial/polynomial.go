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

package polynomial

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/internal/parallel"
	"github.com/consensys/gnark-crypto/polynomial"
)

func FromInterface(i1 interface{}) fr.Element {

	var val fr.Element

	switch c1 := i1.(type) {
	case fr.Element:
		val.Set(&c1)
	case *fr.Element:
		val.Set(c1)
	case big.Int:
		val.SetBigInt(&c1)
	case *big.Int:
		val.SetBigInt(c1)
	case uint64:
		val.SetUint64(c1)
	case string:
		val.SetString(c1)
	case []byte:
		val.SetBytes(c1)
	default:
		panic("unsupported type")
	}

	return val
}

// Polynomial polynomial represented by coefficients bn254 fr field.
type Polynomial []fr.Element

// Degree returns the degree of the polynomial, which is the length of Data.
func (p *Polynomial) Degree() uint64 {
	res := uint64(len(*p) - 1)
	return res
}

// Eval evaluates p at v
func (p *Polynomial) Eval(v interface{}) interface{} {

	var res fr.Element

	_v := FromInterface(v)
	_p := *p

	s := len(_p)
	res.Set(&_p[s-1])
	for i := s - 2; i >= 0; i-- {
		res.Mul(&res, &_v)
		res.Add(&res, &_p[i])
	}
	return &res
}

// Clone returns a copy of the polynomial
func (p *Polynomial) Clone() polynomial.Polynomial {
	_pCopy := make(Polynomial, len(*p))
	copy(_pCopy, *p)
	return &_pCopy
}

// AddConstantInPlace adds a constant to the polynomial, modifying p
func (p *Polynomial) AddConstantInPlace(c interface{}) {

	_c := FromInterface(c)
	_p := *p

	parallel.Execute(len(_p), func(start, end int) {
		for i := start; i < end; i++ {
			_p[i].Add(&_p[i], &_c)
		}
	})

}

// AddConstantInPlace subs a constant to the polynomial, modifying p
func (p *Polynomial) SubConstantInPlace(c interface{}) {

	_c := FromInterface(c)
	_p := *p

	parallel.Execute(len(_p), func(start, end int) {
		for i := start; i < end; i++ {
			_p[i].Sub(&_p[i], &_c)
		}
	})
}

// ScaleInPlace multiplies p by v, modifying p
func (p *Polynomial) ScaleInPlace(c interface{}) {

	_c := FromInterface(c)
	_p := *p

	parallel.Execute(len(_p), func(start, end int) {
		for i := start; i < end; i++ {
			_p[i].Mul(&_p[i], &_c)
		}
	})
}

// Add adds p1 to p, modifying p.
// This function allocates a new slice each times it is called.
func (p *Polynomial) Add(p1, p2 polynomial.Polynomial) polynomial.Polynomial {

	_p1 := *(p1).(*Polynomial)
	_p2 := *(p2.(*Polynomial))

	// if p is one of the operand and is the polynomial of greatest degree, no allocation is needed
	if p == p1 && len(_p1) > len(_p2) {
		parallel.Execute(len(_p2), func(start, end int) {
			for i := start; i < end; i++ {
				_p1[i].Add(&_p1[i], &_p2[i])
			}
		})
		return p
	}
	if p == p2 && len(_p2) > len(_p1) {
		parallel.Execute(len(_p1), func(start, end int) {
			for i := start; i < end; i++ {
				_p2[i].Add(&_p1[i], &_p2[i])
			}
		})
		return p
	}

	// here p is not one of the operand, we allocate a new polynomial
	maxSize := len(_p1)
	if maxSize < len(_p2) {
		maxSize = len(_p2)
	}
	res := make(Polynomial, maxSize)
	if len(_p1) < len(_p2) {
		copy(res, _p2)
		parallel.Execute(len(_p1), func(start, end int) {
			for i := start; i < end; i++ {
				res[i].Add(&_p1[i], &_p2[i])
			}
		})
	} else {
		copy(res, _p1)
		parallel.Execute(len(_p2), func(start, end int) {
			for i := start; i < end; i++ {
				res[i].Add(&_p1[i], &_p2[i])
			}
		})
	}

	*p = res
	return &res

}

// Equal checks equality between two polynomials
func (p *Polynomial) Equal(p1 polynomial.Polynomial) bool {

	_p1 := *(p1).(*Polynomial)
	_p := *p

	if len(_p1) != len(_p) {
		return false
	}

	for i := 0; i < len(_p1); i++ {
		if !_p1[i].Equal(&_p[i]) {
			return false
		}
	}
	return true

}
