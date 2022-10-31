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

package test_vector_utils

import (
	"encoding/json"
	"fmt"
	"github.com/consensys/gnark-crypto/internal/generator/test_vector_utils/small_rational"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

type ElementTriplet struct {
	key1        small_rational.SmallRational
	key2        small_rational.SmallRational
	key2Present bool
	value       small_rational.SmallRational
	used        bool
}

func (t *ElementTriplet) CmpKey(o *ElementTriplet) int {
	if cmp1 := t.key1.Cmp(&o.key1); cmp1 != 0 {
		return cmp1
	}

	if t.key2Present {
		if o.key2Present {
			return t.key2.Cmp(&o.key2)
		}
		return 1
	} else {
		if o.key2Present {
			return -1
		}
		return 0
	}
}

var hashCache = make(map[string]HashMap)

func GetHash(path string) (HashMap, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if h, ok := hashCache[path]; ok {
		return h, nil
	}
	var bytes []byte
	if bytes, err = os.ReadFile(path); err == nil {
		var asMap map[string]interface{}
		if err = json.Unmarshal(bytes, &asMap); err != nil {
			return nil, err
		}

		res := make(HashMap, 0, len(asMap))

		for k, v := range asMap {
			var entry ElementTriplet
			if _, err = entry.value.SetInterface(v); err != nil {
				return nil, err
			}

			key := strings.Split(k, ",")

			switch len(key) {
			case 1:
				entry.key2Present = false
			case 2:
				entry.key2Present = true
				if _, err = entry.key2.SetInterface(key[1]); err != nil {
					return nil, err
				}
			default:
				return nil, fmt.Errorf("cannot parse %T as one or two field elements", v)
			}
			if _, err = entry.key1.SetInterface(key[0]); err != nil {
				return nil, err
			}

			res = append(res, &entry)
		}

		res.sort()

		hashCache[path] = res

		return res, nil

	} else {
		return nil, err
	}
}

type HashMap []*ElementTriplet

func (t *ElementTriplet) writeKeyValue(sb *strings.Builder) error {
	sb.WriteString("\t\"")
	sb.WriteString(t.key1.String())
	if t.key2Present {
		sb.WriteRune(',')
		sb.WriteString(t.key2.String())
	}
	sb.WriteString("\":")
	var value interface{}
	var valueBytes []byte
	var err error

	if value, err = ElementToInterface(&t.value); err != nil {
		return err
	}
	if valueBytes, err = json.Marshal(value); err != nil {
		return err
	}
	sb.WriteString(string(valueBytes))
	return nil
}

func (m *HashMap) SaveUsedEntries(path string) error {

	var sb strings.Builder
	sb.WriteRune('[')

	first := true

	for _, element := range *m {
		if !element.used {
			continue
		}
		if !first {
			sb.WriteRune(',')
		}
		first = false
		sb.WriteString("\n\t")
		if err := element.writeKeyValue(&sb); err != nil {
			return err
		}
	}

	if !first {
		sb.WriteRune(',')
	}

	sb.WriteString("\n]")

	return os.WriteFile(path, []byte(sb.String()), 0)
}

func (m *HashMap) sort() {
	sort.Slice(*m, func(i, j int) bool {
		return (*m)[i].CmpKey((*m)[j]) <= 0
	})
}

func (m *HashMap) find(toFind *ElementTriplet) small_rational.SmallRational {
	i := sort.Search(len(*m), func(i int) bool { return (*m)[i].CmpKey(toFind) >= 0 })

	if i < len(*m) && (*m)[i].CmpKey(toFind) == 0 {
		(*m)[i].used = true
		return (*m)[i].value
	}
	// if not found, add it:
	if _, err := toFind.value.SetInterface(rand.Int63n(11) - 5); err != nil {
		panic(err.Error())
	}
	toFind.used = true
	*m = append(*m, toFind)
	m.sort() //Inefficient, but it's okay. This is only run when a new test case is introduced

	return toFind.value
}

func (m *HashMap) findPair(x *small_rational.SmallRational, y *small_rational.SmallRational) small_rational.SmallRational {

	toFind := ElementTriplet{
		key1:        *x,
		key2Present: y != nil,
	}

	if y != nil {
		toFind.key2 = *y
	}

	return m.find(&toFind)
}

type MapHashTranscript struct {
	HashMap         HashMap
	stateValid      bool
	resultAvailable bool
	state           small_rational.SmallRational
}

func (m *MapHashTranscript) Update(i ...interface{}) {
	if len(i) > 0 {
		for _, x := range i {

			var xElement small_rational.SmallRational
			if _, err := xElement.SetInterface(x); err != nil {
				panic(err.Error())
			}
			if m.stateValid {
				m.state = m.HashMap.findPair(&xElement, &m.state)
			} else {
				m.state = m.HashMap.findPair(&xElement, nil)
			}

			m.stateValid = true
		}
	} else { //just hash the state itself
		if !m.stateValid {
			panic("nothing to hash")
		}
		m.state = m.HashMap.findPair(&m.state, nil)
	}
	m.resultAvailable = true
}

func (m *MapHashTranscript) Next(i ...interface{}) small_rational.SmallRational {

	if len(i) > 0 || !m.resultAvailable {
		m.Update(i...)
	}
	m.resultAvailable = false
	return m.state
}

func (m *MapHashTranscript) NextN(N int, i ...interface{}) []small_rational.SmallRational {

	if len(i) > 0 {
		m.Update(i...)
	}

	res := make([]small_rational.SmallRational, N)

	for n := range res {
		res[n] = m.Next()
	}

	return res
}

func SliceToElementSlice(slice []interface{}) ([]small_rational.SmallRational, error) {
	elementSlice := make([]small_rational.SmallRational, len(slice))
	for i, v := range slice {
		if _, err := elementSlice[i].SetInterface(v); err != nil {
			return nil, err
		}
	}
	return elementSlice, nil
}

func SliceEquals(a []small_rational.SmallRational, b []small_rational.SmallRational) error {
	if len(a) != len(b) {
		return fmt.Errorf("length mismatch %d≠%d", len(a), len(b))
	}
	for i := range a {
		if !a[i].Equal(&b[i]) {
			return fmt.Errorf("at index %d: %s ≠ %s", i, a[i].String(), b[i].String())
		}
	}
	return nil
}

func ElementToInterface(x *small_rational.SmallRational) (interface{}, error) {
	text := x.Text(10)
	if len(text) < 10 && !strings.Contains(text, "/") {
		return strconv.Atoi(text)
	}
	return text, nil
}

func ElementSliceToInterfaceSlice(x interface{}) ([]interface{}, error) {
	if x == nil {
		return nil, nil
	}

	X := reflect.ValueOf(x)

	res := make([]interface{}, X.Len())
	var err error
	for i := range res {
		xI := X.Index(i).Interface().(small_rational.SmallRational)
		if res[i], err = ElementToInterface(&xI); err != nil {
			return nil, err
		}
	}
	return res, nil
}

func ElementSliceSliceToInterfaceSliceSlice(x interface{}) ([][]interface{}, error) {
	if x == nil {
		return nil, nil
	}

	X := reflect.ValueOf(x)

	res := make([][]interface{}, X.Len())
	var err error
	for i := range res {
		if res[i], err = ElementSliceToInterfaceSlice(X.Index(i).Interface()); err != nil {
			return nil, err
		}
	}

	return res, nil
}
