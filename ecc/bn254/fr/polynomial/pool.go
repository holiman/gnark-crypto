package polynomial

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"reflect"
	"sync"
	"unsafe"
)

// Memory management for polynomials
// Copied verbatim from gkr repo

// Sets a maximum for the array size we keep in pool
const maxNForLargePool int = 1 << 24
const maxNForSmallPool int = 256

// Aliases because it is annoying to use arrays in all the places
type largeArr = [maxNForLargePool]fr.Element
type smallArr = [maxNForSmallPool]fr.Element

var rC = sync.Map{}

var (
	largePool = sync.Pool{
		New: func() interface{} {
			var res largeArr
			return &res
		},
	}
	smallPool = sync.Pool{
		New: func() interface{} {
			var res smallArr
			return &res
		},
	}
)

// ClearPool Clears the pool completely, shields against memory leaks
// Eg: if we forgot to dump a polynomial at some point, this will ensure the value get dumped eventually
// Returns how many polynomials were cleared that way
func ClearPool() int {
	res := 0
	rC.Range(func(k, _ interface{}) bool {
		switch ptr := k.(type) {
		case *largeArr:
			largePool.Put(ptr)
		case *smallArr:
			smallPool.Put(ptr)
		default:
			panic(fmt.Sprintf("tried to clear %v", reflect.TypeOf(ptr)))
		}
		res++
		return true
	})
	return res
}

// CountPool Returns the number of elements in the pool without mutating it
func CountPool() int {
	res := 0
	rC.Range(func(_, _ interface{}) bool {
		res++
		return true
	})
	return res
}

// Make tries to find a reusable polynomial or allocates a new one
func Make(n int) []fr.Element {
	if n > maxNForLargePool {
		panic(fmt.Sprintf("been provided with size of %v but the maximum is %v", n, maxNForLargePool))
	}

	if n <= maxNForSmallPool {
		ptr := smallPool.Get().(*smallArr)
		rC.Store(ptr, struct{}{}) // registers the pointer being used
		return (*ptr)[:n]
	}

	ptr := largePool.Get().(*largeArr)
	rC.Store(ptr, struct{}{}) // remember we allocated the pointer is being used
	return (*ptr)[:n]
}

// Dump dumps a set of polynomials into the pool
// Returns the number of deallocated polys
func Dump(arrs ...[]fr.Element) int {
	cnt := 0
	for _, arr := range arrs {
		ptr := ptr(arr)
		pool := &smallPool
		if len(arr) > maxNForSmallPool {
			pool = &largePool
		}
		// If the rC did not register, then
		// either the array was allocated somewhere else which can be ignored
		// otherwise a double put which MUST be ignored
		if _, ok := rC.Load(ptr); ok {
			pool.Put(ptr)
			// And deregisters the ptr
			rC.Delete(ptr)
			cnt++
		}
	}
	return cnt
}

func ptr(m []fr.Element) unsafe.Pointer {
	if cap(m) != maxNForSmallPool && cap(m) != maxNForLargePool {
		panic(fmt.Sprintf("can't cast to large or small array, the put array's is %v it should have capacity %v or %v", cap(m), maxNForLargePool, maxNForSmallPool))
	}
	return unsafe.Pointer(&m[0])
}
