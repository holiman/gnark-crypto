package bls381

import (
	"fmt"
	"testing"

	"github.com/consensys/gurvy/bls381/fr"
)

func TestG2JacToAffineFromJac(t *testing.T) {

	p := testPointsG2()

	_p := G2Affine{}
	_p.FromJacobian(&p[0])
	if !_p.X.Equal(&p[1].X) || !_p.Y.Equal(&p[1].Y) {
		t.Fatal("ToAffineFromJac failed")
	}

}

func TestG2JacAdd(t *testing.T) {

	p := testPointsG2()

	// p3 = p1 + p2
	p1 := p[1].Clone()
	_p2 := G2Affine{}
	_p2.FromJacobian(&p[2])
	p[1].AddMixed(&_p2)
	p[2].AddAssign(p1)

	if !p[3].Equal(&p[1]) {
		t.Fatal("Add failed")
	}

	// test commutativity
	if !p[3].Equal(&p[2]) {
		t.Fatal("Add failed")
	}
}

func TestG2JacSub(t *testing.T) {

	p := testPointsG2()

	// p4 = p1 - p2
	p[1].SubAssign(p[2])

	if !p[4].Equal(&p[1]) {
		t.Fatal("Sub failed")
	}
}

func TestG2JacDouble(t *testing.T) {

	p := testPointsG2()

	// p5 = 2 * p1
	p[1].DoubleAssign()
	if !p[5].Equal(&p[1]) {
		t.Fatal("Double failed")
	}

	G := g2Infinity.Clone()
	R := g2Infinity.Clone()
	G.DoubleAssign()

	if !G.Equal(R) {
		t.Fatal("Double failed (infinity case)")
	}
}

func TestG2JacScalarMul(t *testing.T) {

	p := testPointsG2()

	// p6 = [p1]32394 (scalar mul)
	scalar := fr.Element{32394}
	p[1].ScalarMul(&p[1], scalar)

	if !p[1].Equal(&p[6]) {
		t.Error("ScalarMul failed")
	}
}

func TestMultiExpG2(t *testing.T) {

	var G G2Jac

	// mixer ensures that all the words of a fpElement are set
	var mixer fr.Element
	mixer.SetString("7716837800905789770901243404444209691916730933998574719964609384059111546487")

	samplePoints := make([]G2Affine, 3000)
	sampleScalars := make([]fr.Element, 3000)

	G.Set(&g2Gen)

	for i := 1; i <= 3000; i++ {
		sampleScalars[i-1].SetUint64(uint64(i)).
			MulAssign(&mixer).
			FromMont()
		samplePoints[i-1].FromJacobian(&G)
		G.AddAssign(&g2Gen)
	}

	var testLotOfPoint, testPoint G2Jac

	<-testLotOfPoint.MultiExp(samplePoints, sampleScalars)
	<-testPoint.MultiExp(samplePoints[:30], sampleScalars[:30])

	var finalBigScalar fr.Element
	var finalLotOfPoint G2Jac
	finalBigScalar.SetString("9004500500").MulAssign(&mixer).FromMont()
	finalLotOfPoint.ScalarMul(&g2Gen, finalBigScalar)

	var finalScalar fr.Element
	var finalPoint G2Jac
	finalScalar.SetString("9455").MulAssign(&mixer).FromMont()
	finalPoint.ScalarMul(&g2Gen, finalScalar)

	if !finalLotOfPoint.Equal(&testLotOfPoint) {
		t.Fatal("error multi (>50 points) exp")
	}
	if !finalPoint.Equal(&testPoint) {
		t.Fatal("error multi <=50 points) exp")
	}

}

//--------------------//
//     benches		  //
//--------------------//

var benchResG2 G2Jac

func BenchmarkG2ScalarMul(b *testing.B) {

	p := testPointsG2()

	var scalar fr.Element
	scalar.SetRandom()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p[1].ScalarMul(&p[1], scalar)
		b.StopTimer()
		scalar.SetRandom()
		b.StartTimer()
	}

}

func BenchmarkG2Add(b *testing.B) {

	p := testPointsG2()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchResG2 = p[1]
		benchResG2.AddAssign(&p[2])
	}

}

func BenchmarkG2AddMixed(b *testing.B) {

	p := testPointsG2()
	_p2 := G2Affine{}
	_p2.FromJacobian(&p[2])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchResG2 = p[1]
		benchResG2.AddMixed(&_p2)
	}

}

func BenchmarkG2Double(b *testing.B) {

	p := testPointsG2()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchResG2 = p[1]
		benchResG2.DoubleAssign()
	}

}

func BenchmarkG2WindowedMultiExp(b *testing.B) {

	var G G2Jac

	var mixer fr.Element
	mixer.SetString("7716837800905789770901243404444209691916730933998574719964609384059111546487")

	var nbSamples int
	nbSamples = 400000

	samplePoints := make([]G2Jac, nbSamples)
	sampleScalars := make([]fr.Element, nbSamples)

	G.Set(&g2Gen)

	for i := 1; i <= nbSamples; i++ {
		sampleScalars[i-1].SetUint64(uint64(i)).
			Mul(&sampleScalars[i-1], &mixer).
			FromMont()
		samplePoints[i-1].Set(&g2Gen)
	}

	var testPoint G2Jac

	for i := 0; i < 8; i++ {
		b.Run(fmt.Sprintf("%d points", (i+1)*50000), func(b *testing.B) {
			b.ResetTimer()
			for j := 0; j < b.N; j++ {
				testPoint.WindowedMultiExp(samplePoints[:50000+i*50000], sampleScalars[:50000+i*50000])
			}
		})
	}
}

func BenchmarkMultiExpG2(b *testing.B) {

	var G G2Jac

	var mixer fr.Element
	mixer.SetString("7716837800905789770901243404444209691916730933998574719964609384059111546487")

	var nbSamples int
	nbSamples = 800000

	samplePoints := make([]G2Affine, nbSamples)
	sampleScalars := make([]fr.Element, nbSamples)

	G.Set(&g2Gen)

	for i := 1; i <= nbSamples; i++ {
		sampleScalars[i-1].SetUint64(uint64(i)).
			Mul(&sampleScalars[i-1], &mixer).
			FromMont()
		samplePoints[i-1].FromJacobian(&G)
	}

	var testPoint G2Jac

	for i := 0; i < 16; i++ {

		b.Run(fmt.Sprintf("%d points)", (i+1)*50000), func(b *testing.B) {
			b.ResetTimer()
			for j := 0; j < b.N; j++ {
				<-testPoint.MultiExp(samplePoints[:50000+i*50000], sampleScalars[:50000+i*50000])
			}
		})
	}
}
