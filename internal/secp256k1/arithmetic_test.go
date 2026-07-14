package secp256k1

import (
	"encoding/binary"
	"math/big"
	"math/rand"
	"testing"
)

var (
	testFieldModulus  = mustBigInt("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")
	testScalarModulus = mustBigInt("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
)

func TestFieldArithmeticDifferential(t *testing.T) {
	t.Parallel()

	boundaries := []*big.Int{
		new(big.Int),
		big.NewInt(1),
		new(big.Int).Sub(testFieldModulus, big.NewInt(1)),
	}
	for _, a := range boundaries {
		for _, b := range boundaries {
			testFieldPair(t, a, b)
		}
	}

	rng := rand.New(rand.NewSource(0x5ec256))
	for range 64 {
		testFieldPair(t, randomBigInt(rng, testFieldModulus), randomBigInt(rng, testFieldModulus))
	}

	modulusBytes := bigIntBytes(testFieldModulus)
	var out fieldElement
	if out.setBytes(&modulusBytes) {
		t.Fatal("field accepted the modulus")
	}

	var zero fieldElement
	zeroBytes := [32]byte{}
	if !zero.setBytes(&zeroBytes) || zero.isZero() != 1 {
		t.Fatal("field rejected or misclassified zero")
	}
	var one fieldElement
	one.one()
	var selected fieldElement
	selected.conditionalSelect(&one, &zero, 0)
	if selected.isZero() != 1 {
		t.Fatal("conditionalSelect(_, zero, 0) did not select zero")
	}
	selected.conditionalSelect(&one, &zero, 1)
	if selected.equal(&one) != 1 {
		t.Fatal("conditionalSelect(one, _, 1) did not select one")
	}
}

func TestFieldSquareRootDifferential(t *testing.T) {
	t.Parallel()

	rng := rand.New(rand.NewSource(0x5ec257))
	for range 64 {
		a := randomBigInt(rng, testFieldModulus)
		aBytes := bigIntBytes(a)
		var x, square, root, check fieldElement
		if !x.setBytes(&aBytes) {
			t.Fatal("setBytes rejected a reduced field element")
		}
		square.square(&x)
		if !root.sqrt(&square) {
			t.Fatal("sqrt rejected a square")
		}
		check.square(&root)
		if check.equal(&square) != 1 {
			t.Fatal("sqrt result does not square to its input")
		}
	}

	nonResidue := firstQuadraticNonResidue(testFieldModulus)
	nonResidueBytes := bigIntBytes(nonResidue)
	var input, root fieldElement
	if !input.setBytes(&nonResidueBytes) {
		t.Fatal("setBytes rejected a reduced non-residue")
	}
	if root.sqrt(&input) {
		t.Fatal("sqrt accepted a quadratic non-residue")
	}
}

func TestScalarArithmeticDifferential(t *testing.T) {
	t.Parallel()

	boundaries := []*big.Int{
		new(big.Int),
		big.NewInt(1),
		new(big.Int).Sub(testScalarModulus, big.NewInt(1)),
	}
	for _, a := range boundaries {
		for _, b := range boundaries {
			testScalarPair(t, a, b)
		}
	}

	rng := rand.New(rand.NewSource(0x5ca1a2))
	for range 64 {
		testScalarPair(t, randomBigInt(rng, testScalarModulus), randomBigInt(rng, testScalarModulus))
	}

	modulusBytes := bigIntBytes(testScalarModulus)
	if scalarBytesCanonical(&modulusBytes) {
		t.Fatal("scalar accepted the group order")
	}
	zero := [32]byte{}
	if !scalarBytesCanonical(&zero) || validPrivateKey(&zero) || !validTweak(&zero) {
		t.Fatal("scalar zero boundary semantics are incorrect")
	}
}

func testFieldPair(t *testing.T, a, b *big.Int) {
	t.Helper()

	aBytes, bBytes := bigIntBytes(a), bigIntBytes(b)
	var x, y fieldElement
	if !x.setBytes(&aBytes) || !y.setBytes(&bBytes) {
		t.Fatal("setBytes rejected a reduced field element")
	}
	roundTrip := x.bytes()
	if got := new(big.Int).SetBytes(roundTrip[:]); got.Cmp(a) != 0 {
		t.Fatalf("field round trip = %x, want %x", got, a)
	}

	testFieldResult(t, "add", new(fieldElement).add(&x, &y), new(big.Int).Add(a, b))
	testFieldResult(t, "sub", new(fieldElement).sub(&x, &y), new(big.Int).Sub(a, b))
	testFieldResult(t, "mul", new(fieldElement).mul(&x, &y), new(big.Int).Mul(a, b))
	testFieldResult(t, "square", new(fieldElement).square(&x), new(big.Int).Mul(a, a))
	testFieldResult(t, "neg", new(fieldElement).neg(&x), new(big.Int).Neg(a))

	if a.Sign() != 0 {
		inverse := new(fieldElement).invert(&x)
		want := new(big.Int).ModInverse(a, testFieldModulus)
		testFieldResult(t, "invert", inverse, want)
	}
}

func testFieldResult(t *testing.T, operation string, got *fieldElement, want *big.Int) {
	t.Helper()

	want = new(big.Int).Mod(want, testFieldModulus)
	gotBytes := got.bytes()
	gotInt := new(big.Int).SetBytes(gotBytes[:])
	if gotInt.Cmp(want) != 0 {
		t.Fatalf("field %s = %x, want %x", operation, gotInt, want)
	}
}

func testScalarPair(t *testing.T, a, b *big.Int) {
	t.Helper()

	aBytes, bBytes := bigIntBytes(a), bigIntBytes(b)
	x, y := scalarFromBytes(&aBytes), scalarFromBytes(&bBytes)
	if got := scalarBigInt(&x); got.Cmp(a) != 0 {
		t.Fatalf("scalar round trip = %x, want %x", got, a)
	}

	var result scalarElement
	fiat_secp256k1scalar_add(scalarMont(&result), scalarMont(&x), scalarMont(&y))
	testScalarResult(t, "add", &result, new(big.Int).Add(a, b))
	fiat_secp256k1scalar_sub(scalarMont(&result), scalarMont(&x), scalarMont(&y))
	testScalarResult(t, "sub", &result, new(big.Int).Sub(a, b))
	fiat_secp256k1scalar_mul(scalarMont(&result), scalarMont(&x), scalarMont(&y))
	testScalarResult(t, "mul", &result, new(big.Int).Mul(a, b))
	fiat_secp256k1scalar_square(scalarMont(&result), scalarMont(&x))
	testScalarResult(t, "square", &result, new(big.Int).Mul(a, a))
	fiat_secp256k1scalar_opp(scalarMont(&result), scalarMont(&x))
	testScalarResult(t, "neg", &result, new(big.Int).Neg(a))

	if a.Sign() != 0 {
		inverse := scalarPow(&x, new(big.Int).Sub(testScalarModulus, big.NewInt(2)))
		want := new(big.Int).ModInverse(a, testScalarModulus)
		testScalarResult(t, "invert", &inverse, want)
	}
}

func scalarPow(x *scalarElement, exponent *big.Int) scalarElement {
	var result scalarElement
	fiat_secp256k1scalar_set_one(scalarMont(&result))
	for i := exponent.BitLen() - 1; i >= 0; i-- {
		var next scalarElement
		fiat_secp256k1scalar_square(scalarMont(&next), scalarMont(&result))
		result = next
		if exponent.Bit(i) == 1 {
			fiat_secp256k1scalar_mul(scalarMont(&next), scalarMont(&result), scalarMont(x))
			result = next
		}
	}
	return result
}

func scalarMont(x *scalarElement) *fiat_secp256k1scalar_montgomery_domain_field_element {
	return (*fiat_secp256k1scalar_montgomery_domain_field_element)(x)
}

func testScalarResult(t *testing.T, operation string, got *scalarElement, want *big.Int) {
	t.Helper()

	want = new(big.Int).Mod(want, testScalarModulus)
	if gotInt := scalarBigInt(got); gotInt.Cmp(want) != 0 {
		t.Fatalf("scalar %s = %x, want %x", operation, gotInt, want)
	}
}

func scalarBigInt(x *scalarElement) *big.Int {
	encoded := x.bytes()
	return new(big.Int).SetBytes(encoded[:])
}

func randomBigInt(rng *rand.Rand, modulus *big.Int) *big.Int {
	var encoded [32]byte
	for i := range 4 {
		binary.BigEndian.PutUint64(encoded[i*8:], rng.Uint64())
	}
	return new(big.Int).Mod(new(big.Int).SetBytes(encoded[:]), modulus)
}

func bigIntBytes(x *big.Int) [32]byte {
	var out [32]byte
	x.FillBytes(out[:])
	return out
}

func firstQuadraticNonResidue(modulus *big.Int) *big.Int {
	exponent := new(big.Int).Rsh(new(big.Int).Sub(modulus, big.NewInt(1)), 1)
	minusOne := new(big.Int).Sub(modulus, big.NewInt(1))
	for candidate := big.NewInt(2); ; candidate.Add(candidate, big.NewInt(1)) {
		if new(big.Int).Exp(candidate, exponent, modulus).Cmp(minusOne) == 0 {
			return new(big.Int).Set(candidate)
		}
	}
}

func mustBigInt(value string) *big.Int {
	out, ok := new(big.Int).SetString(value, 16)
	if !ok {
		panic("invalid test modulus")
	}
	return out
}
