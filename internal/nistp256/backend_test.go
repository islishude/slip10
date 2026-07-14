package nistp256

import (
	"encoding/hex"
	"math/big"
	"math/rand"
	"testing"
)

func TestOfficialRootPublicKey(t *testing.T) {
	private := decode32(t, "612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2")
	want := decode33(t, "0266874dc6ade47b3ecd096745ca09bcd29638dd52c2c12117b11ed3e458cfa9e8")
	got, ok := PublicKeyFromPrivate(private)
	if !ok || got != want {
		t.Fatalf("PublicKeyFromPrivate() = %x, %v, want %x, true", got, ok, want)
	}
	if !IsValidPublicKey(got) {
		t.Fatal("IsValidPublicKey() = false")
	}
	zeroTweak := [32]byte{}
	unchanged, ok := AddPublicKey(got, zeroTweak)
	if !ok || unchanged != got {
		t.Fatalf("AddPublicKey(P, 0) = %x, %v, want %x, true", unchanged, ok, got)
	}
}

func TestCompleteAdditionExceptionalCases(t *testing.T) {
	t.Parallel()

	wantGenerator, ok := generator.compressed()
	if !ok {
		t.Fatal("generator encoded as infinity")
	}
	infinity := identity()
	var sum point
	if got, ok := sum.add(&infinity, &generator).compressed(); !ok || got != wantGenerator {
		t.Fatalf("infinity + G = %x, %v", got, ok)
	}
	if got, ok := sum.add(&generator, &infinity).compressed(); !ok || got != wantGenerator {
		t.Fatalf("G + infinity = %x, %v", got, ok)
	}

	var doubled point
	doubled.add(&generator, &generator)
	two := [32]byte{31: 2}
	wantDouble := scalarMult(&generator, &two)
	assertSamePoint(t, "G + G", &doubled, &wantDouble)

	negative := generator
	negative.y.neg(&negative.y)
	if sum.add(&generator, &negative).isInfinity() != 1 {
		t.Fatal("G + (-G) is not infinity")
	}

	order := bigIntBytes(testScalarModulus)
	orderMultiple := scalarMult(&generator, &order)
	if orderMultiple.isInfinity() != 1 {
		t.Fatal("n*G is not infinity")
	}
}

func TestRandomPointAddition(t *testing.T) {
	t.Parallel()

	rng := rand.New(rand.NewSource(0x256add))
	for range 32 {
		k := randomBigInt(rng, testScalarModulus)
		l := randomBigInt(rng, testScalarModulus)
		kBytes, lBytes := bigIntBytes(k), bigIntBytes(l)
		p := scalarMult(&generator, &kBytes)
		q := scalarMult(&generator, &lBytes)
		var got point
		got.add(&p, &q)

		sum := new(big.Int).Mod(new(big.Int).Add(k, l), testScalarModulus)
		sumBytes := bigIntBytes(sum)
		want := scalarMult(&generator, &sumBytes)
		assertSamePoint(t, "random addition", &got, &want)
	}
}

func assertSamePoint(t *testing.T, operation string, got, want *point) {
	t.Helper()

	gotEncoding, gotOK := got.compressed()
	wantEncoding, wantOK := want.compressed()
	if gotOK != wantOK || gotEncoding != wantEncoding {
		t.Fatalf("%s = %x, %v, want %x, %v", operation, gotEncoding, gotOK, wantEncoding, wantOK)
	}
}

func decode32(t *testing.T, value string) [32]byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("decode %q: %v", value, err)
	}
	var out [32]byte
	copy(out[:], decoded)
	return out
}

func decode33(t *testing.T, value string) [33]byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 33 {
		t.Fatalf("decode %q: %v", value, err)
	}
	var out [33]byte
	copy(out[:], decoded)
	return out
}
