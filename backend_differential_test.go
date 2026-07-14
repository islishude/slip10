package slip10

import (
	"encoding/binary"
	"math/big"
	"math/rand"
	"testing"

	"github.com/islishude/slip10/internal/nistp256"
	"github.com/islishude/slip10/internal/secp256k1"
)

type differentialBackend struct {
	name              string
	p                 *big.Int
	n                 *big.Int
	a                 *big.Int
	b                 *big.Int
	g                 oraclePoint
	publicFromPrivate func([32]byte) ([33]byte, bool)
	addPrivate        func([32]byte, [32]byte) ([32]byte, bool)
	addPublic         func([33]byte, [32]byte) ([33]byte, bool)
	validPrivate      func([32]byte) bool
	validPublic       func([33]byte) bool
}

type oraclePoint struct {
	x *big.Int
	y *big.Int
}

func TestECDSABackendsDifferential(t *testing.T) {
	for _, backend := range differentialBackends() {
		t.Run(backend.name, func(t *testing.T) {
			testBackendBoundaries(t, backend)
			testBackendRandomOperations(t, backend)
		})
	}
}

func testBackendBoundaries(t *testing.T, backend differentialBackend) {
	t.Helper()

	zero := [32]byte{}
	one := oracleBytes32(big.NewInt(1))
	order := oracleBytes32(backend.n)
	orderMinusOne := oracleBytes32(new(big.Int).Sub(backend.n, big.NewInt(1)))
	if backend.validPrivate(zero) || backend.validPrivate(order) || !backend.validPrivate(one) || !backend.validPrivate(orderMinusOne) {
		t.Fatal("private scalar boundary validation failed")
	}
	if _, ok := backend.publicFromPrivate(zero); ok {
		t.Fatal("PublicKeyFromPrivate(0) succeeded")
	}
	if _, ok := backend.publicFromPrivate(order); ok {
		t.Fatal("PublicKeyFromPrivate(n) succeeded")
	}

	generator, ok := backend.publicFromPrivate(one)
	if !ok || generator != backend.compress(backend.g) {
		t.Fatalf("PublicKeyFromPrivate(1) = %x, %v", generator, ok)
	}
	unchanged, ok := backend.addPublic(generator, zero)
	if !ok || unchanged != generator {
		t.Fatalf("G + 0*G = %x, %v", unchanged, ok)
	}
	if _, ok := backend.addPublic(generator, order); ok {
		t.Fatal("AddPublicKey accepted tweak n")
	}
	if _, ok := backend.addPublic(generator, orderMinusOne); ok {
		t.Fatal("G + (n-1)*G did not report infinity")
	}
	negativeGenerator, ok := backend.publicFromPrivate(orderMinusOne)
	if !ok {
		t.Fatal("PublicKeyFromPrivate(n-1) failed")
	}
	if _, ok := backend.addPublic(negativeGenerator, one); ok {
		t.Fatal("(-G) + G did not report infinity")
	}
	if _, ok := backend.addPrivate(one, orderMinusOne); ok {
		t.Fatal("private scalar sum zero was accepted")
	}

	invalidPrefix := generator
	invalidPrefix[0] = 0x04
	if backend.validPublic(invalidPrefix) {
		t.Fatal("uncompressed SEC1 prefix was accepted")
	}
	var fieldOverflow [33]byte
	fieldOverflow[0] = 0x02
	backend.p.FillBytes(fieldOverflow[1:])
	if backend.validPublic(fieldOverflow) {
		t.Fatal("x coordinate equal to p was accepted")
	}
	if backend.validPublic([33]byte{}) {
		t.Fatal("zero public encoding was accepted")
	}

	nonResidueX := backend.firstNonResidueX()
	var nonResidue [33]byte
	nonResidue[0] = 0x02
	nonResidueX.FillBytes(nonResidue[1:])
	if backend.validPublic(nonResidue) {
		t.Fatal("compressed point with non-residue right-hand side was accepted")
	}

	oppositeParity := generator
	oppositeParity[0] ^= 1
	if !backend.validPublic(generator) || !backend.validPublic(oppositeParity) {
		t.Fatal("canonical compressed generator encodings were rejected")
	}
}

func testBackendRandomOperations(t *testing.T, backend differentialBackend) {
	t.Helper()

	rng := rand.New(rand.NewSource(int64(len(backend.name)) * 0x10ecd5a))
	for range 48 {
		privateInt := oracleRandomBelow(rng, backend.n)
		if privateInt.Sign() == 0 {
			privateInt.SetInt64(1)
		}
		tweakInt := oracleRandomBelow(rng, backend.n)
		private := oracleBytes32(privateInt)
		tweak := oracleBytes32(tweakInt)

		gotPublic, ok := backend.publicFromPrivate(private)
		if !ok {
			t.Fatal("PublicKeyFromPrivate rejected a reduced non-zero scalar")
		}
		parentPoint := backend.scalarMult(privateInt)
		wantPublic := backend.compress(parentPoint)
		if gotPublic != wantPublic {
			t.Fatalf("scalar multiplication = %x, want %x", gotPublic, wantPublic)
		}

		childInt := new(big.Int).Mod(new(big.Int).Add(privateInt, tweakInt), backend.n)
		gotPrivate, privateOK := backend.addPrivate(private, tweak)
		gotChildPublic, publicOK := backend.addPublic(gotPublic, tweak)
		if childInt.Sign() == 0 {
			if privateOK || publicOK {
				t.Fatal("zero/infinity child was accepted")
			}
			continue
		}
		wantPrivate := oracleBytes32(childInt)
		wantChildPublic := backend.compress(backend.scalarMult(childInt))
		if !privateOK || gotPrivate != wantPrivate {
			t.Fatalf("private addition = %x, %v, want %x, true", gotPrivate, privateOK, wantPrivate)
		}
		if !publicOK || gotChildPublic != wantChildPublic {
			t.Fatalf("public addition = %x, %v, want %x, true", gotChildPublic, publicOK, wantChildPublic)
		}
	}
}

func differentialBackends() []differentialBackend {
	return []differentialBackend{
		{
			name: "secp256k1",
			p:    oracleBigInt("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
			n:    oracleBigInt("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
			a:    new(big.Int),
			b:    big.NewInt(7),
			g: oraclePoint{
				x: oracleBigInt("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
				y: oracleBigInt("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
			},
			publicFromPrivate: secp256k1.PublicKeyFromPrivate,
			addPrivate:        secp256k1.AddPrivateKey,
			addPublic:         secp256k1.AddPublicKey,
			validPrivate:      secp256k1.IsValidPrivateKey,
			validPublic:       secp256k1.IsValidPublicKey,
		},
		{
			name: "nist256p1",
			p:    oracleBigInt("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
			n:    oracleBigInt("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
			a:    big.NewInt(-3),
			b:    oracleBigInt("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
			g: oraclePoint{
				x: oracleBigInt("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
				y: oracleBigInt("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
			},
			publicFromPrivate: nistp256.PublicKeyFromPrivate,
			addPrivate:        nistp256.AddPrivateKey,
			addPublic:         nistp256.AddPublicKey,
			validPrivate:      nistp256.IsValidPrivateKey,
			validPublic:       nistp256.IsValidPublicKey,
		},
	}
}

func (backend differentialBackend) scalarMult(scalar *big.Int) oraclePoint {
	result := oraclePoint{}
	for i := scalar.BitLen() - 1; i >= 0; i-- {
		result = backend.add(result, result)
		if scalar.Bit(i) == 1 {
			result = backend.add(result, backend.g)
		}
	}
	return result
}

func (backend differentialBackend) add(p, q oraclePoint) oraclePoint {
	if p.x == nil {
		return q.copy()
	}
	if q.x == nil {
		return p.copy()
	}

	var numerator, denominator *big.Int
	if p.x.Cmp(q.x) == 0 {
		ySum := backend.mod(new(big.Int).Add(p.y, q.y))
		if ySum.Sign() == 0 {
			return oraclePoint{}
		}
		xSquared := new(big.Int).Mul(p.x, p.x)
		numerator = new(big.Int).Add(new(big.Int).Mul(big.NewInt(3), xSquared), backend.a)
		denominator = new(big.Int).Mul(big.NewInt(2), p.y)
	} else {
		numerator = new(big.Int).Sub(q.y, p.y)
		denominator = new(big.Int).Sub(q.x, p.x)
	}
	denominator.ModInverse(backend.mod(denominator), backend.p)
	lambda := backend.mod(new(big.Int).Mul(backend.mod(numerator), denominator))
	x := backend.mod(new(big.Int).Sub(new(big.Int).Sub(new(big.Int).Mul(lambda, lambda), p.x), q.x))
	y := backend.mod(new(big.Int).Sub(new(big.Int).Mul(lambda, new(big.Int).Sub(p.x, x)), p.y))
	return oraclePoint{x: x, y: y}
}

func (backend differentialBackend) compress(point oraclePoint) [33]byte {
	if point.x == nil {
		panic("cannot compress infinity in test oracle")
	}
	var out [33]byte
	out[0] = 0x02 | byte(point.y.Bit(0))
	point.x.FillBytes(out[1:])
	return out
}

func (backend differentialBackend) firstNonResidueX() *big.Int {
	exponent := new(big.Int).Rsh(new(big.Int).Sub(backend.p, big.NewInt(1)), 1)
	minusOne := new(big.Int).Sub(backend.p, big.NewInt(1))
	for x := new(big.Int); x.Cmp(backend.p) < 0; x.Add(x, big.NewInt(1)) {
		xSquared := new(big.Int).Mul(x, x)
		rhs := new(big.Int).Mul(xSquared, x)
		rhs.Add(rhs, new(big.Int).Mul(backend.a, x))
		rhs.Add(rhs, backend.b)
		rhs = backend.mod(rhs)
		if new(big.Int).Exp(rhs, exponent, backend.p).Cmp(minusOne) == 0 {
			return new(big.Int).Set(x)
		}
	}
	panic("prime field has no quadratic non-residue")
}

func (backend differentialBackend) mod(x *big.Int) *big.Int {
	return new(big.Int).Mod(x, backend.p)
}

func (point oraclePoint) copy() oraclePoint {
	if point.x == nil {
		return oraclePoint{}
	}
	return oraclePoint{x: new(big.Int).Set(point.x), y: new(big.Int).Set(point.y)}
}

func oracleRandomBelow(rng *rand.Rand, modulus *big.Int) *big.Int {
	var encoded [32]byte
	for i := range 4 {
		binary.BigEndian.PutUint64(encoded[i*8:], rng.Uint64())
	}
	return new(big.Int).Mod(new(big.Int).SetBytes(encoded[:]), modulus)
}

func oracleBytes32(x *big.Int) [32]byte {
	var out [32]byte
	x.FillBytes(out[:])
	return out
}

func oracleBigInt(value string) *big.Int {
	out, ok := new(big.Int).SetString(value, 16)
	if !ok {
		panic("invalid oracle constant")
	}
	return out
}
