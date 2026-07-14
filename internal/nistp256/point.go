package nistp256

// point represents a NIST P-256 point in projective coordinates (X:Y:Z),
// where affine x = X/Z and y = Y/Z. Infinity is (0:1:0).
type point struct {
	x fieldElement
	y fieldElement
	z fieldElement
}

var curveB = func() fieldElement {
	b := [32]byte{
		0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7,
		0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc,
		0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6,
		0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b,
	}
	var out fieldElement
	if !out.setBytes(&b) {
		panic("nistp256: invalid curve constant")
	}
	return out
}()

var generator = func() point {
	x := [32]byte{
		0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
		0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
		0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
		0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
	}
	y := [32]byte{
		0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
		0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
		0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
		0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
	}
	var p point
	if !p.x.setBytes(&x) || !p.y.setBytes(&y) {
		panic("nistp256: invalid generator")
	}
	p.z.one()
	return p
}()

func identity() point {
	var p point
	p.y.one()
	return p
}

// add implements the complete a = -3 projective addition formula from
// Renes-Costello-Batina, "Complete addition formulas for prime order elliptic
// curves", Appendix A.2. It handles infinity and doubling without exceptions.
func (r *point) add(p, q *point) *point {
	var t0, t1, t2, t3, t4 fieldElement
	t0.mul(&p.x, &q.x)
	t1.mul(&p.y, &q.y)
	t2.mul(&p.z, &q.z)

	var a, b fieldElement
	a.add(&p.x, &p.y)
	b.add(&q.x, &q.y)
	t3.mul(&a, &b)
	a.add(&t0, &t1)
	t3.sub(&t3, &a)

	a.add(&p.y, &p.z)
	b.add(&q.y, &q.z)
	t4.mul(&a, &b)
	a.add(&t1, &t2)
	t4.sub(&t4, &a)

	a.add(&p.x, &p.z)
	b.add(&q.x, &q.z)
	var xz fieldElement
	xz.mul(&a, &b)
	a.add(&t0, &t2)
	xz.sub(&xz, &a)

	var z3, x3, y3 fieldElement
	z3.mul(&curveB, &t2)
	x3.sub(&xz, &z3)
	z3.add(&x3, &x3)
	x3.add(&x3, &z3)
	z3.sub(&t1, &x3)
	x3.add(&t1, &x3)

	y3.mul(&curveB, &xz)
	t1.add(&t2, &t2)
	t2.add(&t1, &t2)
	y3.sub(&y3, &t2)
	y3.sub(&y3, &t0)
	t1.add(&y3, &y3)
	y3.add(&t1, &y3)
	t1.add(&t0, &t0)
	t0.add(&t1, &t0)
	t0.sub(&t0, &t2)

	t1.mul(&t4, &y3)
	t2.mul(&t0, &y3)
	y3.mul(&x3, &z3)
	y3.add(&y3, &t2)
	x3.mul(&t3, &x3)
	x3.sub(&x3, &t1)
	z3.mul(&t4, &z3)
	t1.mul(&t3, &t0)
	z3.add(&z3, &t1)

	r.x = x3
	r.y = y3
	r.z = z3
	return r
}

func (r *point) conditionalSelect(p, q *point, cond int) *point {
	r.x.conditionalSelect(&p.x, &q.x, cond)
	r.y.conditionalSelect(&p.y, &q.y, cond)
	r.z.conditionalSelect(&p.z, &q.z, cond)
	return r
}

func (p *point) isInfinity() int {
	return p.z.isZero()
}

func scalarMult(p *point, scalar *[32]byte) point {
	r0 := identity()
	r1 := *p
	for i := range 256 {
		bit := int((scalar[i/8] >> (7 - uint(i%8))) & 1)
		conditionalSwap(&r0, &r1, bit)
		var sum, doubled point
		sum.add(&r0, &r1)
		doubled.add(&r0, &r0)
		r0 = doubled
		r1 = sum
		conditionalSwap(&r0, &r1, bit)
	}
	return r0
}

func conditionalSwap(p, q *point, cond int) {
	originalP := *p
	p.conditionalSelect(q, p, cond)
	q.conditionalSelect(&originalP, q, cond)
}

func pointFromCompressed(in *[33]byte) (point, bool) {
	if in[0] != 0x02 && in[0] != 0x03 {
		return point{}, false
	}
	var xBytes [32]byte
	copy(xBytes[:], in[1:])
	var x fieldElement
	if !x.setBytes(&xBytes) {
		return point{}, false
	}

	// y^2 = x^3 - 3x + b.
	var x2, rhs, threeX fieldElement
	x2.square(&x)
	rhs.mul(&x2, &x)
	threeX.add(&x, &x)
	threeX.add(&threeX, &x)
	rhs.sub(&rhs, &threeX)
	rhs.add(&rhs, &curveB)

	var y fieldElement
	if !y.sqrt(&rhs) {
		return point{}, false
	}
	yBytes := y.bytes()
	chooseNegative := int((yBytes[31] & 1) ^ (in[0] & 1))
	var negativeY, selectedY fieldElement
	negativeY.neg(&y)
	selectedY.conditionalSelect(&negativeY, &y, chooseNegative)

	p := point{x: x, y: selectedY}
	p.z.one()
	return p, true
}

func (p *point) compressed() ([33]byte, bool) {
	if p.isInfinity() == 1 {
		return [33]byte{}, false
	}
	var zInv, x, y fieldElement
	zInv.invert(&p.z)
	x.mul(&p.x, &zInv)
	y.mul(&p.y, &zInv)
	xBytes := x.bytes()
	yBytes := y.bytes()
	var out [33]byte
	out[0] = 0x02 | (yBytes[31] & 1)
	copy(out[1:], xBytes[:])
	return out, true
}

// IsValidPrivateKey reports whether key is a non-zero scalar below the group order.
func IsValidPrivateKey(key [32]byte) bool {
	return validPrivateKey(&key)
}

// AddPrivateKey adds tweak to parent modulo the group order. A false result
// means the tweak is out of range or the resulting scalar is zero.
func AddPrivateKey(parent, tweak [32]byte) ([32]byte, bool) {
	return addPrivateKey(&parent, &tweak)
}

// PublicKeyFromPrivate returns the compressed SEC1 public key for private.
func PublicKeyFromPrivate(private [32]byte) ([33]byte, bool) {
	if !validPrivateKey(&private) {
		return [33]byte{}, false
	}
	p := scalarMult(&generator, &private)
	return p.compressed()
}

// IsValidPublicKey reports whether public is a canonical compressed curve point.
func IsValidPublicKey(public [33]byte) bool {
	_, ok := pointFromCompressed(&public)
	return ok
}

// AddPublicKey returns public + tweak*G. A false result means the input is
// invalid or the resulting point is infinity.
func AddPublicKey(public [33]byte, tweak [32]byte) ([33]byte, bool) {
	parent, ok := pointFromCompressed(&public)
	if !ok || !validTweak(&tweak) {
		return [33]byte{}, false
	}
	tweakPoint := scalarMult(&generator, &tweak)
	var child point
	child.add(&parent, &tweakPoint)
	return child.compressed()
}
