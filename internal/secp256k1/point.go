package secp256k1

// point represents a secp256k1 point in projective coordinates (X:Y:Z),
// where affine x = X/Z and y = Y/Z. Infinity is (0:1:0).
type point struct {
	x fieldElement
	y fieldElement
	z fieldElement
}

var generator = func() point {
	x := [32]byte{
		0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
		0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
		0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
		0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
	}
	y := [32]byte{
		0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65,
		0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
		0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19,
		0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8,
	}
	var p point
	if !p.x.setBytes(&x) || !p.y.setBytes(&y) {
		panic("secp256k1: invalid generator")
	}
	p.z.one()
	return p
}()

func identity() point {
	var p point
	p.y.one()
	return p
}

// add implements Algorithm 7 from Renes-Costello-Batina, "Complete addition
// formulas for prime order elliptic curves", for short Weierstrass curves
// with a = 0. It is complete for secp256k1, including infinity and doubling.
func (r *point) add(p, q *point) *point {
	var xx, yy, zz fieldElement
	xx.mul(&p.x, &q.x)
	yy.mul(&p.y, &q.y)
	zz.mul(&p.z, &q.z)

	var pxy, qxy, xyPairs, n fieldElement
	pxy.add(&p.x, &p.y)
	qxy.add(&q.x, &q.y)
	xyPairs.mul(&pxy, &qxy)
	n.add(&xx, &yy)
	xyPairs.sub(&xyPairs, &n)

	var pyz, qyz, yzPairs fieldElement
	pyz.add(&p.y, &p.z)
	qyz.add(&q.y, &q.z)
	yzPairs.mul(&pyz, &qyz)
	n.add(&yy, &zz)
	yzPairs.sub(&yzPairs, &n)

	var pxz, qxz, xzPairs fieldElement
	pxz.add(&p.x, &p.z)
	qxz.add(&q.x, &q.z)
	xzPairs.mul(&pxz, &qxz)
	n.add(&xx, &zz)
	xzPairs.sub(&xzPairs, &n)

	var bzz3, yyMinus, yyPlus fieldElement
	mul21(&bzz3, &zz)
	yyMinus.sub(&yy, &bzz3)
	yyPlus.add(&yy, &bzz3)

	var byz3, xx3, bxx9 fieldElement
	mul21(&byz3, &yzPairs)
	mul3(&xx3, &xx)
	mul63(&bxx9, &xx)

	var x1, x2, y1, y2, z1, z2 fieldElement
	x1.mul(&xyPairs, &yyMinus)
	x2.mul(&byz3, &xzPairs)
	y1.mul(&yyPlus, &yyMinus)
	y2.mul(&bxx9, &xzPairs)
	z1.mul(&yzPairs, &yyPlus)
	z2.mul(&xx3, &xyPairs)

	var out point
	out.x.sub(&x1, &x2)
	out.y.add(&y1, &y2)
	out.z.add(&z1, &z2)
	*r = out
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

	var x2, rhs, seven fieldElement
	x2.square(&x)
	rhs.mul(&x2, &x)
	seven.setUint64(7)
	rhs.add(&rhs, &seven)

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

func mul3(z, x *fieldElement) {
	var x2 fieldElement
	x2.add(x, x)
	z.add(&x2, x)
}

func mul21(z, x *fieldElement) {
	var x2, x4, x8, x16, x20 fieldElement
	x2.add(x, x)
	x4.add(&x2, &x2)
	x8.add(&x4, &x4)
	x16.add(&x8, &x8)
	x20.add(&x16, &x4)
	z.add(&x20, x)
}

func mul63(z, x *fieldElement) {
	var x2, x4, x8, x16, x32, x64 fieldElement
	x2.add(x, x)
	x4.add(&x2, &x2)
	x8.add(&x4, &x4)
	x16.add(&x8, &x8)
	x32.add(&x16, &x16)
	x64.add(&x32, &x32)
	z.sub(&x64, x)
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
