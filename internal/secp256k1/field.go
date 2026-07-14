package secp256k1

import (
	"encoding/binary"
	"math/bits"
)

type fieldElement fiat_secp256k1field_montgomery_domain_field_element

func (z *fieldElement) setBytes(in *[32]byte) bool {
	if !fieldBytesCanonical(in) {
		return false
	}
	var little [32]byte
	for i := range in {
		little[i] = in[31-i]
	}
	var nonMont fiat_secp256k1field_non_montgomery_domain_field_element
	fiat_secp256k1field_from_bytes((*[4]uint64)(&nonMont), &little)
	fiat_secp256k1field_to_montgomery(
		(*fiat_secp256k1field_montgomery_domain_field_element)(z),
		&nonMont,
	)
	return true
}

func (z *fieldElement) setUint64(v uint64) *fieldElement {
	var in [32]byte
	binary.BigEndian.PutUint64(in[24:], v)
	if !z.setBytes(&in) {
		panic("secp256k1: internal field constant is out of range")
	}
	return z
}

func (z *fieldElement) bytes() [32]byte {
	var nonMont fiat_secp256k1field_non_montgomery_domain_field_element
	fiat_secp256k1field_from_montgomery(
		&nonMont,
		(*fiat_secp256k1field_montgomery_domain_field_element)(z),
	)
	var little [32]byte
	fiat_secp256k1field_to_bytes(&little, (*[4]uint64)(&nonMont))
	var out [32]byte
	for i := range little {
		out[i] = little[31-i]
	}
	return out
}

func (z *fieldElement) one() *fieldElement {
	fiat_secp256k1field_set_one((*fiat_secp256k1field_montgomery_domain_field_element)(z))
	return z
}

func (z *fieldElement) add(x, y *fieldElement) *fieldElement {
	fiat_secp256k1field_add(
		(*fiat_secp256k1field_montgomery_domain_field_element)(z),
		(*fiat_secp256k1field_montgomery_domain_field_element)(x),
		(*fiat_secp256k1field_montgomery_domain_field_element)(y),
	)
	return z
}

func (z *fieldElement) sub(x, y *fieldElement) *fieldElement {
	fiat_secp256k1field_sub(
		(*fiat_secp256k1field_montgomery_domain_field_element)(z),
		(*fiat_secp256k1field_montgomery_domain_field_element)(x),
		(*fiat_secp256k1field_montgomery_domain_field_element)(y),
	)
	return z
}

func (z *fieldElement) neg(x *fieldElement) *fieldElement {
	fiat_secp256k1field_opp(
		(*fiat_secp256k1field_montgomery_domain_field_element)(z),
		(*fiat_secp256k1field_montgomery_domain_field_element)(x),
	)
	return z
}

func (z *fieldElement) mul(x, y *fieldElement) *fieldElement {
	fiat_secp256k1field_mul(
		(*fiat_secp256k1field_montgomery_domain_field_element)(z),
		(*fiat_secp256k1field_montgomery_domain_field_element)(x),
		(*fiat_secp256k1field_montgomery_domain_field_element)(y),
	)
	return z
}

func (z *fieldElement) square(x *fieldElement) *fieldElement {
	fiat_secp256k1field_square(
		(*fiat_secp256k1field_montgomery_domain_field_element)(z),
		(*fiat_secp256k1field_montgomery_domain_field_element)(x),
	)
	return z
}

func (z *fieldElement) conditionalSelect(x, y *fieldElement, cond int) *fieldElement {
	fiat_secp256k1field_selectznz(
		(*[4]uint64)(z),
		fiat_secp256k1field_uint1(uint64(cond)),
		(*[4]uint64)(y),
		(*[4]uint64)(x),
	)
	return z
}

func (z *fieldElement) isZero() int {
	var nonzero uint64
	fiat_secp256k1field_nonzero(&nonzero, (*[4]uint64)(z))
	return int(1 ^ ((nonzero | (0 - nonzero)) >> 63))
}

func (z *fieldElement) equal(x *fieldElement) int {
	var diff fieldElement
	diff.sub(z, x)
	return diff.isZero()
}

func (z *fieldElement) sqrt(x *fieldElement) bool {
	var candidate, check fieldElement
	candidate.sqrtCandidate(x)
	check.square(&candidate)
	if check.equal(x) != 1 {
		return false
	}
	*z = candidate
	return true
}

func fieldBytesCanonical(in *[32]byte) bool {
	limbs := [4]uint64{
		binary.BigEndian.Uint64(in[24:]),
		binary.BigEndian.Uint64(in[16:24]),
		binary.BigEndian.Uint64(in[8:16]),
		binary.BigEndian.Uint64(in[:8]),
	}
	var modulus [5]uint64
	fiat_secp256k1field_msat(&modulus)
	_, borrow := bits.Sub64(limbs[0], modulus[0], 0)
	_, borrow = bits.Sub64(limbs[1], modulus[1], borrow)
	_, borrow = bits.Sub64(limbs[2], modulus[2], borrow)
	_, borrow = bits.Sub64(limbs[3], modulus[3], borrow)
	return borrow == 1
}
