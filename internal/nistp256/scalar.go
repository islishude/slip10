package nistp256

import (
	"encoding/binary"
	"math/bits"
)

type scalarElement fiat_nistp256scalar_montgomery_domain_field_element

func validPrivateKey(key *[32]byte) bool {
	return scalarBytesCanonical(key) && !bytesZero(key)
}

func validTweak(tweak *[32]byte) bool {
	return scalarBytesCanonical(tweak)
}

func addPrivateKey(parent, tweak *[32]byte) ([32]byte, bool) {
	if !validPrivateKey(parent) || !validTweak(tweak) {
		return [32]byte{}, false
	}
	x := scalarFromBytes(parent)
	y := scalarFromBytes(tweak)
	var sum scalarElement
	fiat_nistp256scalar_add(
		(*fiat_nistp256scalar_montgomery_domain_field_element)(&sum),
		(*fiat_nistp256scalar_montgomery_domain_field_element)(&x),
		(*fiat_nistp256scalar_montgomery_domain_field_element)(&y),
	)
	out := sum.bytes()
	return out, !bytesZero(&out)
}

func scalarFromBytes(in *[32]byte) scalarElement {
	var little [32]byte
	for i := range in {
		little[i] = in[31-i]
	}
	var nonMont fiat_nistp256scalar_non_montgomery_domain_field_element
	fiat_nistp256scalar_from_bytes((*[4]uint64)(&nonMont), &little)
	var out scalarElement
	fiat_nistp256scalar_to_montgomery(
		(*fiat_nistp256scalar_montgomery_domain_field_element)(&out),
		&nonMont,
	)
	return out
}

func (s *scalarElement) bytes() [32]byte {
	var nonMont fiat_nistp256scalar_non_montgomery_domain_field_element
	fiat_nistp256scalar_from_montgomery(
		&nonMont,
		(*fiat_nistp256scalar_montgomery_domain_field_element)(s),
	)
	var little [32]byte
	fiat_nistp256scalar_to_bytes(&little, (*[4]uint64)(&nonMont))
	var out [32]byte
	for i := range little {
		out[i] = little[31-i]
	}
	return out
}

func scalarBytesCanonical(in *[32]byte) bool {
	limbs := [4]uint64{
		binary.BigEndian.Uint64(in[24:]),
		binary.BigEndian.Uint64(in[16:24]),
		binary.BigEndian.Uint64(in[8:16]),
		binary.BigEndian.Uint64(in[:8]),
	}
	var modulus [5]uint64
	fiat_nistp256scalar_msat(&modulus)
	_, borrow := bits.Sub64(limbs[0], modulus[0], 0)
	_, borrow = bits.Sub64(limbs[1], modulus[1], borrow)
	_, borrow = bits.Sub64(limbs[2], modulus[2], borrow)
	_, borrow = bits.Sub64(limbs[3], modulus[3], borrow)
	return borrow == 1
}

func bytesZero(in *[32]byte) bool {
	var nonzero byte
	for _, b := range in {
		nonzero |= b
	}
	return nonzero == 0
}
