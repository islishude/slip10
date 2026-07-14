package slip10

import "fmt"

const (
	PrivateKeySize = 32
	PublicKeySize  = 33
	ChainCodeSize  = 32

	HardenedOffset uint32 = 1 << 31
)

// Curve identifies one of the curves defined by SLIP-0010.
type Curve uint8

const (
	Secp256k1 Curve = iota + 1
	NISTP256
	Ed25519
	Curve25519
)

func (c Curve) String() string {
	switch c {
	case Secp256k1:
		return "secp256k1"
	case NISTP256:
		return "nist256p1"
	case Ed25519:
		return "ed25519"
	case Curve25519:
		return "curve25519"
	default:
		return fmt.Sprintf("Curve(%d)", uint8(c))
	}
}

func (c Curve) valid() bool {
	return c >= Secp256k1 && c <= Curve25519
}

func (c Curve) supportsPublicDerivation() bool {
	return c == Secp256k1 || c == NISTP256
}

// PrivateKey is the 32-byte private key material defined by SLIP-0010. For
// Ed25519 it is an RFC 8032 seed, and for Curve25519 it is an RFC 7748 scalar
// input. For secp256k1 and NIST P-256 it is a big-endian integer.
type PrivateKey [PrivateKeySize]byte

// PublicKey is the curve-specific ser_P encoding defined by SLIP-0010.
type PublicKey [PublicKeySize]byte

// ChainCode is a SLIP-0010 chain code.
type ChainCode [ChainCodeSize]byte

// Fingerprint is the first four bytes of HASH160(ser_P(public key)).
type Fingerprint [4]byte

// Metadata contains the BIP32-style metadata associated with an extended key.
type Metadata struct {
	Depth             uint8
	ParentFingerprint Fingerprint
	ChildNumber       uint32
}

func (m Metadata) valid() bool {
	if m.Depth != 0 {
		return true
	}
	return m.ParentFingerprint == (Fingerprint{}) && m.ChildNumber == 0
}
