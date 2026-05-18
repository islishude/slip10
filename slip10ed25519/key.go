package slip10ed25519

import "crypto/ed25519"

const (
	// SeedSize is the size in bytes of the SLIP-0010 Ed25519 private seed.
	SeedSize = 32
	// ChainCodeSize is the size in bytes of an extended key chain code.
	ChainCodeSize = 32
	// PublicKeySize is the size in bytes of an Ed25519 public key.
	PublicKeySize = ed25519.PublicKeySize
	// SlipPublicSize is the size in bytes of a SLIP-0010 serialized public key.
	SlipPublicSize = 1 + PublicKeySize

	// HardenedOffset is added to a child index to mark it as hardened.
	HardenedOffset uint32 = 0x80000000
)

// ExtendedPrivateKey holds SLIP-0010 Ed25519 private key material and
// BIP32-style metadata.
type ExtendedPrivateKey struct {
	// key is the SLIP-0010 Ed25519 private material: a 32-byte RFC 8032 seed,
	// not an Ed25519 scalar and not a 64-byte Go ed25519.PrivateKey.
	key       [SeedSize]byte
	chainCode [ChainCodeSize]byte

	// The remaining fields mirror BIP32-style extended-key metadata. They do
	// not affect derivation, but make serialized keys and test vectors traceable.
	depth             uint8
	parentFingerprint [4]byte
	childNumber       uint32
}

// Seed returns a copy of the 32-byte Ed25519 seed.
func (k *ExtendedPrivateKey) Seed() []byte {
	if k == nil {
		return nil
	}

	out := make([]byte, SeedSize)
	copy(out, k.key[:])
	return out
}

// ChainCode returns a copy of the 32-byte chain code.
func (k *ExtendedPrivateKey) ChainCode() []byte {
	if k == nil {
		return nil
	}

	out := make([]byte, ChainCodeSize)
	copy(out, k.chainCode[:])
	return out
}

// Depth returns the derivation depth of the key.
func (k *ExtendedPrivateKey) Depth() uint8 {
	if k == nil {
		return 0
	}

	return k.depth
}

// ChildNumber returns the hardened child number used to derive the key.
func (k *ExtendedPrivateKey) ChildNumber() uint32 {
	if k == nil {
		return 0
	}

	return k.childNumber
}

// ParentFingerprint returns the four-byte fingerprint of the parent key.
func (k *ExtendedPrivateKey) ParentFingerprint() [4]byte {
	if k == nil {
		return [4]byte{}
	}

	return k.parentFingerprint
}

// PrivateKey returns the Go Ed25519 private key expanded from the seed.
func (k *ExtendedPrivateKey) PrivateKey() ed25519.PrivateKey {
	if k == nil {
		return nil
	}

	// Go's ed25519 package expands the 32-byte seed into a 64-byte private key.
	return ed25519.NewKeyFromSeed(k.Seed())
}

// PublicKey returns a copy of the Ed25519 public key derived from the seed.
func (k *ExtendedPrivateKey) PublicKey() ed25519.PublicKey {
	if k == nil {
		return nil
	}

	priv := k.PrivateKey()
	pub := priv.Public().(ed25519.PublicKey)

	out := make([]byte, len(pub))
	copy(out, pub)
	return ed25519.PublicKey(out)
}

// Wipe clears the private seed, chain code, and derivation metadata in place.
func (k *ExtendedPrivateKey) Wipe() {
	if k == nil {
		return
	}
	clear(k.key[:])
	clear(k.chainCode[:])
	clear(k.parentFingerprint[:])
	k.depth = 0
	k.childNumber = 0
}

func (k *ExtendedPrivateKey) clone() *ExtendedPrivateKey {
	if k == nil {
		return nil
	}
	out := *k
	return &out
}
