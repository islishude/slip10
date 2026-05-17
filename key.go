package slip10

import "crypto/ed25519"

const (
	SeedSize       = 32
	ChainCodeSize  = 32
	PublicKeySize  = ed25519.PublicKeySize
	SlipPublicSize = 1 + PublicKeySize

	HardenedOffset uint32 = 0x80000000
)

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

func (k *ExtendedPrivateKey) Seed() []byte {
	if k == nil {
		return nil
	}

	out := make([]byte, SeedSize)
	copy(out, k.key[:])
	return out
}

func (k *ExtendedPrivateKey) ChainCode() []byte {
	if k == nil {
		return nil
	}

	out := make([]byte, ChainCodeSize)
	copy(out, k.chainCode[:])
	return out
}

func (k *ExtendedPrivateKey) Depth() uint8 {
	if k == nil {
		return 0
	}

	return k.depth
}

func (k *ExtendedPrivateKey) ChildNumber() uint32 {
	if k == nil {
		return 0
	}

	return k.childNumber
}

func (k *ExtendedPrivateKey) ParentFingerprint() [4]byte {
	if k == nil {
		return [4]byte{}
	}

	return k.parentFingerprint
}

func (k *ExtendedPrivateKey) PrivateKey() ed25519.PrivateKey {
	if k == nil {
		return nil
	}

	// Go's ed25519 package expands the 32-byte seed into a 64-byte private key.
	return ed25519.NewKeyFromSeed(k.Seed())
}

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
