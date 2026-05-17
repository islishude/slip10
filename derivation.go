package slip10

import "encoding/binary"

var ed25519SeedHMACKey = []byte("ed25519 seed")

const (
	// SLIP-0010 reuses the BIP32 seed size range: 128 to 512 bits.
	masterSeedMinSize = 16
	masterSeedMaxSize = 64
)

func NewMasterKey(seed []byte) (*ExtendedPrivateKey, error) {
	if len(seed) < masterSeedMinSize || len(seed) > masterSeedMaxSize {
		return nil, ErrInvalidSeed
	}

	// Master key generation is HMAC-SHA512(Key = "ed25519 seed", Data = S).
	I := hmacSHA512(ed25519SeedHMACKey, seed)

	k := &ExtendedPrivateKey{}
	// For Ed25519, SLIP-0010 treats I_L as a raw 32-byte seed, not as a
	// modulo-reduced curve scalar. I_R is the child-derivation chain code.
	copy(k.key[:], I[:32])
	copy(k.chainCode[:], I[32:64])
	return k, nil
}

func (k *ExtendedPrivateKey) Child(index uint32) (*ExtendedPrivateKey, error) {
	if k == nil {
		return nil, ErrNilKey
	}
	if index < HardenedOffset {
		return nil, ErrNonHardenedDerivation
	}
	if k.depth == ^uint8(0) {
		return nil, ErrDepthOverflow
	}

	// Ed25519 supports only hardened private child derivation:
	// HMAC-SHA512(Key = c_par, Data = 0x00 || k_par || ser32(i)).
	var data [1 + SeedSize + 4]byte
	data[0] = 0x00
	copy(data[1:33], k.key[:])
	binary.BigEndian.PutUint32(data[33:37], index)

	I := hmacSHA512(k.chainCode[:], data[:])

	child := &ExtendedPrivateKey{
		depth: k.depth + 1,
		// The fingerprint is metadata used to identify the parent node; it is
		// not an input to SLIP-0010 child key derivation.
		parentFingerprint: k.Fingerprint(),
		childNumber:       index,
	}
	copy(child.key[:], I[:32])
	copy(child.chainCode[:], I[32:64])

	return child, nil
}

func (k *ExtendedPrivateKey) Derive(path string) (*ExtendedPrivateKey, error) {
	if k == nil {
		return nil, ErrNilKey
	}

	indexes, err := ParsePath(path)
	if err != nil {
		return nil, err
	}

	cur := k.clone()
	for _, index := range indexes {
		cur, err = cur.Child(index)
		if err != nil {
			return nil, err
		}
	}
	return cur, nil
}

func DerivePath(seed []byte, path string) (*ExtendedPrivateKey, error) {
	root, err := NewMasterKey(seed)
	if err != nil {
		return nil, err
	}
	return root.Derive(path)
}
