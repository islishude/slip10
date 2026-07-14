package slip10

import "encoding/binary"

const (
	masterSeedMinSize = 16
	masterSeedMaxSize = 64
)

var curveSeedKeys = map[Curve][]byte{
	Secp256k1:  []byte("Bitcoin seed"),
	NISTP256:   []byte("Nist256p1 seed"),
	Ed25519:    []byte("ed25519 seed"),
	Curve25519: []byte("curve25519 seed"),
}

// NewMasterKey derives the curve-specific root extended private key from a
// 16-to-64-byte seed.
func NewMasterKey(curve Curve, seed []byte) (*ExtendedPrivateKey, error) {
	if !curve.valid() {
		return nil, ErrInvalidCurve
	}
	if len(seed) < masterSeedMinSize || len(seed) > masterSeedMaxSize {
		return nil, ErrInvalidSeed
	}
	return newMasterKey(curve, seed, hmacSHA512)
}

type hmacFunction func(key, data []byte) [64]byte

func newMasterKey(curve Curve, seed []byte, hmacFn hmacFunction) (*ExtendedPrivateKey, error) {
	data := seed
	for {
		digest := hmacFn(curveSeedKeys[curve], data)
		var key PrivateKey
		copy(key[:], digest[:32])
		if validPrivateKey(curve, key) {
			var chainCode ChainCode
			copy(chainCode[:], digest[32:])
			return NewExtendedPrivateKey(curve, key, chainCode, Metadata{})
		}
		// SLIP-0010 retries invalid ECDSA master keys with the complete
		// intermediate digest as the next seed.
		data = digest[:]
	}
}

// Child derives the private child at index.
func (k *ExtendedPrivateKey) Child(index uint32) (*ExtendedPrivateKey, error) {
	if k == nil {
		return nil, ErrNilKey
	}
	if !k.curve.valid() {
		return nil, ErrInvalidCurve
	}
	if k.metadata.Depth == ^uint8(0) {
		return nil, ErrDepthOverflow
	}
	if !IsHardened(index) && !k.curve.supportsPublicDerivation() {
		return nil, ErrNonHardenedDerivation
	}

	var digest [64]byte
	if IsHardened(index) {
		var data [1 + PrivateKeySize + 4]byte
		copy(data[1:33], k.key[:])
		binary.BigEndian.PutUint32(data[33:], index)
		digest = hmacSHA512(k.chainCode[:], data[:])
	} else {
		var data [PublicKeySize + 4]byte
		copy(data[:PublicKeySize], k.publicKey[:])
		binary.BigEndian.PutUint32(data[PublicKeySize:], index)
		digest = hmacSHA512(k.chainCode[:], data[:])
	}

	var childKey PrivateKey
	if k.curve == Ed25519 || k.curve == Curve25519 {
		copy(childKey[:], digest[:32])
	} else {
		childKey, digest = deriveECDSAPrivateCandidate(k.curve, k.key, digest, func(previous [64]byte) [64]byte {
			return retryDigest(k.chainCode, previous, index)
		})
	}

	var childChainCode ChainCode
	copy(childChainCode[:], digest[32:])
	metadata := Metadata{
		Depth:             k.metadata.Depth + 1,
		ParentFingerprint: k.Fingerprint(),
		ChildNumber:       index,
	}
	return NewExtendedPrivateKey(k.curve, childKey, childChainCode, metadata)
}

// Derive derives a private key at an absolute path such as m/0'/1/2h.
func (k *ExtendedPrivateKey) Derive(path string) (*ExtendedPrivateKey, error) {
	if k == nil {
		return nil, ErrNilKey
	}
	if !k.curve.valid() {
		return nil, ErrInvalidCurve
	}
	indexes, err := ParsePath(path)
	if err != nil {
		return nil, err
	}
	current := k.clone()
	for _, index := range indexes {
		current, err = current.Child(index)
		if err != nil {
			return nil, err
		}
	}
	return current, nil
}

// Child derives a non-hardened public child at index.
func (k *ExtendedPublicKey) Child(index uint32) (*ExtendedPublicKey, error) {
	if k == nil {
		return nil, ErrNilKey
	}
	if !k.curve.valid() {
		return nil, ErrInvalidCurve
	}
	if !k.curve.supportsPublicDerivation() {
		return nil, ErrPublicDerivationUnsupported
	}
	if IsHardened(index) {
		return nil, ErrHardenedPublicDerivation
	}
	if k.metadata.Depth == ^uint8(0) {
		return nil, ErrDepthOverflow
	}

	var data [PublicKeySize + 4]byte
	copy(data[:PublicKeySize], k.key[:])
	binary.BigEndian.PutUint32(data[PublicKeySize:], index)
	digest := hmacSHA512(k.chainCode[:], data[:])

	childKey, digest := deriveECDSAPublicCandidate(k.curve, k.key, digest, func(previous [64]byte) [64]byte {
		return retryDigest(k.chainCode, previous, index)
	})

	var childChainCode ChainCode
	copy(childChainCode[:], digest[32:])
	metadata := Metadata{
		Depth:             k.metadata.Depth + 1,
		ParentFingerprint: k.Fingerprint(),
		ChildNumber:       index,
	}
	return newExtendedPublicKey(k.curve, childKey, childChainCode, metadata), nil
}

// Derive derives a public key at an absolute non-hardened path.
func (k *ExtendedPublicKey) Derive(path string) (*ExtendedPublicKey, error) {
	if k == nil {
		return nil, ErrNilKey
	}
	if !k.curve.valid() {
		return nil, ErrInvalidCurve
	}
	if !k.curve.supportsPublicDerivation() {
		return nil, ErrPublicDerivationUnsupported
	}
	indexes, err := ParsePath(path)
	if err != nil {
		return nil, err
	}
	current := k.clone()
	for _, index := range indexes {
		current, err = current.Child(index)
		if err != nil {
			return nil, err
		}
	}
	return current, nil
}

// DerivePath derives the curve root from seed and then follows path.
func DerivePath(curve Curve, seed []byte, path string) (*ExtendedPrivateKey, error) {
	root, err := NewMasterKey(curve, seed)
	if err != nil {
		return nil, err
	}
	return root.Derive(path)
}

func retryDigest(chainCode ChainCode, previous [64]byte, index uint32) [64]byte {
	var data [1 + ChainCodeSize + 4]byte
	data[0] = 0x01
	copy(data[1:33], previous[32:])
	binary.BigEndian.PutUint32(data[33:], index)
	return hmacSHA512(chainCode[:], data[:])
}

type retryFunction func(previous [64]byte) [64]byte

func deriveECDSAPrivateCandidate(curve Curve, parent PrivateKey, digest [64]byte, retry retryFunction) (PrivateKey, [64]byte) {
	for {
		var tweak PrivateKey
		copy(tweak[:], digest[:32])
		child, ok := addPrivateKeys(curve, parent, tweak)
		if ok {
			return child, digest
		}
		digest = retry(digest)
	}
}

func deriveECDSAPublicCandidate(curve Curve, parent PublicKey, digest [64]byte, retry retryFunction) (PublicKey, [64]byte) {
	for {
		var tweak PrivateKey
		copy(tweak[:], digest[:32])
		child, ok := addPublicKey(curve, parent, tweak)
		if ok {
			return child, digest
		}
		digest = retry(digest)
	}
}
