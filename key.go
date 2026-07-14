package slip10

// ExtendedPrivateKey contains private key material, a chain code, and
// derivation metadata. Values are immutable except for Wipe.
type ExtendedPrivateKey struct {
	curve     Curve
	key       PrivateKey
	publicKey PublicKey
	chainCode ChainCode
	metadata  Metadata
}

// ExtendedPublicKey contains a serialized public key, a chain code, and
// derivation metadata.
type ExtendedPublicKey struct {
	curve     Curve
	key       PublicKey
	chainCode ChainCode
	metadata  Metadata
}

// NewExtendedPrivateKey constructs an extended private key from its
// components. For secp256k1 and NIST P-256, key must be a non-zero scalar below
// the curve order. Ed25519 and Curve25519 accept every 32-byte private value.
func NewExtendedPrivateKey(curve Curve, key PrivateKey, chainCode ChainCode, metadata Metadata) (*ExtendedPrivateKey, error) {
	if !curve.valid() {
		return nil, ErrInvalidCurve
	}
	if !metadata.valid() {
		return nil, ErrInvalidMetadata
	}
	if !validPrivateKey(curve, key) {
		return nil, ErrInvalidPrivateKey
	}
	public, err := publicKeyFromPrivate(curve, key)
	if err != nil {
		return nil, err
	}
	return &ExtendedPrivateKey{
		curve:     curve,
		key:       key,
		publicKey: public,
		chainCode: chainCode,
		metadata:  metadata,
	}, nil
}

// NewExtendedPublicKey constructs an extended public key for secp256k1 or
// NIST P-256. SLIP-0010 does not define public child derivation for Ed25519 or
// Curve25519, so those curves cannot be imported as public parents.
func NewExtendedPublicKey(curve Curve, key PublicKey, chainCode ChainCode, metadata Metadata) (*ExtendedPublicKey, error) {
	if !curve.valid() {
		return nil, ErrInvalidCurve
	}
	if !curve.supportsPublicDerivation() {
		return nil, ErrPublicDerivationUnsupported
	}
	if !metadata.valid() {
		return nil, ErrInvalidMetadata
	}
	if !validPublicKey(curve, key) {
		return nil, ErrInvalidPublicKey
	}
	return newExtendedPublicKey(curve, key, chainCode, metadata), nil
}

func newExtendedPublicKey(curve Curve, key PublicKey, chainCode ChainCode, metadata Metadata) *ExtendedPublicKey {
	return &ExtendedPublicKey{
		curve:     curve,
		key:       key,
		chainCode: chainCode,
		metadata:  metadata,
	}
}

func (k *ExtendedPrivateKey) Curve() Curve {
	if k == nil {
		return 0
	}
	return k.curve
}

func (k *ExtendedPrivateKey) PrivateKey() PrivateKey {
	if k == nil {
		return PrivateKey{}
	}
	return k.key
}

func (k *ExtendedPrivateKey) PublicKey() PublicKey {
	if k == nil {
		return PublicKey{}
	}
	return k.publicKey
}

func (k *ExtendedPrivateKey) ChainCode() ChainCode {
	if k == nil {
		return ChainCode{}
	}
	return k.chainCode
}

func (k *ExtendedPrivateKey) Metadata() Metadata {
	if k == nil {
		return Metadata{}
	}
	return k.metadata
}

func (k *ExtendedPrivateKey) Depth() uint8 {
	return k.Metadata().Depth
}

func (k *ExtendedPrivateKey) ParentFingerprint() Fingerprint {
	return k.Metadata().ParentFingerprint
}

func (k *ExtendedPrivateKey) ChildNumber() uint32 {
	return k.Metadata().ChildNumber
}

// Public returns a detached extended public key carrying the same metadata and
// chain code. Child derivation from it remains curve-dependent.
func (k *ExtendedPrivateKey) Public() *ExtendedPublicKey {
	if k == nil {
		return nil
	}
	return newExtendedPublicKey(k.curve, k.publicKey, k.chainCode, k.metadata)
}

func (k *ExtendedPrivateKey) Fingerprint() Fingerprint {
	if k == nil || !k.curve.valid() {
		return Fingerprint{}
	}
	return fingerprint(k.publicKey)
}

// Wipe clears private and public key material, chain code, metadata, and curve
// selection in place. As with all Go memory wiping, callers must not assume the
// compiler or runtime cleared copies made before this call.
func (k *ExtendedPrivateKey) Wipe() {
	if k == nil {
		return
	}
	clear(k.key[:])
	clear(k.publicKey[:])
	clear(k.chainCode[:])
	k.metadata = Metadata{}
	k.curve = 0
}

func (k *ExtendedPrivateKey) clone() *ExtendedPrivateKey {
	if k == nil {
		return nil
	}
	clone := *k
	return &clone
}

func (k *ExtendedPublicKey) Curve() Curve {
	if k == nil {
		return 0
	}
	return k.curve
}

func (k *ExtendedPublicKey) PublicKey() PublicKey {
	if k == nil {
		return PublicKey{}
	}
	return k.key
}

func (k *ExtendedPublicKey) ChainCode() ChainCode {
	if k == nil {
		return ChainCode{}
	}
	return k.chainCode
}

func (k *ExtendedPublicKey) Metadata() Metadata {
	if k == nil {
		return Metadata{}
	}
	return k.metadata
}

func (k *ExtendedPublicKey) Depth() uint8 {
	return k.Metadata().Depth
}

func (k *ExtendedPublicKey) ParentFingerprint() Fingerprint {
	return k.Metadata().ParentFingerprint
}

func (k *ExtendedPublicKey) ChildNumber() uint32 {
	return k.Metadata().ChildNumber
}

func (k *ExtendedPublicKey) Fingerprint() Fingerprint {
	if k == nil || !k.curve.valid() {
		return Fingerprint{}
	}
	return fingerprint(k.key)
}

func (k *ExtendedPublicKey) clone() *ExtendedPublicKey {
	if k == nil {
		return nil
	}
	clone := *k
	return &clone
}

func fingerprint(public PublicKey) Fingerprint {
	h := hash160(public[:])
	var out Fingerprint
	copy(out[:], h[:4])
	return out
}
