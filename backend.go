package slip10

import (
	"crypto/ecdh"
	stded25519 "crypto/ed25519"
	"fmt"

	"github.com/islishude/slip10/internal/nistp256"
	"github.com/islishude/slip10/internal/secp256k1"
)

func validPrivateKey(curve Curve, key PrivateKey) bool {
	switch curve {
	case Secp256k1:
		return secp256k1.IsValidPrivateKey([32]byte(key))
	case NISTP256:
		return nistp256.IsValidPrivateKey([32]byte(key))
	case Ed25519, Curve25519:
		return true
	default:
		return false
	}
}

func validPublicKey(curve Curve, key PublicKey) bool {
	switch curve {
	case Secp256k1:
		return secp256k1.IsValidPublicKey([33]byte(key))
	case NISTP256:
		return nistp256.IsValidPublicKey([33]byte(key))
	default:
		return false
	}
}

func publicKeyFromPrivate(curve Curve, key PrivateKey) (PublicKey, error) {
	switch curve {
	case Secp256k1:
		public, ok := secp256k1.PublicKeyFromPrivate([32]byte(key))
		if !ok {
			return PublicKey{}, ErrInvalidPrivateKey
		}
		return PublicKey(public), nil
	case NISTP256:
		public, ok := nistp256.PublicKeyFromPrivate([32]byte(key))
		if !ok {
			return PublicKey{}, ErrInvalidPrivateKey
		}
		return PublicKey(public), nil
	case Ed25519:
		private := stded25519.NewKeyFromSeed(key[:])
		var public PublicKey
		copy(public[1:], private[stded25519.SeedSize:])
		return public, nil
	case Curve25519:
		private, err := ecdh.X25519().NewPrivateKey(key[:])
		if err != nil {
			return PublicKey{}, fmt.Errorf("%w: %v", ErrInvalidPrivateKey, err)
		}
		var public PublicKey
		copy(public[1:], private.PublicKey().Bytes())
		return public, nil
	default:
		return PublicKey{}, ErrInvalidCurve
	}
}

func addPrivateKeys(curve Curve, parent, tweak PrivateKey) (PrivateKey, bool) {
	switch curve {
	case Secp256k1:
		child, ok := secp256k1.AddPrivateKey([32]byte(parent), [32]byte(tweak))
		return PrivateKey(child), ok
	case NISTP256:
		child, ok := nistp256.AddPrivateKey([32]byte(parent), [32]byte(tweak))
		return PrivateKey(child), ok
	default:
		return PrivateKey{}, false
	}
}

func addPublicKey(curve Curve, parent PublicKey, tweak PrivateKey) (PublicKey, bool) {
	switch curve {
	case Secp256k1:
		child, ok := secp256k1.AddPublicKey([33]byte(parent), [32]byte(tweak))
		return PublicKey(child), ok
	case NISTP256:
		child, ok := nistp256.AddPublicKey([33]byte(parent), [32]byte(tweak))
		return PublicKey(child), ok
	default:
		return PublicKey{}, false
	}
}
