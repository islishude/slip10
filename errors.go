package slip10

import "errors"

var (
	// ErrInvalidSeed indicates that a master seed is outside the supported size range.
	ErrInvalidSeed = errors.New("slip10: invalid seed")
	// ErrNilKey indicates that an operation was called on a nil extended key.
	ErrNilKey = errors.New("slip10: nil extended private key")
	// ErrNonHardenedDerivation indicates that a non-hardened child was requested.
	ErrNonHardenedDerivation = errors.New("slip10: non-hardened derivation is unsupported")
	// ErrDepthOverflow indicates that derivation would exceed the uint8 depth field.
	ErrDepthOverflow = errors.New("slip10: derivation depth overflow")
	// ErrInvalidPath indicates that a derivation path is malformed or out of range.
	ErrInvalidPath = errors.New("slip10: invalid derivation path")
	// ErrInvalidExtendedKey indicates that binary extended-key data is malformed.
	ErrInvalidExtendedKey = errors.New("slip10: invalid extended private key")
)
