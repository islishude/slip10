package slip10

import "errors"

var (
	ErrInvalidSeed           = errors.New("slip10: invalid seed")
	ErrNilKey                = errors.New("slip10: nil extended private key")
	ErrNonHardenedDerivation = errors.New("slip10: non-hardened derivation is unsupported")
	ErrDepthOverflow         = errors.New("slip10: derivation depth overflow")
	ErrInvalidPath           = errors.New("slip10: invalid derivation path")
	ErrInvalidExtendedKey    = errors.New("slip10: invalid extended private key")
)
