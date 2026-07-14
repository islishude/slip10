package slip10

import "errors"

var (
	ErrInvalidCurve                = errors.New("slip10: invalid curve")
	ErrInvalidSeed                 = errors.New("slip10: invalid seed")
	ErrInvalidPrivateKey           = errors.New("slip10: invalid private key")
	ErrInvalidPublicKey            = errors.New("slip10: invalid public key")
	ErrInvalidMetadata             = errors.New("slip10: invalid metadata")
	ErrInvalidPath                 = errors.New("slip10: invalid derivation path")
	ErrNilKey                      = errors.New("slip10: nil extended key")
	ErrDepthOverflow               = errors.New("slip10: derivation depth overflow")
	ErrNonHardenedDerivation       = errors.New("slip10: non-hardened private derivation is unsupported")
	ErrHardenedPublicDerivation    = errors.New("slip10: hardened public derivation is unsupported")
	ErrPublicDerivationUnsupported = errors.New("slip10: public derivation is unsupported for this curve")
)
