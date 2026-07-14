package slip10

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"

	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // Required by SLIP-0010/BIP32 fingerprints.
)

func hmacSHA512(key, data []byte) [64]byte {
	mac := hmac.New(sha512.New, key)
	_, _ = mac.Write(data)
	var out [64]byte
	mac.Sum(out[:0])
	return out
}

func hash160(data []byte) [20]byte {
	sha := sha256.Sum256(data)
	h := ripemd160.New()
	_, _ = h.Write(sha[:])
	var out [20]byte
	copy(out[:], h.Sum(nil))
	return out
}
