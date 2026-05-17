package slip10

import (
	"crypto/hmac"
	"crypto/sha512"
)

func hmacSHA512(key, data []byte) [64]byte {
	mac := hmac.New(sha512.New, key)
	_, _ = mac.Write(data)
	var out [64]byte
	// Sum appends to the provided slice; out[:0] writes exactly the digest into
	// the fixed buffer without allocating a second result slice.
	mac.Sum(out[:0])
	return out
}
