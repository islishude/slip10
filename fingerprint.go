package slip10

import (
	"crypto/sha256"

	"golang.org/x/crypto/ripemd160"
)

func hash160(data []byte) [20]byte {
	// BIP32 key identifiers use HASH160: RIPEMD160(SHA256(serialized pubkey)).
	// SLIP-0010 test vectors carry the same fingerprint metadata.
	sha := sha256.Sum256(data)

	h := ripemd160.New()
	_, _ = h.Write(sha[:])
	sum := h.Sum(nil)

	var out [20]byte
	copy(out[:], sum)
	return out
}

func (k *ExtendedPrivateKey) SLIP10PublicKey() []byte {
	if k == nil {
		return nil
	}

	// SLIP-0010 defines Ed25519 ser_P(P) as 0x00 || RFC 8032 point encoding.
	raw := k.PublicKey()
	out := make([]byte, SlipPublicSize)
	out[0] = 0x00
	copy(out[1:], raw)
	return out
}

func (k *ExtendedPrivateKey) Fingerprint() [4]byte {
	if k == nil {
		return [4]byte{}
	}

	// BIP32 defines the key fingerprint as the first 32 bits of the key
	// identifier. This matches the fingerprint values in SLIP-0010 vectors.
	h := hash160(k.SLIP10PublicKey())

	var fp [4]byte
	copy(fp[:], h[:4])
	return fp
}
