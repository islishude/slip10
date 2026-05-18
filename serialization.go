package slip10

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	binaryMagic = "SL10EDV1"
	binarySize  = len(binaryMagic) + 1 + 4 + 4 + ChainCodeSize + SeedSize
)

// MarshalBinary encodes k into this package's compact extended-key format.
func (k *ExtendedPrivateKey) MarshalBinary() ([]byte, error) {
	if k == nil {
		return nil, ErrNilKey
	}

	// This is a compact package-local binary format, not BIP32 xprv/xpub
	// serialization. It stores enough metadata to resume derivation faithfully.
	out := make([]byte, binarySize)
	offset := 0
	copy(out[offset:], binaryMagic)
	offset += len(binaryMagic)
	out[offset] = k.depth
	offset++
	copy(out[offset:], k.parentFingerprint[:])
	offset += len(k.parentFingerprint)
	binary.BigEndian.PutUint32(out[offset:offset+4], k.childNumber)
	offset += 4
	copy(out[offset:], k.chainCode[:])
	offset += ChainCodeSize
	copy(out[offset:], k.key[:])
	return out, nil
}

// UnmarshalBinary decodes this package's compact extended-key format into k.
func (k *ExtendedPrivateKey) UnmarshalBinary(data []byte) error {
	if k == nil {
		return ErrNilKey
	}
	if len(data) != binarySize {
		return fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidExtendedKey, len(data), binarySize)
	}
	if !bytes.Equal(data[:len(binaryMagic)], []byte(binaryMagic)) {
		return fmt.Errorf("%w: wrong magic", ErrInvalidExtendedKey)
	}

	offset := len(binaryMagic)
	k.depth = data[offset]
	offset++
	copy(k.parentFingerprint[:], data[offset:offset+4])
	offset += 4
	k.childNumber = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	copy(k.chainCode[:], data[offset:offset+ChainCodeSize])
	offset += ChainCodeSize
	copy(k.key[:], data[offset:offset+SeedSize])
	return nil
}

// UnmarshalBinary decodes this package's compact extended-key format.
func UnmarshalBinary(data []byte) (*ExtendedPrivateKey, error) {
	k := &ExtendedPrivateKey{}
	if err := k.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return k, nil
}
