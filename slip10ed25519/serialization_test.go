package slip10ed25519

import (
	"bytes"
	"errors"
	"testing"
)

func TestMarshalBinaryRoundTrip(t *testing.T) {
	key, err := DerivePath(mustDecodeHex(t, "000102030405060708090a0b0c0d0e0f"), "m/0'/1'")
	if err != nil {
		t.Fatalf("DerivePath() error = %v", err)
	}

	data, err := key.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	if len(data) != 81 {
		t.Fatalf("MarshalBinary() len = %d, want 81", len(data))
	}
	if !bytes.Equal(data[:8], []byte("SL10EDV1")) {
		t.Fatalf("MarshalBinary() magic = %q, want SL10EDV1", data[:8])
	}

	decoded, err := UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}

	assertHexBytes(t, "Seed", decoded.Seed(), "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2")
	assertHexBytes(t, "ChainCode", decoded.ChainCode(), "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14")
	assertHexBytes(t, "SLIP10PublicKey", decoded.SLIP10PublicKey(), "001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187")
	if decoded.Depth() != key.Depth() {
		t.Fatalf("Depth() = %d, want %d", decoded.Depth(), key.Depth())
	}
	if decoded.ChildNumber() != key.ChildNumber() {
		t.Fatalf("ChildNumber() = %d, want %d", decoded.ChildNumber(), key.ChildNumber())
	}
	if decoded.ParentFingerprint() != key.ParentFingerprint() {
		t.Fatalf("ParentFingerprint() = %x, want %x", decoded.ParentFingerprint(), key.ParentFingerprint())
	}
}

func TestMarshalBinaryRejectsNilKey(t *testing.T) {
	var key *ExtendedPrivateKey
	_, err := key.MarshalBinary()
	if !errors.Is(err, ErrNilKey) {
		t.Fatalf("MarshalBinary() error = %v, want ErrNilKey", err)
	}
}

func TestUnmarshalBinaryRejectsInvalidInput(t *testing.T) {
	if _, err := UnmarshalBinary(nil); !errors.Is(err, ErrInvalidExtendedKey) {
		t.Fatalf("UnmarshalBinary(nil) error = %v, want ErrInvalidExtendedKey", err)
	}

	key := testRoot(t)
	data, err := key.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	data[0] = 'X'

	if _, err := UnmarshalBinary(data); !errors.Is(err, ErrInvalidExtendedKey) {
		t.Fatalf("UnmarshalBinary(wrong magic) error = %v, want ErrInvalidExtendedKey", err)
	}
}
