package slip10

import (
	"errors"
	"testing"
)

func TestNewMasterKeyRejectsEmptySeed(t *testing.T) {
	_, err := NewMasterKey(nil)
	if !errors.Is(err, ErrInvalidSeed) {
		t.Fatalf("NewMasterKey(nil) error = %v, want ErrInvalidSeed", err)
	}
}

func TestNewMasterKeyRejectsInvalidSeedLength(t *testing.T) {
	tests := [][]byte{
		nil,
		make([]byte, masterSeedMinSize-1),
		make([]byte, masterSeedMaxSize+1),
	}

	for _, seed := range tests {
		_, err := NewMasterKey(seed)
		if !errors.Is(err, ErrInvalidSeed) {
			t.Fatalf("NewMasterKey(seed len %d) error = %v, want ErrInvalidSeed", len(seed), err)
		}
	}
}

func TestNewMasterKeyAcceptsBoundarySeedLength(t *testing.T) {
	for _, seed := range [][]byte{
		make([]byte, masterSeedMinSize),
		make([]byte, masterSeedMaxSize),
	} {
		if _, err := NewMasterKey(seed); err != nil {
			t.Fatalf("NewMasterKey(seed len %d) error = %v", len(seed), err)
		}
	}
}

func TestChildRejectsNilKey(t *testing.T) {
	var key *ExtendedPrivateKey
	_, err := key.Child(HardenedOffset)
	if !errors.Is(err, ErrNilKey) {
		t.Fatalf("Child() error = %v, want ErrNilKey", err)
	}
}

func TestChildRejectsNonHardenedIndex(t *testing.T) {
	key := testRoot(t)
	_, err := key.Child(0)
	if !errors.Is(err, ErrNonHardenedDerivation) {
		t.Fatalf("Child(0) error = %v, want ErrNonHardenedDerivation", err)
	}
}

func TestChildRejectsDepthOverflow(t *testing.T) {
	key := testRoot(t)
	key.depth = 255

	_, err := key.Child(HardenedOffset)
	if !errors.Is(err, ErrDepthOverflow) {
		t.Fatalf("Child() error = %v, want ErrDepthOverflow", err)
	}
}

func TestDeriveRejectsNilKey(t *testing.T) {
	var key *ExtendedPrivateKey
	_, err := key.Derive("m")
	if !errors.Is(err, ErrNilKey) {
		t.Fatalf("Derive() error = %v, want ErrNilKey", err)
	}
}

func TestDeriveReturnsCopyForRootPath(t *testing.T) {
	key := testRoot(t)
	derived, err := key.Derive("m")
	if err != nil {
		t.Fatalf("Derive() error = %v", err)
	}
	if derived == key {
		t.Fatal("Derive(\"m\") returned the receiver, want a copy")
	}
	assertHexBytes(t, "derived seed", derived.Seed(), "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7")
}

func testRoot(t *testing.T) *ExtendedPrivateKey {
	t.Helper()

	key, err := NewMasterKey(mustDecodeHex(t, "000102030405060708090a0b0c0d0e0f"))
	if err != nil {
		t.Fatalf("NewMasterKey() error = %v", err)
	}
	return key
}
