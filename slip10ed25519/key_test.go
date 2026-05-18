package slip10ed25519

import (
	"crypto/ed25519"
	"testing"
)

func TestPublicAndPrivateKey(t *testing.T) {
	key := testRoot(t)

	priv := key.PrivateKey()
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("PrivateKey() len = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}

	pub := key.PublicKey()
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("PublicKey() len = %d, want %d", len(pub), ed25519.PublicKeySize)
	}

	slipPub := key.SLIP10PublicKey()
	if len(slipPub) != SlipPublicSize {
		t.Fatalf("SLIP10PublicKey() len = %d, want %d", len(slipPub), SlipPublicSize)
	}
	if slipPub[0] != 0x00 {
		t.Fatalf("SLIP10PublicKey()[0] = %x, want 00", slipPub[0])
	}

	msg := []byte("hello")
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("ed25519.Verify() = false, want true")
	}
}

func TestByteGettersReturnCopies(t *testing.T) {
	key := testRoot(t)

	seed := key.Seed()
	chainCode := key.ChainCode()

	seed[0] ^= 0xff
	chainCode[0] ^= 0xff

	assertHexBytes(t, "Seed", key.Seed(), "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7")
	assertHexBytes(t, "ChainCode", key.ChainCode(), "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb")
}

func TestNilKeyAccessorsReturnZeroValues(t *testing.T) {
	var key *ExtendedPrivateKey

	if got := key.Seed(); got != nil {
		t.Fatalf("Seed() = %x, want nil", got)
	}
	if got := key.ChainCode(); got != nil {
		t.Fatalf("ChainCode() = %x, want nil", got)
	}
	if got := key.PrivateKey(); got != nil {
		t.Fatalf("PrivateKey() = %x, want nil", got)
	}
	if got := key.PublicKey(); got != nil {
		t.Fatalf("PublicKey() = %x, want nil", got)
	}
	if got := key.SLIP10PublicKey(); got != nil {
		t.Fatalf("SLIP10PublicKey() = %x, want nil", got)
	}
	if got := key.Depth(); got != 0 {
		t.Fatalf("Depth() = %d, want 0", got)
	}
	if got := key.ChildNumber(); got != 0 {
		t.Fatalf("ChildNumber() = %d, want 0", got)
	}
	if got := key.ParentFingerprint(); got != [4]byte{} {
		t.Fatalf("ParentFingerprint() = %x, want 00000000", got)
	}
	if got := key.Fingerprint(); got != [4]byte{} {
		t.Fatalf("Fingerprint() = %x, want 00000000", got)
	}
}

func TestWipe(t *testing.T) {
	key := testRoot(t)
	key.depth = 3
	key.childNumber = HardenedOffset + 3
	key.parentFingerprint = [4]byte{1, 2, 3, 4}

	key.Wipe()

	assertHexBytes(t, "Seed", key.Seed(), "0000000000000000000000000000000000000000000000000000000000000000")
	assertHexBytes(t, "ChainCode", key.ChainCode(), "0000000000000000000000000000000000000000000000000000000000000000")
	if key.Depth() != 0 {
		t.Fatalf("Depth() = %d, want 0", key.Depth())
	}
	if key.ChildNumber() != 0 {
		t.Fatalf("ChildNumber() = %d, want 0", key.ChildNumber())
	}
	if key.ParentFingerprint() != [4]byte{} {
		t.Fatalf("ParentFingerprint() = %x, want 00000000", key.ParentFingerprint())
	}
}
