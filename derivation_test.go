package slip10

import (
	"bytes"
	"errors"
	"testing"
)

func TestMasterSeedValidation(t *testing.T) {
	for _, curve := range []Curve{Secp256k1, NISTP256, Ed25519, Curve25519} {
		for _, size := range []int{masterSeedMinSize, masterSeedMaxSize} {
			if _, err := NewMasterKey(curve, make([]byte, size)); err != nil {
				t.Fatalf("NewMasterKey(%s, %d bytes) error = %v", curve, size, err)
			}
		}
	}
	for _, size := range []int{0, masterSeedMinSize - 1, masterSeedMaxSize + 1} {
		if _, err := NewMasterKey(Ed25519, make([]byte, size)); !errors.Is(err, ErrInvalidSeed) {
			t.Fatalf("NewMasterKey(seed len %d) error = %v", size, err)
		}
	}
	if _, err := NewMasterKey(0, make([]byte, masterSeedMinSize)); !errors.Is(err, ErrInvalidCurve) {
		t.Fatalf("NewMasterKey(invalid curve) error = %v", err)
	}
}

func TestCurveDerivationCapabilities(t *testing.T) {
	seed := make([]byte, masterSeedMinSize)
	for _, curve := range []Curve{Ed25519, Curve25519} {
		root, err := NewMasterKey(curve, seed)
		if err != nil {
			t.Fatalf("NewMasterKey(%s) error = %v", curve, err)
		}
		if _, err := root.Child(0); !errors.Is(err, ErrNonHardenedDerivation) {
			t.Fatalf("%s private Child(0) error = %v", curve, err)
		}
		if _, err := root.Public().Child(0); !errors.Is(err, ErrPublicDerivationUnsupported) {
			t.Fatalf("%s public Child(0) error = %v", curve, err)
		}
		if _, err := root.Public().Derive("m"); !errors.Is(err, ErrPublicDerivationUnsupported) {
			t.Fatalf("%s public Derive(\"m\") error = %v", curve, err)
		}
	}

	root, err := NewMasterKey(Secp256k1, seed)
	if err != nil {
		t.Fatalf("NewMasterKey() error = %v", err)
	}
	if _, err := root.Public().Child(HardenedOffset); !errors.Is(err, ErrHardenedPublicDerivation) {
		t.Fatalf("public hardened Child() error = %v", err)
	}
}

func TestDepthOverflow(t *testing.T) {
	private := PrivateKey{}
	private[31] = 1
	metadata := Metadata{Depth: 255, ChildNumber: 1}
	key, err := NewExtendedPrivateKey(Secp256k1, private, ChainCode{}, metadata)
	if err != nil {
		t.Fatalf("NewExtendedPrivateKey() error = %v", err)
	}
	if _, err := key.Child(0); !errors.Is(err, ErrDepthOverflow) {
		t.Fatalf("private Child() error = %v", err)
	}
	if _, err := key.Public().Child(0); !errors.Is(err, ErrDepthOverflow) {
		t.Fatalf("public Child() error = %v", err)
	}
}

func TestECDSANonHardenedDerivationIdentity(t *testing.T) {
	seed := make([]byte, masterSeedMinSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	for _, curve := range []Curve{Secp256k1, NISTP256} {
		t.Run(curve.String(), func(t *testing.T) {
			root, err := NewMasterKey(curve, seed)
			if err != nil {
				t.Fatalf("NewMasterKey() error = %v", err)
			}
			for _, index := range []uint32{0, 1, maxChildIndex} {
				privateChild, err := root.Child(index)
				if err != nil {
					t.Fatalf("private Child(%d) error = %v", index, err)
				}
				publicChild, err := root.Public().Child(index)
				if err != nil {
					t.Fatalf("public Child(%d) error = %v", index, err)
				}
				if privateChild.PublicKey() != publicChild.PublicKey() ||
					privateChild.ChainCode() != publicChild.ChainCode() ||
					privateChild.Metadata() != publicChild.Metadata() {
					t.Fatalf("CKDpriv/CKDpub mismatch at index %d", index)
				}
			}

			privatePath, err := root.Derive("m/0/1/2")
			if err != nil {
				t.Fatalf("private Derive() error = %v", err)
			}
			publicPath, err := root.Public().Derive("m/0/1/2")
			if err != nil {
				t.Fatalf("public Derive() error = %v", err)
			}
			if privatePath.PublicKey() != publicPath.PublicKey() || privatePath.ChainCode() != publicPath.ChainCode() {
				t.Fatal("private/public path derivation mismatch")
			}
		})
	}
}

func TestRootPathReturnsDetachedCopy(t *testing.T) {
	root, err := NewMasterKey(Ed25519, make([]byte, masterSeedMinSize))
	if err != nil {
		t.Fatalf("NewMasterKey() error = %v", err)
	}
	derived, err := root.Derive("m")
	if err != nil {
		t.Fatalf("Derive() error = %v", err)
	}
	if derived == root || derived.PrivateKey() != root.PrivateKey() {
		t.Fatal("Derive(\"m\") did not return an equal detached copy")
	}
}

func TestScriptedMasterRetry(t *testing.T) {
	var invalid, valid [64]byte
	invalid[40] = 0xaa
	valid[31] = 1
	valid[63] = 0xbb
	calls := 0
	key, err := newMasterKey(NISTP256, make([]byte, masterSeedMinSize), func(hmacKey, data []byte) [64]byte {
		if !bytes.Equal(hmacKey, []byte("Nist256p1 seed")) {
			t.Fatalf("HMAC key = %q", hmacKey)
		}
		calls++
		if calls == 1 {
			return invalid
		}
		if !bytes.Equal(data, invalid[:]) {
			t.Fatalf("retry seed = %x, want complete previous digest", data)
		}
		return valid
	})
	if err != nil {
		t.Fatalf("newMasterKey() error = %v", err)
	}
	if calls != 2 || key.PrivateKey()[31] != 1 || key.ChainCode()[31] != 0xbb {
		t.Fatalf("retry result calls=%d private=%x chain=%x", calls, key.PrivateKey(), key.ChainCode())
	}
}

func TestScriptedChildRetryBranches(t *testing.T) {
	parent := PrivateKey{}
	parent[31] = 1
	public, err := publicKeyFromPrivate(Secp256k1, parent)
	if err != nil {
		t.Fatalf("publicKeyFromPrivate() error = %v", err)
	}
	order := privateKeyFromHex(t, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	orderMinusOne := privateKeyFromHex(t, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")
	one := PrivateKey{}
	one[31] = 1

	sequence := [][64]byte{digestWithTweak(orderMinusOne, 0x11), digestWithTweak(one, 0x22)}
	initial := digestWithTweak(order, 0x00)
	position := 0
	child, successfulDigest := deriveECDSAPrivateCandidate(Secp256k1, parent, initial, func(previous [64]byte) [64]byte {
		result := sequence[position]
		position++
		return result
	})
	if position != 2 || child[31] != 2 || successfulDigest[63] != 0x22 {
		t.Fatalf("private retry position=%d child=%x digest=%x", position, child, successfulDigest)
	}

	position = 0
	publicChild, successfulDigest := deriveECDSAPublicCandidate(Secp256k1, public, digestWithTweak(orderMinusOne, 0x00), func(previous [64]byte) [64]byte {
		sequence := [][64]byte{digestWithTweak(order, 0x11), digestWithTweak(one, 0x22)}
		result := sequence[position]
		position++
		return result
	})
	wantPublic, err := publicKeyFromPrivate(Secp256k1, PrivateKey{31: 2})
	if err != nil {
		t.Fatalf("publicKeyFromPrivate(2) error = %v", err)
	}
	if position != 2 || publicChild != wantPublic || successfulDigest[63] != 0x22 {
		t.Fatalf("public retry position=%d child=%x digest=%x", position, publicChild, successfulDigest)
	}
}

func TestRetryDigestFormat(t *testing.T) {
	var chainCode ChainCode
	for i := range chainCode {
		chainCode[i] = byte(i)
	}
	var previous [64]byte
	for i := range previous {
		previous[i] = byte(0x80 + i)
	}
	const index = uint32(0x12345678)

	var data [1 + ChainCodeSize + 4]byte
	data[0] = 0x01
	copy(data[1:33], previous[32:])
	data[33] = 0x12
	data[34] = 0x34
	data[35] = 0x56
	data[36] = 0x78
	want := hmacSHA512(chainCode[:], data[:])
	if got := retryDigest(chainCode, previous, index); got != want {
		t.Fatalf("retryDigest() = %x, want %x", got, want)
	}

	changedLeft := previous
	changedLeft[0] ^= 0xff
	if retryDigest(chainCode, changedLeft, index) != want {
		t.Fatal("retryDigest() included I_L instead of only I_R")
	}
}

func digestWithTweak(tweak PrivateKey, marker byte) [64]byte {
	var digest [64]byte
	copy(digest[:32], tweak[:])
	digest[63] = marker
	return digest
}

func privateKeyFromHex(t *testing.T, value string) PrivateKey {
	t.Helper()
	decoded := decodeHex(t, value)
	if len(decoded) != PrivateKeySize {
		t.Fatalf("private key length = %d", len(decoded))
	}
	var out PrivateKey
	copy(out[:], decoded)
	return out
}
