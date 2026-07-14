package slip10

import (
	"errors"
	"testing"
)

func TestCurveStrings(t *testing.T) {
	tests := map[Curve]string{
		Secp256k1:  "secp256k1",
		NISTP256:   "nist256p1",
		Ed25519:    "ed25519",
		Curve25519: "curve25519",
	}
	for curve, want := range tests {
		if got := curve.String(); got != want {
			t.Fatalf("%d.String() = %q, want %q", curve, got, want)
		}
	}
	if got := Curve(99).String(); got != "Curve(99)" {
		t.Fatalf("Curve(99).String() = %q", got)
	}
}

func TestComponentConstructors(t *testing.T) {
	private := PrivateKey{}
	private[31] = 1
	chainCode := ChainCode{1, 2, 3}
	key, err := NewExtendedPrivateKey(Secp256k1, private, chainCode, Metadata{})
	if err != nil {
		t.Fatalf("NewExtendedPrivateKey() error = %v", err)
	}
	public, err := NewExtendedPublicKey(Secp256k1, key.PublicKey(), chainCode, Metadata{})
	if err != nil {
		t.Fatalf("NewExtendedPublicKey() error = %v", err)
	}
	if public.PublicKey() != key.PublicKey() || public.ChainCode() != chainCode {
		t.Fatal("public component constructor did not preserve components")
	}

	if _, err := NewExtendedPrivateKey(0, private, chainCode, Metadata{}); !errors.Is(err, ErrInvalidCurve) {
		t.Fatalf("invalid curve error = %v", err)
	}
	if _, err := NewExtendedPrivateKey(Secp256k1, PrivateKey{}, chainCode, Metadata{}); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("zero ECDSA private key error = %v", err)
	}
	for _, test := range []struct {
		curve Curve
		order string
	}{
		{Secp256k1, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"},
		{NISTP256, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"},
	} {
		order := privateKeyFromHex(t, test.order)
		if _, err := NewExtendedPrivateKey(test.curve, order, chainCode, Metadata{}); !errors.Is(err, ErrInvalidPrivateKey) {
			t.Fatalf("%s order private key error = %v", test.curve, err)
		}
	}
	for _, curve := range []Curve{Ed25519, Curve25519} {
		if _, err := NewExtendedPrivateKey(curve, PrivateKey{}, chainCode, Metadata{}); err != nil {
			t.Fatalf("%s zero private material error = %v", curve, err)
		}
	}
	if _, err := NewExtendedPrivateKey(Secp256k1, private, chainCode, Metadata{ChildNumber: 1}); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("invalid root metadata error = %v", err)
	}
	if _, err := NewExtendedPublicKey(Ed25519, PublicKey{}, chainCode, Metadata{}); !errors.Is(err, ErrPublicDerivationUnsupported) {
		t.Fatalf("Ed25519 public import error = %v", err)
	}
	invalidPublic := key.PublicKey()
	invalidPublic[0] = 0x04
	if _, err := NewExtendedPublicKey(Secp256k1, invalidPublic, chainCode, Metadata{}); !errors.Is(err, ErrInvalidPublicKey) {
		t.Fatalf("invalid public key error = %v", err)
	}
}

func TestKeyAccessorsAndWipe(t *testing.T) {
	root, err := NewMasterKey(Ed25519, make([]byte, masterSeedMinSize))
	if err != nil {
		t.Fatalf("NewMasterKey() error = %v", err)
	}
	copyKey := root.PrivateKey()
	copyKey[0] ^= 0xff
	if copyKey == root.PrivateKey() {
		t.Fatal("PrivateKey() did not return a value copy")
	}
	public := root.Public()
	if public.Curve() != Ed25519 || public.PublicKey() != root.PublicKey() {
		t.Fatal("Public() did not preserve public components")
	}
	wantPublic := public.PublicKey()
	wantChainCode := public.ChainCode()

	root.Wipe()
	if root.Curve() != 0 || root.PrivateKey() != (PrivateKey{}) || root.PublicKey() != (PublicKey{}) || root.ChainCode() != (ChainCode{}) || root.Metadata() != (Metadata{}) || root.Fingerprint() != (Fingerprint{}) {
		t.Fatal("Wipe() did not clear the extended private key")
	}
	if public.PublicKey() != wantPublic || public.ChainCode() != wantChainCode || public.Curve() != Ed25519 {
		t.Fatal("Wipe() modified a detached public-key copy")
	}
}

func TestNilKeyBehavior(t *testing.T) {
	var private *ExtendedPrivateKey
	if _, err := private.Child(0); !errors.Is(err, ErrNilKey) {
		t.Fatalf("private.Child() error = %v", err)
	}
	if _, err := private.Derive("m"); !errors.Is(err, ErrNilKey) {
		t.Fatalf("private.Derive() error = %v", err)
	}
	if private.Public() != nil || private.PrivateKey() != (PrivateKey{}) || private.Fingerprint() != (Fingerprint{}) {
		t.Fatal("nil private getters returned non-zero values")
	}
	private.Wipe()

	var public *ExtendedPublicKey
	if _, err := public.Child(0); !errors.Is(err, ErrNilKey) {
		t.Fatalf("public.Child() error = %v", err)
	}
	if _, err := public.Derive("m"); !errors.Is(err, ErrNilKey) {
		t.Fatalf("public.Derive() error = %v", err)
	}
	if public.PublicKey() != (PublicKey{}) || public.Fingerprint() != (Fingerprint{}) {
		t.Fatal("nil public getters returned non-zero values")
	}
}
