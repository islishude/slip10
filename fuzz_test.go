package slip10

import "testing"

func FuzzParsePath(f *testing.F) {
	for _, seed := range []string{"m", "m/0", "m/0'/1/2h", "m//0", "m/-1", "m/2147483648'"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, path string) {
		indexes, err := ParsePath(path)
		if err != nil {
			return
		}
		for _, index := range indexes {
			if IsHardened(index) {
				base, err := Unharden(index)
				if err != nil || base > maxChildIndex {
					t.Fatalf("invalid hardened index %d: %v", index, err)
				}
			} else if index > maxChildIndex {
				t.Fatalf("invalid normal index %d", index)
			}
		}
	})
}

func FuzzExtendedPublicKeyImport(f *testing.F) {
	for _, curve := range []Curve{Secp256k1, NISTP256} {
		root, err := NewMasterKey(curve, make([]byte, masterSeedMinSize))
		if err != nil {
			f.Fatalf("NewMasterKey(%s) error = %v", curve, err)
		}
		public := root.PublicKey()
		f.Add(uint8(curve), public[:])
	}
	f.Add(uint8(NISTP256), make([]byte, PublicKeySize))
	invalidPrefix := make([]byte, PublicKeySize)
	invalidPrefix[0] = 0x04
	f.Add(uint8(Secp256k1), invalidPrefix)
	f.Fuzz(func(t *testing.T, curveByte uint8, input []byte) {
		if len(input) != PublicKeySize {
			return
		}
		var key PublicKey
		copy(key[:], input)
		_, _ = NewExtendedPublicKey(Curve(curveByte), key, ChainCode{}, Metadata{})
	})
}
