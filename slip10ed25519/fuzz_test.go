package slip10ed25519

import "testing"

func FuzzParsePath(f *testing.F) {
	seeds := []string{
		"m",
		"m/0'",
		"m/44'/501'/0'",
		"m/0h/1H/2'",
		"m/0",
		"m//0'",
		"m/-1'",
		"m/2147483648'",
		"m/999999999999999999999'",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, path string) {
		indexes, err := ParsePath(path)
		if err != nil {
			return
		}
		for _, index := range indexes {
			if !IsHardened(index) {
				t.Fatalf("ParsePath(%q) returned non-hardened index %d", path, index)
			}
			base, err := Unharden(index)
			if err != nil {
				t.Fatalf("Unharden(%d) error = %v", index, err)
			}
			if base > maxHardenableIndex {
				t.Fatalf("ParsePath(%q) returned base index %d > %d", path, base, maxHardenableIndex)
			}
		}
	})
}
