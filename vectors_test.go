package slip10

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type vectorFile []struct {
	Name  string       `json:"name"`
	Seed  string       `json:"seed"`
	Cases []vectorCase `json:"cases"`
}

type vectorCase struct {
	Path        string `json:"path"`
	Fingerprint string `json:"fingerprint"`
	ChainCode   string `json:"chainCode"`
	Private     string `json:"private"`
	Public      string `json:"public"`
}

func TestOfficialEd25519Vectors(t *testing.T) {
	vectors := loadVectors(t)

	for _, vector := range vectors {
		seed := mustDecodeHex(t, vector.Seed)
		for _, tc := range vector.Cases {
			t.Run(vector.Name+"/"+tc.Path, func(t *testing.T) {
				key, err := DerivePath(seed, tc.Path)
				if err != nil {
					t.Fatalf("DerivePath() error = %v", err)
				}

				assertHexBytes(t, "Seed", key.Seed(), tc.Private)
				assertHexBytes(t, "ChainCode", key.ChainCode(), tc.ChainCode)
				assertHexBytes(t, "SLIP10PublicKey", key.SLIP10PublicKey(), tc.Public)

				parentFingerprint := key.ParentFingerprint()
				assertHexBytes(t, "ParentFingerprint", parentFingerprint[:], tc.Fingerprint)

				indexes, err := ParsePath(tc.Path)
				if err != nil {
					t.Fatalf("ParsePath() error = %v", err)
				}
				if got, want := int(key.Depth()), len(indexes); got != want {
					t.Fatalf("Depth() = %d, want %d", got, want)
				}
				if len(indexes) == 0 {
					if got := key.ChildNumber(); got != 0 {
						t.Fatalf("ChildNumber() = %d, want 0", got)
					}
				} else if got, want := key.ChildNumber(), indexes[len(indexes)-1]; got != want {
					t.Fatalf("ChildNumber() = %d, want %d", got, want)
				}
			})
		}
	}
}

func TestFingerprintMatchesVectorParentFingerprint(t *testing.T) {
	seed := mustDecodeHex(t, "000102030405060708090a0b0c0d0e0f")
	root, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey() error = %v", err)
	}

	rootFingerprint := root.Fingerprint()
	assertHexBytes(t, "root Fingerprint", rootFingerprint[:], "ddebc675")

	child, err := root.Child(HardenedOffset)
	if err != nil {
		t.Fatalf("Child() error = %v", err)
	}
	childParentFingerprint := child.ParentFingerprint()
	assertHexBytes(t, "child parent fingerprint", childParentFingerprint[:], "ddebc675")
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()

	data, err := os.ReadFile("testdata/slip10_ed25519_vectors.json")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	var vectors vectorFile
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	return vectors
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()

	out, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("DecodeString(%q) error = %v", s, err)
	}
	return out
}

func assertHexBytes(t *testing.T, name string, got []byte, wantHex string) {
	t.Helper()

	want := mustDecodeHex(t, wantHex)
	if hex.EncodeToString(got) != wantHex {
		t.Fatalf("%s = %x, want %x", name, got, want)
	}
}
