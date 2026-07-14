package slip10

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type vectorFile struct {
	Source string        `json:"source"`
	Groups []vectorGroup `json:"groups"`
}

type vectorGroup struct {
	Name  string       `json:"name"`
	Curve string       `json:"curve"`
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

func TestOfficialVectors(t *testing.T) {
	vectors := loadVectors(t)
	const source = "https://github.com/satoshilabs/slips/blob/0c9ce4e7cc53371e4d132563c1d4e1ce7351e707/slip-0010.md"
	if vectors.Source != source || len(vectors.Groups) != 10 {
		t.Fatalf("vector provenance/groups = %q/%d, want %q/10", vectors.Source, len(vectors.Groups), source)
	}
	total := 0
	for _, group := range vectors.Groups {
		curve := parseVectorCurve(t, group.Curve)
		seed := decodeHex(t, group.Seed)
		for i, test := range group.Cases {
			total++
			t.Run(group.Name+"/"+test.Path, func(t *testing.T) {
				key, err := DerivePath(curve, seed, test.Path)
				if err != nil {
					t.Fatalf("DerivePath() error = %v", err)
				}
				privateKey := key.PrivateKey()
				chainCode := key.ChainCode()
				publicKey := key.PublicKey()
				parentFingerprint := key.ParentFingerprint()
				assertHex(t, "private key", privateKey[:], test.Private)
				assertHex(t, "chain code", chainCode[:], test.ChainCode)
				assertHex(t, "public key", publicKey[:], test.Public)
				assertHex(t, "parent fingerprint", parentFingerprint[:], test.Fingerprint)

				indexes, err := ParsePath(test.Path)
				if err != nil {
					t.Fatalf("ParsePath() error = %v", err)
				}
				if key.Depth() != uint8(len(indexes)) {
					t.Fatalf("Depth() = %d, want %d", key.Depth(), len(indexes))
				}
				if len(indexes) == 0 {
					if key.ChildNumber() != 0 {
						t.Fatalf("ChildNumber() = %d, want 0", key.ChildNumber())
					}
				} else if key.ChildNumber() != indexes[len(indexes)-1] {
					t.Fatalf("ChildNumber() = %d, want %d", key.ChildNumber(), indexes[len(indexes)-1])
				}

				if i > 0 && curve.supportsPublicDerivation() && len(indexes) > 0 && !IsHardened(indexes[len(indexes)-1]) {
					parent, err := DerivePath(curve, seed, group.Cases[i-1].Path)
					if err != nil {
						t.Fatalf("derive parent: %v", err)
					}
					publicChild, err := parent.Public().Child(indexes[len(indexes)-1])
					if err != nil {
						t.Fatalf("public Child() error = %v", err)
					}
					if publicChild.PublicKey() != key.PublicKey() || publicChild.ChainCode() != key.ChainCode() {
						t.Fatalf("CKDpub result = (%x, %x), want (%x, %x)", publicChild.PublicKey(), publicChild.ChainCode(), key.PublicKey(), key.ChainCode())
					}
				}
			})
		}
	}
	if total != 52 {
		t.Fatalf("official vector count = %d, want 52", total)
	}
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	data, err := os.ReadFile("testdata/slip10_vectors.json")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var vectors vectorFile
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	return vectors
}

func parseVectorCurve(t *testing.T, name string) Curve {
	t.Helper()
	switch name {
	case "secp256k1":
		return Secp256k1
	case "nist256p1":
		return NISTP256
	case "ed25519":
		return Ed25519
	case "curve25519":
		return Curve25519
	default:
		t.Fatalf("unknown vector curve %q", name)
		return 0
	}
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("DecodeString(%q) error = %v", value, err)
	}
	return decoded
}

func assertHex(t *testing.T, name string, got []byte, want string) {
	t.Helper()
	if hex.EncodeToString(got) != want {
		t.Fatalf("%s = %x, want %s", name, got, want)
	}
}
