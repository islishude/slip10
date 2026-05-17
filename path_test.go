package slip10

import (
	"errors"
	"testing"
)

func TestParsePathValid(t *testing.T) {
	tests := []struct {
		path string
		want []uint32
	}{
		{path: "m", want: nil},
		{path: "m/0'", want: []uint32{0x80000000}},
		{path: "m/0h/1H/2'", want: []uint32{0x80000000, 0x80000001, 0x80000002}},
		{path: "m/2147483647'", want: []uint32{0xffffffff}},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			got, err := ParsePath(tc.path)
			if err != nil {
				t.Fatalf("ParsePath() error = %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("ParsePath() len = %d, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("ParsePath()[%d] = %d, want %d", i, got[i], tc.want[i])
				}
				if !IsHardened(got[i]) {
					t.Fatalf("ParsePath()[%d] = %d, want hardened index", i, got[i])
				}
			}
		})
	}
}

func TestParsePathInvalid(t *testing.T) {
	tests := []struct {
		path string
		want error
	}{
		{path: "m/0", want: ErrNonHardenedDerivation},
		{path: "m/0/1'", want: ErrNonHardenedDerivation},
		{path: "m/-1'", want: ErrInvalidPath},
		{path: "m/2147483648'", want: ErrInvalidPath},
		{path: "m/0''", want: ErrInvalidPath},
		{path: "m//0'", want: ErrInvalidPath},
		{path: "n/0'", want: ErrInvalidPath},
		{path: "/0'", want: ErrInvalidPath},
		{path: "", want: ErrInvalidPath},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			_, err := ParsePath(tc.path)
			if !errors.Is(err, tc.want) {
				t.Fatalf("ParsePath() error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestHardenHelpers(t *testing.T) {
	got, err := Harden(42)
	if err != nil {
		t.Fatalf("Harden() error = %v", err)
	}
	if got != HardenedOffset+42 {
		t.Fatalf("Harden(42) = %d, want %d", got, HardenedOffset+42)
	}
	if !IsHardened(got) {
		t.Fatalf("IsHardened(%d) = false, want true", got)
	}

	unhardened, err := Unharden(got)
	if err != nil {
		t.Fatalf("Unharden() error = %v", err)
	}
	if unhardened != 42 {
		t.Fatalf("Unharden() = %d, want 42", unhardened)
	}

	if _, err := Harden(HardenedOffset); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("Harden(HardenedOffset) error = %v, want ErrInvalidPath", err)
	}
	if _, err := Unharden(42); !errors.Is(err, ErrNonHardenedDerivation) {
		t.Fatalf("Unharden(42) error = %v, want ErrNonHardenedDerivation", err)
	}
}
