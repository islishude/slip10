package slip10

import (
	"errors"
	"reflect"
	"testing"
)

func TestParsePath(t *testing.T) {
	tests := []struct {
		path string
		want []uint32
	}{
		{path: "m"},
		{path: "m/0", want: []uint32{0}},
		{path: "m/0/1'/2h/3H", want: []uint32{0, HardenedOffset + 1, HardenedOffset + 2, HardenedOffset + 3}},
		{path: "m/2147483647", want: []uint32{maxChildIndex}},
		{path: "m/2147483647'", want: []uint32{^uint32(0)}},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			got, err := ParsePath(test.path)
			if err != nil {
				t.Fatalf("ParsePath() error = %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("ParsePath() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestParsePathRejectsMalformedInput(t *testing.T) {
	for _, path := range []string{"", "M", "m/", "m//0", "m/-1", "m/+1", "m/1x", "m/1''", "m/2147483648", "m/2147483648'"} {
		t.Run(path, func(t *testing.T) {
			if _, err := ParsePath(path); !errors.Is(err, ErrInvalidPath) {
				t.Fatalf("ParsePath(%q) error = %v, want ErrInvalidPath", path, err)
			}
		})
	}
}

func TestHardenHelpers(t *testing.T) {
	index, err := Harden(42)
	if err != nil || index != HardenedOffset+42 || !IsHardened(index) {
		t.Fatalf("Harden(42) = %d, %v", index, err)
	}
	base, err := Unharden(index)
	if err != nil || base != 42 {
		t.Fatalf("Unharden() = %d, %v", base, err)
	}
	if _, err := Harden(HardenedOffset); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("Harden(HardenedOffset) error = %v", err)
	}
	if _, err := Unharden(42); !errors.Is(err, ErrNonHardenedDerivation) {
		t.Fatalf("Unharden(42) error = %v", err)
	}
}
