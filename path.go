package slip10

import (
	"fmt"
	"strconv"
	"strings"
)

const maxChildIndex = HardenedOffset - 1

// Harden marks a normal child index as hardened.
func Harden(index uint32) (uint32, error) {
	if index >= HardenedOffset {
		return 0, fmt.Errorf("%w: index %d", ErrInvalidPath, index)
	}
	return index + HardenedOffset, nil
}

// IsHardened reports whether index denotes a hardened child.
func IsHardened(index uint32) bool {
	return index >= HardenedOffset
}

// Unharden returns the base index of a hardened child index.
func Unharden(index uint32) (uint32, error) {
	if !IsHardened(index) {
		return 0, ErrNonHardenedDerivation
	}
	return index - HardenedOffset, nil
}

// ParsePath parses an absolute SLIP-0010 path. A missing suffix denotes a
// normal child. The suffixes ', h, and H denote a hardened child.
func ParsePath(path string) ([]uint32, error) {
	if path == "m" {
		return nil, nil
	}
	if !strings.HasPrefix(path, "m/") {
		return nil, fmt.Errorf("%w: %q", ErrInvalidPath, path)
	}

	parts := strings.Split(path[2:], "/")
	indexes := make([]uint32, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("%w: empty segment", ErrInvalidPath)
		}

		hardened := false
		last := part[len(part)-1]
		if last == '\'' || last == 'h' || last == 'H' {
			hardened = true
			part = part[:len(part)-1]
		}
		if part == "" {
			return nil, fmt.Errorf("%w: empty segment", ErrInvalidPath)
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return nil, fmt.Errorf("%w: segment %q", ErrInvalidPath, part)
			}
		}

		base, err := strconv.ParseUint(part, 10, 31)
		if err != nil || base > uint64(maxChildIndex) {
			return nil, fmt.Errorf("%w: segment %q", ErrInvalidPath, part)
		}
		index := uint32(base)
		if hardened {
			index += HardenedOffset
		}
		indexes = append(indexes, index)
	}
	return indexes, nil
}
