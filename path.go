package slip10

import (
	"fmt"
	"strconv"
	"strings"
)

const maxHardenableIndex = HardenedOffset - 1

func Harden(i uint32) (uint32, error) {
	if i >= HardenedOffset {
		return 0, fmt.Errorf("%w: index %d", ErrInvalidPath, i)
	}
	return i + HardenedOffset, nil
}

func IsHardened(i uint32) bool {
	return i >= HardenedOffset
}

func Unharden(i uint32) (uint32, error) {
	if !IsHardened(i) {
		return 0, ErrNonHardenedDerivation
	}
	return i - HardenedOffset, nil
}

func ParsePath(path string) ([]uint32, error) {
	if path == "m" {
		return nil, nil
	}
	if !strings.HasPrefix(path, "m/") {
		return nil, fmt.Errorf("%w: %q", ErrInvalidPath, path)
	}

	parts := strings.Split(path[2:], "/")
	out := make([]uint32, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("%w: empty segment", ErrInvalidPath)
		}

		suffix := part[len(part)-1]
		// Ed25519 has no non-hardened derivation in SLIP-0010, so every path
		// segment must opt into hardened form.
		if suffix != '\'' && suffix != 'h' && suffix != 'H' {
			return nil, fmt.Errorf("%w: segment %q", ErrNonHardenedDerivation, part)
		}

		numeric := part[:len(part)-1]
		if numeric == "" {
			return nil, fmt.Errorf("%w: segment %q", ErrInvalidPath, part)
		}
		for _, r := range numeric {
			if r < '0' || r > '9' {
				return nil, fmt.Errorf("%w: segment %q", ErrInvalidPath, part)
			}
		}

		base, err := strconv.ParseUint(numeric, 10, 32)
		if err != nil || base > uint64(maxHardenableIndex) {
			return nil, fmt.Errorf("%w: segment %q", ErrInvalidPath, part)
		}

		out = append(out, uint32(base)+HardenedOffset)
	}

	return out, nil
}
