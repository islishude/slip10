# slip10

`slip10` is a pure-Go implementation of the fixed
[SLIP-0010 specification](https://github.com/satoshilabs/slips/blob/0c9ce4e7cc53371e4d132563c1d4e1ce7351e707/slip-0010.md)
for all four specified curves. It requires Go 1.25 or newer and has no CGO or
assembly in this repository. Its only external runtime dependency is
`golang.org/x/crypto/ripemd160`, used for fingerprints.

This version is a breaking replacement for the former `slip10ed25519`
subpackage. That package, its method signatures, and the package-local
`SL10EDV1` encoding no longer exist; there is no compatibility layer.

## Curve capabilities

| Curve      | SLIP-0010 name | Hardened CKDpriv | Normal CKDpriv | Normal CKDpub |
| ---------- | -------------- | :--------------: | :------------: | :-----------: |
| secp256k1  | `secp256k1`    |       yes        |      yes       |      yes      |
| NIST P-256 | `nist256p1`    |       yes        |      yes       |      yes      |
| Ed25519    | `ed25519`      |       yes        |       no       |      no       |
| Curve25519 | `curve25519`   |       yes        |       no       |      no       |

Trying a normal private child on Ed25519 or Curve25519 returns
`ErrNonHardenedDerivation`. Public parents are importable only for the two
ECDSA curves; their hardened public children return
`ErrHardenedPublicDerivation`.

## Install and use

```sh
go get github.com/islishude/slip10
```

```go
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/islishude/slip10"
)

func main() {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")

	private, err := slip10.DerivePath(slip10.Secp256k1, seed, "m/0'/1/2h/3")
	if err != nil {
		panic(err)
	}
	public := private.Public()

	fmt.Printf("private: %x\n", private.PrivateKey())
	fmt.Printf("public:  %x\n", public.PublicKey())
	fmt.Printf("chain:   %x\n", private.ChainCode())
	fmt.Printf("fingerprint: %x\n", private.Fingerprint())

	// ECDSA public derivation accepts normal indexes only.
	child, err := public.Child(4)
	if err != nil {
		panic(err)
	}
	fmt.Printf("public child: %x\n", child.PublicKey())
}
```

The main constructors are:

```go
NewMasterKey(curve, seed)
DerivePath(curve, seed, path)
NewExtendedPrivateKey(curve, key, chainCode, metadata)
NewExtendedPublicKey(curve, key, chainCode, metadata)
```

Extended keys expose their components as fixed-size value copies. An
`ExtendedPrivateKey` also has a best-effort `Wipe` method; this cannot erase
copies previously made by the Go compiler, runtime, or caller.

## Paths and indexes

Paths are absolute and accept normal segments plus all common hardened
suffixes:

```text
m/0/1'/2h/3H
```

Capability restrictions are checked during derivation, not parsing. `Harden`,
`Unharden`, and `IsHardened` are available for raw child numbers.

## Key byte semantics

All externally visible values have fixed sizes:

```go
type PrivateKey  [32]byte
type PublicKey   [33]byte
type ChainCode   [32]byte
type Fingerprint [4]byte
```

- secp256k1 and NIST P-256 private keys are canonical, non-zero, big-endian
  scalars below the curve order. Their public keys are compressed 33-byte SEC1.
- An Ed25519 private key is the raw 32-byte RFC 8032 seed used by
  `crypto/ed25519.NewKeyFromSeed`.
- A Curve25519 private key is the raw 32-byte RFC 7748 scalar input used by
  `crypto/ecdh.X25519`; clamping occurs inside the standard-library operation.
- Ed25519 and Curve25519 public serialization is `0x00 || public[32]`, exactly
  the SLIP-0010 `ser_P` representation.

Fingerprints are `HASH160(ser_P(public))[0:4]`. The library deliberately does
not implement signatures, mnemonic phrases, Base58 xprv/xpub, or any private
extended-key serialization.

## Arithmetic generation

The checked-in secp256k1 and P-256 field/scalar Montgomery arithmetic is
generated with a single 64-bit limb type and `math/bits`. Generation uses the
pinned image for
[`fiat-crypto-go-tool`](https://github.com/islishude/fiat-crypto-go-tool/tree/cffa6010a1adeac65787e6db7dcb8e33c09a677f):

```text
ghcr.io/islishude/fiat-crypto-go-tool@sha256:fa7d326be7c8ce419573e4f3165a88a41dfb0d29276887dd3c9de643f2723424
```

With Docker available, regenerate or perform a read-only consistency check:

```sh
go generate ./...
go run ./internal/cmd/genarith -check
```

The generator rejects `TODO` markers and verifies every output with
`go/format`. The committed addchain programs and templates generate field
inversion with exponent `p-2` and square root candidates with `(p+1)/4`.

## Security and verification

ECDSA point multiplication always runs a 256-round Montgomery ladder. Each
round performs the same complete addition/doubling work and uses constant-time
conditional swaps. Point addition uses the complete Renes-Costello-Batina
[formulas](https://eprint.iacr.org/2015/1060) for `a=0` and `a=-3`; private and
field arithmetic never uses `math/big` in production code.

SLIP-0010 requires retrying invalid HMAC candidates. The number of HMAC
iterations is therefore data-dependent by specification, including retries for
`I_L >= n`, a zero private child, or an infinite public child. Path validation,
public-key decoding, allocation, and the best-effort wiping API are also not a
constant-time boundary.

The tests include all 52 nodes from the pinned upstream vectors, independent
`math/big` differential oracles confined to `_test.go`, retry-state injection,
CKDpriv/CKDpub equivalence, parser fuzz seeds, and exceptional point cases.

```sh
go run ./internal/cmd/genarith -check
go test ./...
go test -race ./...
go vet ./...
```
