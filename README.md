# slip10

`slip10` implements the Ed25519 hardened-only branch of
[SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md) in
Go.

The package derives a 32-byte RFC 8032 Ed25519 seed and a 32-byte chain code
from a BIP32-sized seed (`16..64` bytes). Child derivation follows the
SLIP-0010 Ed25519 rule:

```text
I = HMAC-SHA512(Key = c_par, Data = 0x00 || k_par || ser32(i))
k_i = I_L
c_i = I_R
```

Only hardened child indexes are supported. Non-hardened derivation, public child
derivation, BIP32 xpub handling, and Ed25519 scalar arithmetic are intentionally
out of scope.

## Install

```sh
go get github.com/islishude/slip10
```

## Example

```go
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/islishude/slip10"
)

func main() {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")

	key, err := slip10.DerivePath(seed, "m/0'/1'")
	if err != nil {
		panic(err)
	}

	fmt.Printf("seed: %x\n", key.Seed())
	fmt.Printf("chain code: %x\n", key.ChainCode())
	fmt.Printf("slip10 public key: %x\n", key.SLIP10PublicKey())
}
```

## Paths

Paths use the usual `m/...` notation. Because SLIP-0010 Ed25519 only supports
hardened private child derivation, every segment must use a hardened suffix:

```text
m/44'/501'/0'
m/44h/501h/0h
m/44H/501H/0H
```

The raw hardened index can also be built with `Harden(i)`.

## Fingerprints

SLIP-0010 defines Ed25519 public-key serialization as:

```text
ser_P(P) = 0x00 || ENC(x, y)
```

where `ENC(x, y)` is the RFC 8032 compressed point encoding.

The package exposes `Fingerprint` and `ParentFingerprint` to match the
BIP32-style metadata shown in the SLIP-0010 test vectors. The fingerprint is not
used as derivation input. It is computed the BIP32 way:

```text
fingerprint = HASH160(ser_P(public_key))[0:4]
HASH160(x) = RIPEMD160(SHA256(x))
```

## Serialization

`MarshalBinary` and `UnmarshalBinary` use a compact package-local binary format
with magic `SL10EDV1`. It is intended for round-tripping this package's
`ExtendedPrivateKey` values and is not BIP32 xprv/xpub serialization.

## Verification

The test suite includes the official SLIP-0010 Ed25519 vectors.

```sh
go test ./...
```
