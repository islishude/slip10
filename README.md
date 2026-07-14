# slip10

Pure-Go implementation of the fixed
[SLIP-0010 specification](https://github.com/satoshilabs/slips/blob/0c9ce4e7cc53371e4d132563c1d4e1ce7351e707/slip-0010.md)
for secp256k1, NIST P-256, Ed25519, and Curve25519.

- Requires Go 1.25 or newer.
- Uses no CGO or assembly from this repository.
- Supports private and public extended-key derivation where SLIP-0010 defines it.

## Install

```sh
go get github.com/islishude/slip10
```

## Usage

```go
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/islishude/slip10"
)

func main() {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")

	key, err := slip10.DerivePath(slip10.Secp256k1, seed, "m/0'/1/2h")
	if err != nil {
		panic(err)
	}

	fmt.Printf("private: %x\n", key.PrivateKey())
	fmt.Printf("public:  %x\n", key.PublicKey())
	fmt.Printf("chain:   %x\n", key.ChainCode())
}
```

Paths are absolute and accept `'`, `h`, or `H` as hardened suffixes:

```text
m/0/1'/2h/3H
```

## Capabilities

| Curve      | Private child derivation | Public child derivation |
| ---------- | ------------------------ | ----------------------- |
| secp256k1  | Normal and hardened      | Normal                  |
| NIST P-256 | Normal and hardened      | Normal                  |
| Ed25519    | Hardened only            | No                      |
| Curve25519 | Hardened only            | No                      |

Private keys and chain codes are 32 bytes. Public keys are 33 bytes: compressed
SEC1 for the ECDSA curves, and `0x00 || public[32]` for Ed25519 and Curve25519.
Fingerprints are the first four bytes of `HASH160(ser_P(public))`.

The package does not implement mnemonics, signing, Base58 xprv/xpub encoding,
or private extended-key serialization. `ExtendedPrivateKey.Wipe` is best-effort;
it cannot clear copies made by the Go compiler, runtime, or caller.

## Development

```sh
go run ./internal/cmd/genarith -check
go test ./...
go test -race ./...
go vet ./...
```
