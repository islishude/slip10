// package slip10ed25519 implements SLIP-0010 Ed25519 hardened-only private key
// derivation.
//
// Derived private material is a 32-byte RFC 8032 Ed25519 seed plus a 32-byte
// chain code. The package does not implement public child derivation,
// non-hardened derivation, BIP32 xpub handling, or Ed25519 scalar arithmetic.
package slip10ed25519
