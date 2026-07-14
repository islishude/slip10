// Package slip10 implements universal hierarchical deterministic key
// derivation as specified by SLIP-0010.
//
// It supports secp256k1, NIST P-256, Ed25519, and Curve25519. The two
// short-Weierstrass curves support hardened and non-hardened private child
// derivation as well as non-hardened public child derivation. Ed25519 and
// Curve25519 support hardened private child derivation only.
package slip10
