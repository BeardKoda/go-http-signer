// Package demokey provides a fixed Ed25519 key pair so the examples can talk
// to each other. Never use a hard-coded key outside of examples.
package demokey

import "crypto/ed25519"

const KeyID = "example-key"

var seed = []byte("httpsig-go example seed (demo!!)") // 32 bytes

func Private() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(seed) }

func Public() ed25519.PublicKey { return Private().Public().(ed25519.PublicKey) }
