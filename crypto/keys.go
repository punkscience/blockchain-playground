package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
)

const (
	privateKeyLen = 64
	publicKeyLen  = 32
	seedKeyLen    = 32
	addressLen    = 20
)

type PrivateKey struct {
	key ed25519.PrivateKey
}

func NewPrivateKeyFromSeed(seed []byte) *PrivateKey {
	if len(seed) != seedKeyLen {
		panic("Something horrible has gone wrong. Seed length must be 32.")
	}

	return &PrivateKey{key: ed25519.NewKeyFromSeed(seed)}
}

func NewPrivateKeyFromString(seed string) *PrivateKey {
	b, err := hex.DecodeString(seed)
	if err != nil {
		panic(err)
	}

	return NewPrivateKeyFromSeed(b)
}

func GeneratePrivateKey() *PrivateKey {
	seed := make([]byte, seedKeyLen)

	_, err := io.ReadFull(rand.Reader, seed)
	if err != nil {
		panic(err)
	}

	return &PrivateKey{key: ed25519.NewKeyFromSeed(seed)}
}

func (p PrivateKey) Bytes() []byte {
	return p.key
}

func (p PrivateKey) Sign(message []byte) *Signature {
	return &Signature{value: ed25519.Sign(p.key, message)}
}

func (p PrivateKey) Public() *PublicKey {
	b := make([]byte, publicKeyLen)

	copy(b, p.key[32:])
	return &PublicKey{key: b}
}

type PublicKey struct {
	key ed25519.PublicKey
}

func (p PublicKey) Bytes() []byte {
	return p.key
}

func (p *PublicKey) Address() Address {
	return Address{value: p.key[len(p.key)-addressLen:]}
}

type Signature struct {
	value []byte
}

func (s *Signature) Bytes() []byte {
	return s.value
}

func (s *Signature) Verify(publicKey *PublicKey, msg []byte) bool {
	return ed25519.Verify(publicKey.key, msg, s.value)
}

type Address struct {
	value []byte
}

func (a Address) Bytes() []byte {
	return a.value
}

func (a Address) String() string {
	return hex.EncodeToString(a.value)
}
