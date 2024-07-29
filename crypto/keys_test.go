package crypto

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratePrivateKey(t *testing.T) {

	privKey := GeneratePrivateKey()
	assert.Equal(t, privateKeyLen, len(privKey.Bytes()))

	publicKey := privKey.Public()
	assert.Equal(t, publicKeyLen, len(publicKey.Bytes()))
}

func TestPrivateKeySign(t *testing.T) {

	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	message := []byte("Hello, World!")

	sig := privKey.Sign(message)
	assert.True(t, sig.Verify(pubKey, message))

	// Test with invlid message
	assert.False(t, sig.Verify(pubKey, []byte("faux message")))

	// test with invalid public key
	fauxPrivKey := GeneratePrivateKey()
	fauxPubKey := fauxPrivKey.Public()
	assert.False(t, sig.Verify(fauxPubKey, message))
}

func TestPublicKeyToAddress(t *testing.T) {

	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	address := pubKey.Address()
	assert.Equal(t, addressLen, len(address.Bytes()))
	fmt.Println(address)
}
