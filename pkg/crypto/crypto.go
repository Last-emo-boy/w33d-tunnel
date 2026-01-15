package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	KeySize   = 32
	NonceSize = 12
)

// GenerateKeyPair generates a new X25519 key pair.
func GenerateKeyPair() (privateKey, publicKey []byte, err error) {
	privateKey = make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, privateKey); err != nil {
		return nil, nil, err
	}
	publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, publicKey, nil
}

// ComputeSharedSecret computes the X25519 shared secret.
func ComputeSharedSecret(privateKey, peersPublicKey []byte) ([]byte, error) {
	return curve25519.X25519(privateKey, peersPublicKey)
}

// GetPublicKey derives the public key from the private key.
func GetPublicKey(privateKey []byte) ([]byte, error) {
	return curve25519.X25519(privateKey, curve25519.Basepoint)
}

// DeriveKeys uses HKDF to derive session keys.
func DeriveKeys(secret, salt []byte, info string, length int) ([]byte, error) {
	h := hkdf.New(sha256.New, secret, salt, []byte(info))
	out := make([]byte, length)
	if _, err := io.ReadFull(h, out); err != nil {
		return nil, err
	}
	return out, nil
}

// Encrypt encrypts plaintext using ChaCha20Poly1305.
func Encrypt(key, nonce, plaintext, additionalData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != NonceSize {
		return nil, errors.New("invalid nonce size")
	}
	return aead.Seal(nil, nonce, plaintext, additionalData), nil
}

// Decrypt decrypts ciphertext using ChaCha20Poly1305.
func Decrypt(key, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != NonceSize {
		return nil, errors.New("invalid nonce size")
	}
	return aead.Open(nil, nonce, ciphertext, additionalData)
}

// ComputeHMAC computes HMAC-SHA256.
func ComputeHMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// RandomBytes generates n random bytes.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	io.ReadFull(rand.Reader, b)
	return b
}

// GenerateHeaderMask generates an 8-byte mask using HMAC-SHA256(Key, Sample).
// This is used for header obfuscation.
func GenerateHeaderMask(key, sample []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(sample)
	sum := h.Sum(nil)
	return sum[:8]
}
