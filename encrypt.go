// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package abcrypt

import (
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	defaultMemoryCost  = 19456
	defaultTimeCost    = 2
	defaultParallelism = 1
)

// Encryptor represents an encryptor for the abcrypt encrypted data format.
type Encryptor struct {
	header    *header
	dk        *derivedKey
	plaintext []byte
}

// NewEncryptor creates a new [Encryptor].
//
// This uses the [recommended Argon2 parameters].
//
// [recommended Argon2 parameters]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
func NewEncryptor(plaintext, passphrase []byte) *Encryptor {
	return NewEncryptorWithParams(plaintext, passphrase, defaultMemoryCost, defaultTimeCost, defaultParallelism)
}

// NewEncryptorWithParams creates a new [Encryptor] with the given Argon2
// parameters.
func NewEncryptorWithParams(plaintext, passphrase []byte, memoryCost, timeCost uint32, parallelism uint8) *Encryptor {
	header := newHeader(memoryCost, timeCost, uint32(parallelism))

	s := header.salt[:]
	t := header.timeCost
	m := header.memoryCost
	p := uint8(header.parallelism)
	k := argon2.IDKey(passphrase, s, t, m, p, derivedKeySize)
	derivedKey := newDerivedKey([derivedKeySize]byte(k))

	header.computeMAC(derivedKey.mac[:])

	e := Encryptor{header, derivedKey, plaintext}

	return &e
}

// Encrypt encrypts the plaintext and returns the ciphertext.
func (e *Encryptor) Encrypt() []byte {
	header := e.header.asBytes()

	cipher, err := chacha20poly1305.NewX(e.dk.encrypt[:])
	if err != nil {
		panic(err)
	}

	ciphertext := cipher.Seal(nil, e.header.nonce[:], e.plaintext, nil)

	out := append(header[:], ciphertext...)

	return out
}

// OutLen returns the number of output bytes of the encrypted data.
func (e *Encryptor) OutLen() int {
	return HeaderSize + len(e.plaintext) + TagSize
}

// Encrypt encrypts the plaintext and returns the ciphertext.
//
// This uses the [recommended Argon2 parameters].
//
// This is a convenience function for using [NewEncryptor] and
// [Encryptor.Encrypt].
//
// [recommended Argon2 parameters]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
func Encrypt(plaintext, passphrase []byte) []byte {
	return NewEncryptor(plaintext, passphrase).Encrypt()
}

// EncryptWithParams encrypts the plaintext with the given Argon2 parameters
// and returns the ciphertext.
//
// This is a convenience function for using [NewEncryptorWithParams] and
// [Encryptor.Encrypt].
func EncryptWithParams(plaintext, passphrase []byte, memoryCost, timeCost uint32, parallelism uint8) []byte {
	return NewEncryptorWithParams(plaintext, passphrase, memoryCost, timeCost, parallelism).Encrypt()
}
