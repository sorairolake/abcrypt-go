// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package abcrypt

import (
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	defaultArgon2Type    = Argon2id
	defaultArgon2Version = Version0x13
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
//
// This uses Argon2id as the Argon2 type.
func NewEncryptorWithParams(plaintext, passphrase []byte, memoryCost, timeCost uint32, parallelism uint8) *Encryptor {
	return NewEncryptorWithType(plaintext, passphrase, defaultArgon2Type, memoryCost, timeCost, parallelism)
}

// NewEncryptorWithType creates a new [Encryptor] with the given Argon2 type
// and Argon2 parameters.
//
// This uses version 0x13 as the Argon2 version.
func NewEncryptorWithType(plaintext, passphrase []byte, argon2Type Argon2Type, memoryCost, timeCost uint32, parallelism uint8) *Encryptor {
	return NewEncryptorWithVersion(plaintext, passphrase, argon2Type, defaultArgon2Version, memoryCost, timeCost, parallelism)
}

// NewEncryptorWithVersion creates a new [Encryptor] with the given Argon2
// type, Argon2 version and Argon2 parameters.
func NewEncryptorWithVersion(plaintext, passphrase []byte, argon2Type Argon2Type, argon2Version Argon2Version, memoryCost, timeCost uint32, parallelism uint8) *Encryptor {
	header := newHeader(argon2Type, argon2Version, memoryCost, timeCost, uint32(parallelism))

	if header.argon2Type == Argon2d {
		msg := "abcrypt: Argon2d is not supported"
		panic(msg)
	}

	if header.argon2Version == Version0x10 {
		msg := "abcrypt: version 0x10 is not supported"
		panic(msg)
	}

	s := header.salt[:]
	t := header.timeCost
	m := header.memoryCost
	p := uint8(header.parallelism)

	var k []byte

	switch header.argon2Type {
	case Argon2d:
		panic("abcrypt: entered unreachable code")
	case Argon2i:
		k = argon2.Key(passphrase, s, t, m, p, derivedKeySize)
	case Argon2id:
		k = argon2.IDKey(passphrase, s, t, m, p, derivedKeySize)
	}

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
// This uses Argon2id as the Argon2 type.
//
// This is a convenience function for using [NewEncryptorWithParams] and
// [Encryptor.Encrypt].
func EncryptWithParams(plaintext, passphrase []byte, memoryCost, timeCost uint32, parallelism uint8) []byte {
	return NewEncryptorWithParams(plaintext, passphrase, memoryCost, timeCost, parallelism).Encrypt()
}

// EncryptWithType encrypts the plaintext with the given Argon2 type and Argon2
// parameters and returns the ciphertext.
//
// This uses version 0x13 as the Argon2 version.
//
// This is a convenience function for using [NewEncryptorWithType] and
// [Encryptor.Encrypt].
func EncryptWithType(plaintext, passphrase []byte, argon2Type Argon2Type, memoryCost, timeCost uint32, parallelism uint8) []byte {
	return NewEncryptorWithType(plaintext, passphrase, argon2Type, memoryCost, timeCost, parallelism).Encrypt()
}

// EncryptWithVersion encrypts the plaintext with the given Argon2 type, Argon2
// version and Argon2 parameters and returns the ciphertext.
//
// This is a convenience function for using [NewEncryptorWithVersion] and
// [Encryptor.Encrypt].
func EncryptWithVersion(plaintext, passphrase []byte, argon2Type Argon2Type, argon2Version Argon2Version, memoryCost, timeCost uint32, parallelism uint8) []byte {
	return NewEncryptorWithVersion(plaintext, passphrase, argon2Type, argon2Version, memoryCost, timeCost, parallelism).Encrypt()
}
