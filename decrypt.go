// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package abcrypt

import (
	"fmt"
	"math"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Decryptor represents a decryptor for the abcrypt encrypted data format.
type Decryptor struct {
	header     *header
	dk         *derivedKey
	ciphertext []byte
}

// NewDecryptor creates a new [Decryptor].
func NewDecryptor(ciphertext, passphrase []byte) (*Decryptor, error) {
	header, err := parse(ciphertext)
	if err != nil {
		return nil, err
	}

	if header.argon2Version == version0x10 {
		panic("abcrypt: version 0x10 is not supported")
	}

	if header.parallelism > math.MaxUint8 {
		msg := fmt.Sprintf("abcrypt: `parallelism` over %v is not supported", math.MaxUint8)
		panic(msg)
	}

	s := header.salt[:]
	t := header.timeCost
	m := header.memoryCost
	p := uint8(header.parallelism)

	var k []byte

	switch header.argon2Type {
	case argon2d:
		panic("abcrypt: Argon2d is not supported")
	case Argon2i:
		k = argon2.Key(passphrase, s, t, m, p, derivedKeySize)
	case Argon2id:
		k = argon2.IDKey(passphrase, s, t, m, p, derivedKeySize)
	}

	derivedKey := newDerivedKey([derivedKeySize]byte(k))

	if err := header.verifyMAC(derivedKey.mac[:], ciphertext[84:HeaderSize]); err != nil {
		return nil, err
	}

	d := Decryptor{header, derivedKey, ciphertext[HeaderSize:]}

	return &d, nil
}

// Decrypt decrypts the ciphertext and returns the plaintext.
func (d *Decryptor) Decrypt() ([]byte, error) {
	cipher, err := chacha20poly1305.NewX(d.dk.encrypt[:])
	if err != nil {
		panic(err)
	}

	plaintext, err := cipher.Open(nil, d.header.nonce[:], d.ciphertext, nil)
	if err != nil {
		return nil, &InvalidMACError{err}
	}

	return plaintext, nil
}

// OutLen returns the number of output bytes of the decrypted data.
func (d *Decryptor) OutLen() int {
	return len(d.ciphertext) - TagSize
}

// Decrypt decrypts the ciphertext and returns the plaintext.
//
// This is a convenience function for using [NewDecryptor] and
// [Decryptor.Decrypt].
func Decrypt(ciphertext, passphrase []byte) ([]byte, error) {
	cipher, err := NewDecryptor(ciphertext, passphrase)
	if err != nil {
		return nil, err
	}

	return cipher.Decrypt()
}
