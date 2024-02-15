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

	if header.parallelism > math.MaxUint8 {
		msg := fmt.Sprintf("abcrypt: this package does not support the degree of parallelism `p` greater than %v", math.MaxUint8)
		panic(msg)
	}
	k := argon2.IDKey(passphrase, header.salt[:], header.timeCost, header.memoryCost, uint8(header.parallelism), derivedKeySize)
	dk := newDerivedKey([derivedKeySize]byte(k))

	if err := header.verifyMAC(dk.mac[:], ciphertext[76:HeaderSize]); err != nil {
		return nil, err
	}

	d := Decryptor{header, dk, ciphertext[HeaderSize:]}
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
