// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package abcrypt

import (
	"crypto/rand"
	"encoding/binary"
	"slices"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	magicNumber     = "abcrypt"
	magicNumberSize = 7
)

// version is a type that represents the version of the abcrypt encrypted data
// format.
type version byte

const (
	// version0 indicates version 0.
	version0 version = iota

	// version1 indicates version 1.
	version1
)

// Argon2Type is a type that represents the Argon2 type.
type Argon2Type uint32

const (
	// argon2d indicates Argon2d.
	argon2d Argon2Type = iota

	// Argon2i indicates Argon2i.
	Argon2i

	// Argon2id indicates Argon2id.
	Argon2id
)

// argon2Version is a type that represents the Argon2 version.
type argon2Version uint32

const (
	// version0x10 indicates version 0x10.
	version0x10 argon2Version = 0x10

	// version0x13 indicates version 0x13.
	version0x13 argon2Version = 0x13
)

const saltSize = 32

type header struct {
	magicNumber   [magicNumberSize]byte
	version       version
	argon2Type    Argon2Type
	argon2Version argon2Version
	memoryCost    uint32
	timeCost      uint32
	parallelism   uint32
	salt          [saltSize]byte
	nonce         [chacha20poly1305.NonceSizeX]byte
	mac           [blake2b.Size]byte
}

func newHeader(argon2Type Argon2Type, argon2Version argon2Version, memoryCost, timeCost, parallelism uint32) *header {
	var header header

	header.magicNumber = [magicNumberSize]byte([]byte(magicNumber))
	header.version = version1

	switch argon2Type {
	case argon2d, Argon2i, Argon2id:
		header.argon2Type = argon2Type
	default:
		panic("abcrypt: invalid Argon2 type")
	}

	switch argon2Version {
	case version0x10, version0x13:
		header.argon2Version = argon2Version
	default:
		panic("abcrypt: invalid Argon2 version")
	}

	header.memoryCost = memoryCost
	header.timeCost = timeCost
	header.parallelism = parallelism

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}

	header.salt = [saltSize]byte(salt)

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	header.nonce = [chacha20poly1305.NonceSizeX]byte(nonce)

	return &header
}

func parse(data []byte) (*header, error) {
	if len(data) < HeaderSize+TagSize {
		return nil, ErrInvalidLength
	}

	var header header

	if !slices.Equal(data[:7], []byte(magicNumber)) {
		return nil, ErrInvalidMagicNumber
	}

	header.magicNumber = [magicNumberSize]byte([]byte(magicNumber))

	switch v := version(data[7]); v {
	case version0:
		return nil, &UnsupportedVersionError{byte(v)}
	case version1:
		header.version = v
	default:
		return nil, &UnknownVersionError{byte(v)}
	}

	switch t := Argon2Type(binary.LittleEndian.Uint32(data[8:12])); t {
	case argon2d, Argon2i, Argon2id:
		header.argon2Type = t
	default:
		return nil, &InvalidArgon2TypeError{uint32(t)}
	}

	switch v := argon2Version(binary.LittleEndian.Uint32(data[12:16])); v {
	case version0x10, version0x13:
		header.argon2Version = v
	default:
		return nil, &InvalidArgon2VersionError{uint32(v)}
	}

	header.memoryCost = binary.LittleEndian.Uint32(data[16:20])
	header.timeCost = binary.LittleEndian.Uint32(data[20:24])
	header.parallelism = binary.LittleEndian.Uint32(data[24:28])
	header.salt = [saltSize]byte(data[28:60])
	header.nonce = [chacha20poly1305.NonceSizeX]byte(data[60:84])

	return &header, nil
}

func (h *header) computeMAC(key []byte) {
	mac, err := blake2b.New512(key)
	if err != nil {
		panic(err)
	}

	header := h.asBytes()
	mac.Write(header[:84])

	h.mac = [blake2b.Size]byte(mac.Sum(nil))
}

func (h *header) verifyMAC(key, tag []byte) error {
	mac, err := blake2b.New512(key)
	if err != nil {
		panic(err)
	}

	header := h.asBytes()
	mac.Write(header[:84])

	if !slices.Equal(mac.Sum(nil), tag) {
		return &InvalidHeaderMACError{[64]byte(tag)}
	}

	h.mac = [blake2b.Size]byte(tag)

	return nil
}

func (h *header) asBytes() [HeaderSize]byte {
	var header [HeaderSize]byte

	copy(header[:7], h.magicNumber[:])
	header[7] = byte(h.version)
	binary.LittleEndian.PutUint32(header[8:12], uint32(h.argon2Type))
	binary.LittleEndian.PutUint32(header[12:16], uint32(h.argon2Version))
	binary.LittleEndian.PutUint32(header[16:20], h.memoryCost)
	binary.LittleEndian.PutUint32(header[20:24], h.timeCost)
	binary.LittleEndian.PutUint32(header[24:28], h.parallelism)
	copy(header[28:60], h.salt[:])
	copy(header[60:84], h.nonce[:])
	copy(header[84:], h.mac[:])

	return header
}

type derivedKey struct {
	encrypt [chacha20poly1305.KeySize]byte
	mac     [blake2b.Size]byte
}

const derivedKeySize = 96

func newDerivedKey(dk [derivedKeySize]byte) *derivedKey {
	k := derivedKey{[chacha20poly1305.KeySize]byte(dk[:32]), [blake2b.Size]byte(dk[32:])}

	return &k
}
