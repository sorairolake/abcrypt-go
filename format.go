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

const magicNumber = "abcrypt"
const magicNumberSize = 7

type version uint8

const (
	version0 version = iota
	version1
)

const saltSize = 32

type header struct {
	magicNumber [magicNumberSize]byte
	version     version
	memoryCost  uint32
	timeCost    uint32
	parallelism uint32
	salt        [saltSize]byte
	nonce       [chacha20poly1305.NonceSizeX]byte
	mac         [blake2b.Size]byte
}

func newHeader(memoryCost, timeCost, parallelism uint32) *header {
	var header header

	header.magicNumber = [magicNumberSize]byte([]byte(magicNumber))
	header.version = version0
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

	switch v := data[7]; v {
	case 0:
		header.version = version(v)
	default:
		return nil, &UnknownVersionError{v}
	}

	header.memoryCost = binary.LittleEndian.Uint32(data[8:12])
	header.timeCost = binary.LittleEndian.Uint32(data[12:16])
	header.parallelism = binary.LittleEndian.Uint32(data[16:20])
	header.salt = [saltSize]byte(data[20:52])
	header.nonce = [chacha20poly1305.NonceSizeX]byte(data[52:76])

	return &header, nil
}

func (h *header) computeMAC(key []byte) {
	mac, err := blake2b.New512(key)
	if err != nil {
		panic(err)
	}

	header := h.asBytes()
	mac.Write(header[:76])

	h.mac = [blake2b.Size]byte(mac.Sum(nil))
}

func (h *header) verifyMAC(key, tag []byte) error {
	mac, err := blake2b.New512(key)
	if err != nil {
		panic(err)
	}

	header := h.asBytes()
	mac.Write(header[:76])

	if !slices.Equal(mac.Sum(nil), tag) {
		return ErrInvalidHeaderMAC
	}

	h.mac = [blake2b.Size]byte(tag)

	return nil
}

func (h *header) asBytes() [HeaderSize]byte {
	var header [HeaderSize]byte

	copy(header[:7], h.magicNumber[:])
	header[7] = byte(h.version)
	binary.LittleEndian.PutUint32(header[8:12], h.memoryCost)
	binary.LittleEndian.PutUint32(header[12:16], h.timeCost)
	binary.LittleEndian.PutUint32(header[16:20], h.parallelism)
	copy(header[20:52], h.salt[:])
	copy(header[52:76], h.nonce[:])
	copy(header[76:], h.mac[:])

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
