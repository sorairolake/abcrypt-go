// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package abcrypt_test

import (
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/sorairolake/abcrypt-go"
)

func TestDecrypt(t *testing.T) {
	t.Parallel()

	dataEnc, err := os.ReadFile("testdata/data.txt.abcrypt")
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile("testdata/data.txt")
	if err != nil {
		t.Fatal(err)
	}

	cipher, err := abcrypt.NewDecryptor(dataEnc, []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := cipher.Decrypt()
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(plaintext, data) {
		t.Error("unexpected mismatch between plaintext and test data")
	}
}

func TestDecryptIncorrectPassphrase(t *testing.T) {
	t.Parallel()

	dataEnc, err := os.ReadFile("testdata/data.txt.abcrypt")
	if err != nil {
		t.Fatal(err)
	}

	_, err = abcrypt.NewDecryptor(dataEnc, []byte("password"))
	if err == nil {
		t.Fatal("unexpected success")
	}

	if !errors.Is(err, abcrypt.ErrInvalidHeaderMAC) {
		t.Error("unexpected error type")
	}
}

func TestDecryptInvalidInputLength(t *testing.T) {
	t.Parallel()

	data := make([]byte, abcrypt.HeaderSize+abcrypt.TagSize)

	_, err := abcrypt.NewDecryptor(data[:len(data)-1], []byte(passphrase))
	if err == nil {
		t.Fatal("unexpected success")
	}

	if !errors.Is(err, abcrypt.ErrInvalidLength) {
		t.Error("unexpected error type")
	}

	_, err = abcrypt.NewDecryptor(data, []byte(passphrase))
	if err == nil {
		t.Fatal("unexpected success")
	}

	if !errors.Is(err, abcrypt.ErrInvalidMagicNumber) {
		t.Error("unexpected error type")
	}
}

func TestDecryptInvalidMagicNumber(t *testing.T) {
	t.Parallel()

	dataEnc, err := os.ReadFile("testdata/data.txt.abcrypt")
	if err != nil {
		t.Fatal(err)
	}

	dataEnc[0] = byte('b')

	_, err = abcrypt.NewDecryptor(dataEnc, []byte(passphrase))
	if err == nil {
		t.Fatal("unexpected success")
	}

	if !errors.Is(err, abcrypt.ErrInvalidMagicNumber) {
		t.Error("unexpected error type")
	}
}

func TestDecryptUnknownVersion(t *testing.T) {
	t.Parallel()

	dataEnc, err := os.ReadFile("testdata/data.txt.abcrypt")
	if err != nil {
		t.Fatal(err)
	}

	dataEnc[7] = 1

	_, err = abcrypt.NewDecryptor(dataEnc, []byte(passphrase))
	if err == nil {
		t.Fatal("unexpected success")
	}

	var unknownVersionError *abcrypt.UnknownVersionError
	if !errors.As(err, &unknownVersionError) {
		t.Fatal("unexpected error type")
	}

	if v := unknownVersionError.Version; v != 1 {
		t.Errorf("expected unrecognized version number `%v`, got `%v`", 1, v)
	}
}

func TestDecryptInvalidHeaderMAC(t *testing.T) {
	t.Parallel()

	dataEnc, err := os.ReadFile("testdata/data.txt.abcrypt")
	if err != nil {
		t.Fatal(err)
	}

	headerMAC := dataEnc[76:140]
	slices.Reverse(headerMAC)
	copy(dataEnc[76:140], headerMAC)

	_, err = abcrypt.NewDecryptor(dataEnc, []byte(passphrase))
	if err == nil {
		t.Fatal("unexpected success")
	}

	if !errors.Is(err, abcrypt.ErrInvalidHeaderMAC) {
		t.Error("unexpected error type")
	}
}

func TestDecryptInvalidMAC(t *testing.T) {
	t.Parallel()

	dataEnc, err := os.ReadFile("testdata/data.txt.abcrypt")
	if err != nil {
		t.Fatal(err)
	}

	startMAC := len(dataEnc) - abcrypt.TagSize
	mac := dataEnc[startMAC:]
	slices.Reverse(mac)
	copy(dataEnc[startMAC:], mac)

	cipher, err := abcrypt.NewDecryptor(dataEnc, []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}

	_, err = cipher.Decrypt()
	if err == nil {
		t.Fatal("unexpected success")
	}

	var invalidMACError *abcrypt.InvalidMACError
	if !errors.As(err, &invalidMACError) {
		t.Fatal("unexpected error type")
	}

	const expected = "chacha20poly1305: message authentication failed"
	if invalidMACError.Unwrap().Error() != expected {
		t.Error("unexpected error type")
	}
}

func TestDecryptOutLen(t *testing.T) {
	t.Parallel()

	dataEnc, err := os.ReadFile("testdata/data.txt.abcrypt")
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile("testdata/data.txt")
	if err != nil {
		t.Fatal(err)
	}

	cipher, err := abcrypt.NewDecryptor(dataEnc, []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}

	if outLen, expected := cipher.OutLen(), len(data); outLen != expected {
		t.Errorf("expected outLen `%v`, got `%v`", expected, outLen)
	}
}

func TestConvenientDecrypt(t *testing.T) {
	t.Parallel()

	dataEnc, err := os.ReadFile("testdata/data.txt.abcrypt")
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile("testdata/data.txt")
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := abcrypt.Decrypt(dataEnc, []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(plaintext, data) {
		t.Error("unexpected mismatch between plaintext and test data")
	}
}
