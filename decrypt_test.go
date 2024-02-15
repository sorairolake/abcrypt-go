// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package abcrypt_test

import (
	"errors"
	"os"
	"reflect"
	"slices"
	"testing"

	"github.com/sorairolake/abcrypt-go"
)

func TestDecrypt(t *testing.T) {
	dataEnc, err := os.ReadFile("tests/data/data.txt.abcrypt")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("tests/data/data.txt")
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
	if !reflect.DeepEqual(plaintext, data) {
		t.Error("unexpected mismatch between plaintext and test data")
	}
}

func TestDecryptIncorrectPassphrase(t *testing.T) {
	dataEnc, err := os.ReadFile("tests/data/data.txt.abcrypt")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := abcrypt.NewDecryptor(dataEnc, []byte("password")); err != nil {
		if !errors.Is(err, abcrypt.ErrInvalidHeaderMAC) {
			t.Error("unexpected error type")
		}
	} else {
		t.Fatal("unexpected success")
	}
}

func TestDecryptInvalidInputLength(t *testing.T) {
	data := make([]byte, (abcrypt.HeaderSize+abcrypt.TagSize)-1)

	if _, err := abcrypt.NewDecryptor(data, []byte(passphrase)); err != nil {
		if !errors.Is(err, abcrypt.ErrInvalidLength) {
			t.Error("unexpected error type")
		}
	} else {
		t.Fatal("unexpected success")
	}

	data = append(data, 0)
	if _, err := abcrypt.NewDecryptor(data, []byte(passphrase)); err != nil {
		if !errors.Is(err, abcrypt.ErrInvalidMagicNumber) {
			t.Error("unexpected error type")
		}
	} else {
		t.Fatal("unexpected success")
	}
}

func TestDecryptInvalidMagicNumber(t *testing.T) {
	dataEnc, err := os.ReadFile("tests/data/data.txt.abcrypt")
	if err != nil {
		t.Fatal(err)
	}

	dataEnc[0] = byte('b')
	if _, err := abcrypt.NewDecryptor(dataEnc, []byte(passphrase)); err != nil {
		if !errors.Is(err, abcrypt.ErrInvalidMagicNumber) {
			t.Error("unexpected error type")
		}
	} else {
		t.Fatal("unexpected success")
	}
}

func TestDecryptUnknownVersion(t *testing.T) {
	dataEnc, err := os.ReadFile("tests/data/data.txt.abcrypt")
	if err != nil {
		t.Fatal(err)
	}

	dataEnc[7] = 1
	if _, err := abcrypt.NewDecryptor(dataEnc, []byte(passphrase)); err != nil {
		switch e := err.(type) {
		case *abcrypt.UnknownVersionError:
			if e.Version != 1 {
				t.Errorf("expected unrecognized version number `%v`, got `%v`", 1, e.Version)
			}
		default:
			t.Error("unexpected error type")
		}
	} else {
		t.Fatal("unexpected success")
	}
}

func TestDecryptInvalidHeaderMAC(t *testing.T) {
	dataEnc, err := os.ReadFile("tests/data/data.txt.abcrypt")
	if err != nil {
		t.Fatal(err)
	}

	headerMAC := dataEnc[76:140]
	slices.Reverse(headerMAC)
	copy(dataEnc[76:140], headerMAC)
	if _, err := abcrypt.NewDecryptor(dataEnc, []byte(passphrase)); err != nil {
		if !errors.Is(err, abcrypt.ErrInvalidHeaderMAC) {
			t.Error("unexpected error type")
		}
	} else {
		t.Fatal("unexpected success")
	}
}

func TestDecryptInvalidMAC(t *testing.T) {
	dataEnc, err := os.ReadFile("tests/data/data.txt.abcrypt")
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
	if _, err := cipher.Decrypt(); err != nil {
		switch e := err.(type) {
		case *abcrypt.InvalidMACError:
			const expected = "chacha20poly1305: message authentication failed"
			if e.Unwrap().Error() != expected {
				t.Error("unexpected error type")
			}
		default:
			t.Error("unexpected error type")
		}
	} else {
		t.Fatal("unexpected success")
	}
}

func TestDecryptOutLen(t *testing.T) {
	dataEnc, err := os.ReadFile("tests/data/data.txt.abcrypt")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("tests/data/data.txt")
	if err != nil {
		t.Fatal(err)
	}

	cipher, err := abcrypt.NewDecryptor(dataEnc, []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	outLen := cipher.OutLen()
	expected := len(data)
	if outLen != expected {
		t.Errorf("expected outLen `%v`, got `%v`", expected, outLen)
	}
}

func TestConvenientDecrypt(t *testing.T) {
	dataEnc, err := os.ReadFile("tests/data/data.txt.abcrypt")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("tests/data/data.txt")
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := abcrypt.Decrypt(dataEnc, []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plaintext, data) {
		t.Error("unexpected mismatch between plaintext and test data")
	}
}
