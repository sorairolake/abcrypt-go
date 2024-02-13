// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package abcrypt

import (
	"errors"
	"os"
	"reflect"
	"slices"
	"testing"
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

	cipher, err := NewDecryptor(dataEnc, []byte(passphrase))
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

	if _, err := NewDecryptor(dataEnc, []byte("password")); err != nil {
		if !errors.Is(err, ErrInvalidHeaderMAC) {
			t.Error("unexpected error type")
		}
	} else {
		t.Fatal("unexpected success")
	}
}

func TestDecryptInvalidInputLength(t *testing.T) {
	data := make([]byte, (HeaderSize+TagSize)-1)

	if _, err := NewDecryptor(data, []byte(passphrase)); err != nil {
		if !errors.Is(err, ErrInvalidLength) {
			t.Error("unexpected error type")
		}
	} else {
		t.Fatal("unexpected success")
	}

	data = append(data, 0)
	if _, err := NewDecryptor(data, []byte(passphrase)); err != nil {
		if !errors.Is(err, ErrInvalidMagicNumber) {
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
	if _, err := NewDecryptor(dataEnc, []byte(passphrase)); err != nil {
		if !errors.Is(err, ErrInvalidMagicNumber) {
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
	if _, err := NewDecryptor(dataEnc, []byte(passphrase)); err != nil {
		switch e := err.(type) {
		case *UnknownVersionError:
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
	if _, err := NewDecryptor(dataEnc, []byte(passphrase)); err != nil {
		if !errors.Is(err, ErrInvalidHeaderMAC) {
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

	startMAC := len(dataEnc) - TagSize
	mac := dataEnc[startMAC:]
	slices.Reverse(mac)
	copy(dataEnc[startMAC:], mac)
	cipher, err := NewDecryptor(dataEnc, []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cipher.Decrypt(); err != nil {
		switch e := err.(type) {
		case *InvalidMACError:
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

	cipher, err := NewDecryptor(dataEnc, []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	outLen := cipher.OutLen()
	expected := len(data)
	if outLen != expected {
		t.Errorf("expected outLen `%v`, got `%v`", expected, outLen)
	}
}
