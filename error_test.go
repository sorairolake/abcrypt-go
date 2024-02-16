// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package abcrypt_test

import (
	"errors"
	"math"
	"testing"

	"github.com/sorairolake/abcrypt-go"
)

var errInner = errors.New("error")

func TestErrInvalidLength(t *testing.T) {
	t.Parallel()

	err := abcrypt.ErrInvalidLength
	expected := "abcrypt: encrypted data is shorter than 156 bytes"

	if err.Error() != expected {
		t.Error("unexpected error message")
	}
}

func TestErrInvalidMagicNumber(t *testing.T) {
	t.Parallel()

	err := abcrypt.ErrInvalidMagicNumber
	expected := "abcrypt: invalid magic number"

	if err.Error() != expected {
		t.Error("unexpected error message")
	}
}

func TestUnknownVersionError(t *testing.T) {
	t.Parallel()

	err := abcrypt.UnknownVersionError{math.MaxUint8}
	expected := "abcrypt: unknown version number `255`"

	if err.Error() != expected {
		t.Error("unexpected error message")
	}
}

func TestErrInvalidHeaderMAC(t *testing.T) {
	t.Parallel()

	err := abcrypt.ErrInvalidHeaderMAC
	expected := "abcrypt: invalid header MAC"

	if err.Error() != expected {
		t.Error("unexpected error message")
	}
}

func TestInvalidMACError(t *testing.T) {
	t.Parallel()

	err := abcrypt.InvalidMACError{errInner}
	expected := "abcrypt: invalid ciphertext MAC: error"

	if err.Error() != expected {
		t.Error("unexpected error message")
	}

	if err.Unwrap().Error() != "error" {
		t.Error("unexpected error message")
	}
}
