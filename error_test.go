// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package abcrypt

import (
	"errors"
	"math"
	"testing"
)

func TestErrInvalidLength(t *testing.T) {
	err := ErrInvalidLength
	expected := "abcrypt: encrypted data is shorter than 156 bytes"
	if err.Error() != expected {
		t.Error("unexpected error message")
	}
}

func TestErrInvalidMagicNumber(t *testing.T) {
	err := ErrInvalidMagicNumber
	expected := "abcrypt: invalid magic number"
	if err.Error() != expected {
		t.Error("unexpected error message")
	}
}

func TestUnknownVersionError(t *testing.T) {
	err := UnknownVersionError{math.MaxUint8}
	expected := "abcrypt: unknown version number `255`"
	if err.Error() != expected {
		t.Error("unexpected error message")
	}
}

func TestErrInvalidHeaderMAC(t *testing.T) {
	err := ErrInvalidHeaderMAC
	expected := "abcrypt: invalid header MAC"
	if err.Error() != expected {
		t.Error("unexpected error message")
	}
}

func TestInvalidMACError(t *testing.T) {
	err := InvalidMACError{errors.New("error")}
	expected := "abcrypt: invalid ciphertext MAC: error"
	if err.Error() != expected {
		t.Error("unexpected error message")
	}
	if err.Unwrap().Error() != "error" {
		t.Error("unexpected error message")
	}
}
