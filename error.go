// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package abcrypt

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidLength represents an error due to the encrypted data was
	// shorter than 156 bytes.
	ErrInvalidLength = errors.New("abcrypt: encrypted data is shorter than 156 bytes")
	// ErrInvalidMagicNumber represents an error due to the magic number
	// (file signature) was invalid.
	ErrInvalidMagicNumber = errors.New("abcrypt: invalid magic number")
	// ErrInvalidHeaderMAC represents an error due to the MAC
	// (authentication tag) of the header was invalid.
	ErrInvalidHeaderMAC = errors.New("abcrypt: invalid header MAC")
)

// UnknownVersionError represents an error due to the version was the
// unrecognized abcrypt version number.
type UnknownVersionError struct {
	Version uint8
}

func (e *UnknownVersionError) Error() string {
	return fmt.Sprintf("abcrypt: unknown version number `%v`", e.Version)
}

// InvalidMACError represents an error due to the MAC (authentication tag) of
// the ciphertext was invalid.
type InvalidMACError struct {
	Err error
}

func (e *InvalidMACError) Error() string {
	return fmt.Sprintf("abcrypt: invalid ciphertext MAC: %v", e.Err)
}

func (e *InvalidMACError) Unwrap() error {
	return e.Err
}
