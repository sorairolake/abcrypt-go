// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package abcrypt

import (
	"errors"
	"fmt"
)

// ErrInvalidLength represents an error due to the encrypted data was shorter
// than 156 bytes.
var ErrInvalidLength = errors.New("abcrypt: encrypted data is shorter than 156 bytes")

// ErrInvalidMagicNumber represents an error due to the magic number (file
// signature) was invalid.
var ErrInvalidMagicNumber = errors.New("abcrypt: invalid magic number")

// UnknownVersionError represents an error due to the version was the
// unrecognized abcrypt version number.
type UnknownVersionError struct {
	// Version represents the obtained version number.
	Version uint8
}

// Error returns a string representation of an [UnknownVersionError].
func (e *UnknownVersionError) Error() string {
	return fmt.Sprintf("abcrypt: unknown version number `%v`", e.Version)
}

// InvalidHeaderMACError represents an error due to the MAC (authentication
// tag) of the header was invalid.
type InvalidHeaderMACError struct {
	// MAC represents the obtained MAC of the header.
	MAC [64]byte
}

// Error returns a string representation of an [InvalidHeaderMACError].
func (e *InvalidHeaderMACError) Error() string {
	return "abcrypt: invalid header MAC"
}

// InvalidMACError represents an error due to the MAC (authentication tag) of
// the ciphertext was invalid.
type InvalidMACError struct {
	// Err represents a wrapped error.
	Err error
}

// Error returns a string representation of an [InvalidMACError].
func (e *InvalidMACError) Error() string {
	return fmt.Sprintf("abcrypt: invalid ciphertext MAC: %v", e.Err)
}

// Unwrap returns the underlying error of an [InvalidMACError].
func (e *InvalidMACError) Unwrap() error {
	return e.Err
}
