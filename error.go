// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package abcrypt

import (
	"errors"
	"fmt"
)

// ErrInvalidLength represents an error due to the encrypted data was shorter
// than 164 bytes.
var ErrInvalidLength = errors.New("abcrypt: encrypted data is shorter than 164 bytes")

// ErrInvalidMagicNumber represents an error due to the magic number (file
// signature) was invalid.
var ErrInvalidMagicNumber = errors.New("abcrypt: invalid magic number")

// UnsupportedVersionError represents an error due to the version was the
// unsupported abcrypt version number.
type UnsupportedVersionError struct {
	// Version represents the obtained version number.
	Version byte
}

// Error returns a string representation of an [UnsupportedVersionError].
func (e *UnsupportedVersionError) Error() string {
	return fmt.Sprintf("abcrypt: unsupported version number `%v`", e.Version)
}

// UnknownVersionError represents an error due to the version was the
// unrecognized abcrypt version number.
type UnknownVersionError struct {
	// Version represents the obtained version number.
	Version byte
}

// Error returns a string representation of an [UnknownVersionError].
func (e *UnknownVersionError) Error() string {
	return fmt.Sprintf("abcrypt: unknown version number `%v`", e.Version)
}

// InvalidArgon2TypeError represents an error due to the Argon2 type were
// invalid.
type InvalidArgon2TypeError struct {
	// Variant represents the obtained Argon2 type.
	Variant uint32
}

// Error returns a string representation of an [InvalidArgon2TypeError].
func (e *InvalidArgon2TypeError) Error() string {
	return "abcrypt: invalid Argon2 type"
}

// InvalidArgon2VersionError represents an error due to the Argon2 version were
// invalid.
type InvalidArgon2VersionError struct {
	// Version represents the obtained Argon2 version.
	Version uint32
}

// Error returns a string representation of an [InvalidArgon2VersionError].
func (e *InvalidArgon2VersionError) Error() string {
	return fmt.Sprintf("abcrypt: invalid Argon2 version `%#x`", e.Version)
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
