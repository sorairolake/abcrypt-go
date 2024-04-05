// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Package abcrypt implements the [abcrypt encrypted data format].
//
// [abcrypt encrypted data format]: https://sorairolake.github.io/abcrypt/book/format.html
package abcrypt

import "golang.org/x/crypto/chacha20poly1305"

const (
	// HeaderSize is the number of bytes of the header.
	HeaderSize = 140

	// TagSize is the number of bytes of the MAC (authentication tag) of
	// the ciphertext.
	TagSize = chacha20poly1305.Overhead
)
