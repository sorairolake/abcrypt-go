// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Package abcrypt implements the [abcrypt encrypted data format].
//
// [abcrypt encrypted data format]: https://sorairolake.github.io/abcrypt/book/format.html
package abcrypt

import "golang.org/x/crypto/chacha20poly1305"

// HeaderSize is the number of bytes of the header.
const HeaderSize = 140

// TagSize is the number of bytes of the MAC (authentication tag) of the
// ciphertext.
const TagSize = chacha20poly1305.Overhead
