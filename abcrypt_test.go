// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package abcrypt_test

import (
	"testing"

	"github.com/sorairolake/abcrypt-go"
	"golang.org/x/crypto/chacha20poly1305"
)

const passphrase = "passphrase"

func TestHeaderSize(t *testing.T) {
	t.Parallel()

	if size := abcrypt.HeaderSize; size != 148 {
		t.Errorf("expected HeaderSize `%v`, got `%v`", 148, size)
	}
}

func TestTagSize(t *testing.T) {
	t.Parallel()

	size := abcrypt.TagSize
	if size != 16 {
		t.Errorf("expected TagSize `%v`, got `%v`", 16, size)
	}

	if size != chacha20poly1305.Overhead {
		t.Errorf("expected TagSize `%v`, got `%v`", chacha20poly1305.Overhead, size)
	}
}
