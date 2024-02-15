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
	s := abcrypt.HeaderSize
	if s != 140 {
		t.Errorf("expected HeaderSize `%v`, got `%v`", 140, s)
	}
}

func TestTagSize(t *testing.T) {
	s := abcrypt.TagSize
	if s != 16 {
		t.Errorf("expected TagSize `%v`, got `%v`", 16, s)
	}
	if s != chacha20poly1305.Overhead {
		t.Errorf("expected TagSize `%v`, got `%v`", chacha20poly1305.Overhead, s)
	}
}
