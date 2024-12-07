// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package abcrypt_test

import (
	"slices"
	"testing"

	"github.com/sorairolake/abcrypt-go"
)

func TestMagicNumber(t *testing.T) {
	t.Parallel()

	expected := [abcrypt.MagicNumberSize]byte{0x61, 0x62, 0x63, 0x72, 0x79, 0x70, 0x74}
	if !slices.Equal([]byte(abcrypt.MagicNumber), expected[:]) {
		t.Error("unexpected magic number")
	}
}

func TestMagicNumberSize(t *testing.T) {
	t.Parallel()

	if size := abcrypt.MagicNumberSize; size != 7 {
		t.Errorf("expected magic number size `%v`, got `%v`", 7, size)
	}
}

func TestVersion(t *testing.T) {
	t.Parallel()

	if v0 := abcrypt.Version0; v0 != 0 {
		t.Errorf("expected version `%v`, got `%v`", 0, v0)
	}

	if v1 := abcrypt.Version1; v1 != 1 {
		t.Errorf("expected version `%v`, got `%v`", 1, v1)
	}
}

func TestArgon2Type(t *testing.T) {
	t.Parallel()

	if argon2d := abcrypt.Argon2d; argon2d != 0 {
		t.Errorf("expected Argon2 type `%v`, got `%v`", 0, argon2d)
	}

	if argon2i := abcrypt.Argon2i; argon2i != 1 {
		t.Errorf("expected Argon2 type `%v`, got `%v`", 1, argon2i)
	}

	if argon2id := abcrypt.Argon2id; argon2id != 2 {
		t.Errorf("expected Argon2 type `%v`, got `%v`", 2, argon2id)
	}
}

func TestArgon2Version(t *testing.T) {
	t.Parallel()

	if v0x10 := abcrypt.Version0x10; v0x10 != 0x10 {
		t.Errorf("expected Argon2 version `%#x`, got `%#x`", 0x10, v0x10)
	}

	if v0x13 := abcrypt.Version0x13; v0x13 != 0x13 {
		t.Errorf("expected Argon2 version `%#x`, got `%#x`", 0x13, v0x13)
	}
}

func TestSaltSize(t *testing.T) {
	t.Parallel()

	if size := abcrypt.SaltSize; size != 32 {
		t.Errorf("expected salt size `%v`, got `%v`", 32, size)
	}
}
