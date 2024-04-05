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

func TestSaltSize(t *testing.T) {
	t.Parallel()

	if size := abcrypt.SaltSize; size != 32 {
		t.Errorf("expected salt size `%v`, got `%v`", 32, size)
	}
}
