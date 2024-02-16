// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package abcrypt_test

import (
	"testing"

	"github.com/sorairolake/abcrypt-go"
)

func TestVersion(t *testing.T) {
	t.Parallel()

	if v0 := abcrypt.Version0; v0 != 0 {
		t.Errorf("expected version `%v`, got `%v`", 0, v0)
	}

	if v1 := abcrypt.Version1; v1 != 1 {
		t.Errorf("expected version `%v`, got `%v`", 1, v1)
	}
}

func TestMagicNumber(t *testing.T) {
	t.Parallel()

	expected := [7]byte{0x61, 0x62, 0x63, 0x72, 0x79, 0x70, 0x74}
	if abcrypt.MagicNumber != string(expected[:]) {
		t.Error("unexpected magic number")
	}
}
