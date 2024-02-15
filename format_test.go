// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package abcrypt_test

import (
	"testing"

	"github.com/sorairolake/abcrypt-go"
)

func TestVersion(t *testing.T) {
	if abcrypt.V0 != 0 {
		t.Errorf("expected version `%v`, got `%v`", 0, abcrypt.V0)
	}
	if abcrypt.V1 != 1 {
		t.Errorf("expected version `%v`, got `%v`", 1, abcrypt.V1)
	}
}

func TestMagicNumber(t *testing.T) {
	expected := [7]byte{0x61, 0x62, 0x63, 0x72, 0x79, 0x70, 0x74}
	if abcrypt.MagicNumber != string(expected[:]) {
		t.Error("unexpected magic number")
	}
}
