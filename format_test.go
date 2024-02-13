// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package abcrypt

import "testing"

func TestVersion(t *testing.T) {
	if v0 != 0 {
		t.Errorf("expected version `%v`, got `%v`", 0, v0)
	}
	if v1 != 1 {
		t.Errorf("expected version `%v`, got `%v`", 1, v1)
	}
}

func TestMagicNumber(t *testing.T) {
	expected := [7]byte{0x61, 0x62, 0x63, 0x72, 0x79, 0x70, 0x74}
	if magicNumber != string(expected[:]) {
		t.Error("unexpected magic number")
	}
}
