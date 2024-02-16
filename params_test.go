// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package abcrypt_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/sorairolake/abcrypt-go"
)

func TestParams(t *testing.T) {
	t.Parallel()

	ciphertext, err := os.ReadFile("tests/data/data.txt.abcrypt")
	if err != nil {
		t.Fatal(err)
	}

	params, err := abcrypt.NewParams(ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if memoryCost := params.MemoryCost; memoryCost != 32 {
		t.Errorf("expected memoryCost `%v`, got `%v`", 32, memoryCost)
	}

	if timeCost := params.TimeCost; timeCost != 3 {
		t.Errorf("expected timeCost `%v`, got `%v`", 3, timeCost)
	}

	if parallelism := params.Parallelism; parallelism != 4 {
		t.Errorf("expected parallelism `%v`, got `%v`", 4, parallelism)
	}
}

func TestParamsMarshalJSON(t *testing.T) {
	t.Parallel()

	ciphertext, err := os.ReadFile("tests/data/data.txt.abcrypt")
	if err != nil {
		t.Fatal(err)
	}

	params, err := abcrypt.NewParams(ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	json, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}

	const expected = `{"memoryCost":32,"timeCost":3,"parallelism":4}`
	if string(json) != expected {
		t.Errorf("expected JSON `%v`, got `%s`", expected, json)
	}
}
