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

	{
		ciphertext, err := os.ReadFile("testdata/v1/argon2d/v0x10/data.txt.abcrypt")
		if err != nil {
			t.Fatal(err)
		}

		params, err := abcrypt.NewParams(ciphertext)
		if err != nil {
			t.Fatal(err)
		}

		if memoryCost := params.MemoryCost; memoryCost != 47104 {
			t.Errorf("expected memoryCost `%v`, got `%v`", 47104, memoryCost)
		}

		if timeCost := params.TimeCost; timeCost != 1 {
			t.Errorf("expected timeCost `%v`, got `%v`", 1, timeCost)
		}

		if parallelism := params.Parallelism; parallelism != 1 {
			t.Errorf("expected parallelism `%v`, got `%v`", 1, parallelism)
		}
	}
	{
		ciphertext, err := os.ReadFile("testdata/v1/argon2d/v0x13/data.txt.abcrypt")
		if err != nil {
			t.Fatal(err)
		}

		params, err := abcrypt.NewParams(ciphertext)
		if err != nil {
			t.Fatal(err)
		}

		if memoryCost := params.MemoryCost; memoryCost != 19456 {
			t.Errorf("expected memoryCost `%v`, got `%v`", 19456, memoryCost)
		}

		if timeCost := params.TimeCost; timeCost != 2 {
			t.Errorf("expected timeCost `%v`, got `%v`", 2, timeCost)
		}

		if parallelism := params.Parallelism; parallelism != 1 {
			t.Errorf("expected parallelism `%v`, got `%v`", 1, parallelism)
		}
	}
	{
		ciphertext, err := os.ReadFile("testdata/v1/argon2i/v0x10/data.txt.abcrypt")
		if err != nil {
			t.Fatal(err)
		}

		params, err := abcrypt.NewParams(ciphertext)
		if err != nil {
			t.Fatal(err)
		}

		if memoryCost := params.MemoryCost; memoryCost != 12288 {
			t.Errorf("expected memoryCost `%v`, got `%v`", 12288, memoryCost)
		}

		if timeCost := params.TimeCost; timeCost != 3 {
			t.Errorf("expected timeCost `%v`, got `%v`", 3, timeCost)
		}

		if parallelism := params.Parallelism; parallelism != 1 {
			t.Errorf("expected parallelism `%v`, got `%v`", 1, parallelism)
		}
	}
	{
		ciphertext, err := os.ReadFile("testdata/v1/argon2i/v0x13/data.txt.abcrypt")
		if err != nil {
			t.Fatal(err)
		}

		params, err := abcrypt.NewParams(ciphertext)
		if err != nil {
			t.Fatal(err)
		}

		if memoryCost := params.MemoryCost; memoryCost != 9216 {
			t.Errorf("expected memoryCost `%v`, got `%v`", 9216, memoryCost)
		}

		if timeCost := params.TimeCost; timeCost != 4 {
			t.Errorf("expected timeCost `%v`, got `%v`", 4, timeCost)
		}

		if parallelism := params.Parallelism; parallelism != 1 {
			t.Errorf("expected parallelism `%v`, got `%v`", 1, parallelism)
		}
	}
	{
		ciphertext, err := os.ReadFile("testdata/v1/argon2id/v0x10/data.txt.abcrypt")
		if err != nil {
			t.Fatal(err)
		}

		params, err := abcrypt.NewParams(ciphertext)
		if err != nil {
			t.Fatal(err)
		}

		if memoryCost := params.MemoryCost; memoryCost != 7168 {
			t.Errorf("expected memoryCost `%v`, got `%v`", 7168, memoryCost)
		}

		if timeCost := params.TimeCost; timeCost != 5 {
			t.Errorf("expected timeCost `%v`, got `%v`", 5, timeCost)
		}

		if parallelism := params.Parallelism; parallelism != 1 {
			t.Errorf("expected parallelism `%v`, got `%v`", 1, parallelism)
		}
	}
	{
		ciphertext, err := os.ReadFile("testdata/v1/argon2id/v0x13/data.txt.abcrypt")
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
}

func TestParamsMarshalJSON(t *testing.T) {
	t.Parallel()

	ciphertext, err := os.ReadFile("testdata/v1/argon2id/v0x13/data.txt.abcrypt")
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
