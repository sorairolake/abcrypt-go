// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package abcrypt_test

import (
	"encoding/binary"
	"os"
	"slices"
	"testing"

	"github.com/sorairolake/abcrypt-go"
)

func TestEncrypt(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/data.txt")
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := abcrypt.NewEncryptor(data, []byte(passphrase)).Encrypt()
	if slices.Equal(ciphertext, data) {
		t.Fatal("unexpected match between ciphertext and test data")
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

	cipher, err := abcrypt.NewDecryptor(ciphertext, []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := cipher.Decrypt()
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(plaintext, data) {
		t.Error("unexpected mismatch between plaintext and test data")
	}
}

func TestEncryptWithParams(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/data.txt")
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := abcrypt.NewEncryptorWithParams(data, []byte(passphrase), 32, 3, 4).Encrypt()
	if slices.Equal(ciphertext, data) {
		t.Fatal("unexpected match between ciphertext and test data")
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

	cipher, err := abcrypt.NewDecryptor(ciphertext, []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := cipher.Decrypt()
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(plaintext, data) {
		t.Error("unexpected mismatch between plaintext and test data")
	}
}

func TestEncryptWithContext(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/data.txt")
	if err != nil {
		t.Fatal(err)
	}

	{
		ciphertext := abcrypt.NewEncryptorWithContext(data, []byte(passphrase), abcrypt.Argon2i, 9216, 4, 1).Encrypt()
		if slices.Equal(ciphertext, data) {
			t.Fatal("unexpected match between ciphertext and test data")
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

		cipher, err := abcrypt.NewDecryptor(ciphertext, []byte(passphrase))
		if err != nil {
			t.Fatal(err)
		}

		plaintext, err := cipher.Decrypt()
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(plaintext, data) {
			t.Error("unexpected mismatch between plaintext and test data")
		}
	}
	{
		ciphertext := abcrypt.NewEncryptorWithContext(data, []byte(passphrase), abcrypt.Argon2id, 32, 3, 4).Encrypt()
		if slices.Equal(ciphertext, data) {
			t.Fatal("unexpected match between ciphertext and test data")
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

		cipher, err := abcrypt.NewDecryptor(ciphertext, []byte(passphrase))
		if err != nil {
			t.Fatal(err)
		}

		plaintext, err := cipher.Decrypt()
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(plaintext, data) {
			t.Error("unexpected mismatch between plaintext and test data")
		}
	}
}

func TestEncryptMinimumOutputLength(t *testing.T) {
	t.Parallel()

	cipher := abcrypt.NewEncryptorWithParams(nil, []byte(passphrase), 32, 3, 4)

	expected := abcrypt.HeaderSize + abcrypt.TagSize
	if outLen := cipher.OutLen(); outLen != expected {
		t.Fatalf("expected outLen `%v`, got `%v`", expected, outLen)
	}

	if ciphertext := cipher.Encrypt(); len(ciphertext) != expected {
		t.Errorf("expected ciphertext length `%v`, got `%v`", expected, len(ciphertext))
	}
}

func TestEncryptMagicNumber(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/data.txt")
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := abcrypt.NewEncryptorWithParams(data, []byte(passphrase), 32, 3, 4).Encrypt()
	if expected := []byte("abcrypt"); !slices.Equal(ciphertext[:7], expected) {
		t.Errorf("expected magic number `%v`, got `%v`", expected, ciphertext[:7])
	}
}

func TestEncryptVersion(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/data.txt")
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := abcrypt.NewEncryptorWithParams(data, []byte(passphrase), 32, 3, 4).Encrypt()
	if ciphertext[7] != 1 {
		t.Errorf("expected version `%v`, got `%v`", 1, ciphertext[7])
	}
}

func TestEncryptArgon2Type(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/data.txt")
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := abcrypt.NewEncryptorWithContext(data, []byte(passphrase), abcrypt.Argon2i, 32, 3, 4).Encrypt()

	argon2Type := binary.LittleEndian.Uint32(ciphertext[8:12])
	if argon2Type != 1 {
		t.Errorf("expected Argon2 type `%v`, got `%v`", 1, argon2Type)
	}
}

func TestEncryptArgon2Version(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/data.txt")
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := abcrypt.NewEncryptorWithContext(data, []byte(passphrase), abcrypt.Argon2id, 32, 3, 4).Encrypt()

	argon2Version := binary.LittleEndian.Uint32(ciphertext[12:16])
	if argon2Version != 0x13 {
		t.Errorf("expected Argon2 version `%#x`, got `%#x`", 0x13, argon2Version)
	}
}

func TestEncryptParams(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/data.txt")
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := abcrypt.NewEncryptorWithParams(data, []byte(passphrase), 32, 3, 4).Encrypt()

	memoryCost := binary.LittleEndian.Uint32(ciphertext[16:20])
	if memoryCost != 32 {
		t.Errorf("expected memoryCost `%v`, got `%v`", 32, memoryCost)
	}

	timeCost := binary.LittleEndian.Uint32(ciphertext[20:24])
	if timeCost != 3 {
		t.Errorf("expected timeCost `%v`, got `%v`", 3, timeCost)
	}

	parallelism := binary.LittleEndian.Uint32(ciphertext[24:28])
	if parallelism != 4 {
		t.Errorf("expected parallelism `%v`, got `%v`", 4, parallelism)
	}
}

func TestEncryptorOutLen(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/data.txt")
	if err != nil {
		t.Fatal(err)
	}

	outLen := abcrypt.NewEncryptorWithParams(data, []byte(passphrase), 32, 3, 4).OutLen()
	expected := len(data) + abcrypt.HeaderSize + abcrypt.TagSize

	if outLen != expected {
		t.Errorf("expected outLen `%v`, got `%v`", expected, outLen)
	}
}

func TestConvenientEncrypt(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/data.txt")
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := abcrypt.Encrypt(data, []byte(passphrase))
	if slices.Equal(ciphertext, data) {
		t.Fatal("unexpected match between ciphertext and test data")
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

	plaintext, err := abcrypt.Decrypt(ciphertext, []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(plaintext, data) {
		t.Error("unexpected mismatch between plaintext and test data")
	}
}

func TestConvenientEncryptWithParams(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/data.txt")
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := abcrypt.EncryptWithParams(data, []byte(passphrase), 32, 3, 4)
	if slices.Equal(ciphertext, data) {
		t.Fatal("unexpected match between ciphertext and test data")
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

	plaintext, err := abcrypt.Decrypt(ciphertext, []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(plaintext, data) {
		t.Error("unexpected mismatch between plaintext and test data")
	}
}

func TestConvenientEncryptWithContext(t *testing.T) {
	t.Parallel()

	{
		data, err := os.ReadFile("testdata/data.txt")
		if err != nil {
			t.Fatal(err)
		}

		ciphertext := abcrypt.EncryptWithContext(data, []byte(passphrase), abcrypt.Argon2i, 9216, 4, 1)
		if slices.Equal(ciphertext, data) {
			t.Fatal("unexpected match between ciphertext and test data")
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

		plaintext, err := abcrypt.Decrypt(ciphertext, []byte(passphrase))
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(plaintext, data) {
			t.Error("unexpected mismatch between plaintext and test data")
		}
	}
	{
		data, err := os.ReadFile("testdata/data.txt")
		if err != nil {
			t.Fatal(err)
		}

		ciphertext := abcrypt.EncryptWithContext(data, []byte(passphrase), abcrypt.Argon2id, 32, 3, 4)
		if slices.Equal(ciphertext, data) {
			t.Fatal("unexpected match between ciphertext and test data")
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

		plaintext, err := abcrypt.Decrypt(ciphertext, []byte(passphrase))
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(plaintext, data) {
			t.Error("unexpected mismatch between plaintext and test data")
		}
	}
}
