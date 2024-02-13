// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package abcrypt

import (
	"encoding/binary"
	"os"
	"reflect"
	"testing"
)

func TestEncrypt(t *testing.T) {
	data, err := os.ReadFile("tests/data/data.txt")
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := NewEncryptorWithParams(data, []byte(passphrase), 32, 3, 4).Encrypt()
	if reflect.DeepEqual(ciphertext, data) {
		t.Fatal("unexpected match between ciphertext and test data")
	}

	cipher, err := NewDecryptor(ciphertext, []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := cipher.Decrypt()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plaintext, data) {
		t.Error("unexpected mismatch between plaintext and test data")
	}
}

func TestEncryptMinimumOutputLength(t *testing.T) {
	cipher := NewEncryptorWithParams(nil, []byte(passphrase), 32, 3, 4)
	outLen := cipher.OutLen()
	expected := HeaderSize + TagSize
	if outLen != expected {
		t.Fatalf("expected outLen `%v`, got `%v`", expected, outLen)
	}
	ciphertext := cipher.Encrypt()
	if len(ciphertext) != expected {
		t.Errorf("expected ciphertext length `%v`, got `%v`", expected, len(ciphertext))
	}
}

func TestEncryptMagicNumber(t *testing.T) {
	data, err := os.ReadFile("tests/data/data.txt")
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := NewEncryptorWithParams(data, []byte(passphrase), 32, 3, 4).Encrypt()
	expected := []byte("abcrypt")
	if !reflect.DeepEqual(ciphertext[:7], expected) {
		t.Errorf("expected magic number `%v`, got `%v`", expected, ciphertext[:7])
	}
}

func TestEncryptVersion(t *testing.T) {
	data, err := os.ReadFile("tests/data/data.txt")
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := NewEncryptorWithParams(data, []byte(passphrase), 32, 3, 4).Encrypt()
	if ciphertext[7] != 0 {
		t.Errorf("expected version `%v`, got `%v`", 0, ciphertext[7])
	}
}

func TestEncryptParams(t *testing.T) {
	data, err := os.ReadFile("tests/data/data.txt")
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := NewEncryptorWithParams(data, []byte(passphrase), 32, 3, 4).Encrypt()
	memoryCost := binary.LittleEndian.Uint32(ciphertext[8:12])
	if memoryCost != 32 {
		t.Errorf("expected memoryCost `%v`, got `%v`", 32, memoryCost)
	}
	timeCost := binary.LittleEndian.Uint32(ciphertext[12:16])
	if timeCost != 3 {
		t.Errorf("expected timeCost `%v`, got `%v`", 3, timeCost)
	}
	parallelism := binary.LittleEndian.Uint32(ciphertext[16:20])
	if parallelism != 4 {
		t.Errorf("expected parallelism `%v`, got `%v`", 4, parallelism)
	}
}

func TestEncryptorOutLen(t *testing.T) {
	data, err := os.ReadFile("tests/data/data.txt")
	if err != nil {
		t.Fatal(err)
	}

	outLen := NewEncryptorWithParams(data, []byte(passphrase), 32, 3, 4).OutLen()
	expected := len(data) + HeaderSize + TagSize
	if outLen != expected {
		t.Errorf("expected outLen `%v`, got `%v`", expected, outLen)
	}
}
