// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package abcrypt_test

import (
	"fmt"
	"log"
	"os"
	"slices"

	"github.com/sorairolake/abcrypt-go"
)

const data = "Hello, world!\n"

func Example() {
	ciphertext := abcrypt.EncryptWithParams([]byte(data), []byte(passphrase), 32, 3, 4)

	fmt.Printf("ciphertext and input data are different: %v\n", !slices.Equal(ciphertext, []byte(data)))

	plaintext, err := abcrypt.Decrypt(ciphertext, []byte(passphrase))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("plaintext and input data are identical: %v\n", slices.Equal(plaintext, []byte(data)))

	// Output:
	// ciphertext and input data are different: true
	// plaintext and input data are identical: true
}

func ExampleEncryptor() {
	fmt.Printf("input data size: %v B\n", len(data))

	cipher := abcrypt.NewEncryptorWithParams([]byte(data), []byte(passphrase), 32, 3, 4)

	fmt.Printf("expected output size: %v B\n", cipher.OutLen())

	ciphertext := cipher.Encrypt()

	fmt.Printf("encrypted data size: %v B\n", len(ciphertext))

	// Output:
	// input data size: 14 B
	// expected output size: 178 B
	// encrypted data size: 178 B
}

func ExampleDecryptor() {
	dataEnc, err := os.ReadFile("testdata/v1/data.txt.abcrypt")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("input data size: %v B\n", len(dataEnc))

	cipher, err := abcrypt.NewDecryptor(dataEnc, []byte(passphrase))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("expected output size: %v B\n", cipher.OutLen())

	plaintext, err := cipher.Decrypt()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("decrypted data size: %v B\n", len(plaintext))

	// Output:
	// input data size: 178 B
	// expected output size: 14 B
	// decrypted data size: 14 B
}

func ExampleParams() {
	ciphertext, err := os.ReadFile("testdata/v1/data.txt.abcrypt")
	if err != nil {
		log.Fatal(err)
	}

	params, err := abcrypt.NewParams(ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("memoryCost: %v\n", params.MemoryCost)
	fmt.Printf("timeCost: %v\n", params.TimeCost)
	fmt.Printf("parallelism: %v\n", params.Parallelism)

	// Output:
	// memoryCost: 32
	// timeCost: 3
	// parallelism: 4
}
