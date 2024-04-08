// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"syscall"

	"github.com/sorairolake/abcrypt-go"
	"github.com/sorairolake/abcrypt-go/examples"
	"golang.org/x/term"
)

func main() {
	flag.Parse()
	args := flag.Args()

	if opt.version {
		fmt.Printf("abcrypt-go %v\n", examples.Version)
		os.Exit(0)
	}

	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(1)
	}

	plaintext, err := os.ReadFile(args[0])
	if err != nil {
		log.Fatal(err)
	}

	fmt.Print("Enter passphrase: ")

	passphrase, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println()

	m := uint32(opt.memoryCost)
	t := uint32(opt.timeCost)
	p := uint8(opt.parallelism)
	ciphertext := abcrypt.EncryptWithParams(plaintext, passphrase, m, t, p)

	if err := os.WriteFile(args[1], ciphertext, os.ModeType); err != nil {
		log.Fatal(err)
	}
}
