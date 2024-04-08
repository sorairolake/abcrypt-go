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

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}

	ciphertext, err := os.ReadFile(args[0])
	if err != nil {
		log.Fatal(err)
	}

	fmt.Print("Enter passphrase: ")

	passphrase, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println()

	plaintext, err := abcrypt.Decrypt(ciphertext, passphrase)
	if err != nil {
		log.Fatal(err)
	}

	if opt.output == "" {
		if _, err := os.Stdout.Write(plaintext); err != nil {
			log.Fatal(err)
		}
	} else {
		if err := os.WriteFile(opt.output, plaintext, os.ModeType); err != nil {
			log.Fatal(err)
		}
	}
}
