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
	"golang.org/x/term"
)

func main() {
	outputFlag := flag.String("o", "", "Output the result to a file")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [OPTIONS] <FILE>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	args := flag.Args()

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
	cipher, err := abcrypt.NewDecryptor(ciphertext, passphrase)
	if err != nil {
		log.Fatal(err)
	}
	plaintext, err := cipher.Decrypt()
	if err != nil {
		log.Fatal(err)
	}

	if *outputFlag == "" {
		if _, err := os.Stdout.Write(plaintext); err != nil {
			log.Fatal(err)
		}
	} else {
		if err := os.WriteFile(*outputFlag, plaintext, os.ModeType); err != nil {
			log.Fatal(err)
		}
	}
}
