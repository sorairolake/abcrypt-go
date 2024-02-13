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
	memoryCostFlag := flag.Uint("m", 19456, "Set the memory size in KiB")
	timeCostFlag := flag.Uint("t", 2, "Set the number of iterations")
	parallelismFlag := flag.Uint("p", 1, "Set the degree of parallelism")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [OPTIONS] <INFILE> <OUTFILE>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	args := flag.Args()

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
	ciphertext := abcrypt.NewEncryptorWithParams(plaintext, passphrase, uint32(*memoryCostFlag), uint32(*timeCostFlag), uint8(*parallelismFlag)).Encrypt()

	if err := os.WriteFile(args[1], ciphertext, os.ModeType); err != nil {
		log.Fatal(err)
	}
}
