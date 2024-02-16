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

const (
	defaultMemoryCost  = 19456
	defaultTimeCost    = 2
	defaultParallelism = 1
)

func main() {
	memoryCostFlag := flag.Uint("m", defaultMemoryCost, "Set the memory size in KiB")
	timeCostFlag := flag.Uint("t", defaultTimeCost, "Set the number of iterations")
	parallelismFlag := flag.Uint("p", defaultParallelism, "Set the degree of parallelism")

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

	m := uint32(*memoryCostFlag)
	t := uint32(*timeCostFlag)
	p := uint8(*parallelismFlag)
	ciphertext := abcrypt.EncryptWithParams(plaintext, passphrase, m, t, p)

	if err := os.WriteFile(args[1], ciphertext, os.ModeType); err != nil {
		log.Fatal(err)
	}
}
