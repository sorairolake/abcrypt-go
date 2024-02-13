// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/sorairolake/abcrypt-go"
)

func main() {
	jsonFlag := flag.Bool("j", false, "Output the encryption parameters as JSON")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [OPTIONS] [FILE]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	args := flag.Args()

	var ciphertext []byte
	switch flag.NArg() {
	case 0:
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatal(err)
		}
		ciphertext = b
	case 1:
		b, err := os.ReadFile(args[0])
		if err != nil {
			log.Fatal(err)
		}
		ciphertext = b
	default:
		flag.Usage()
		os.Exit(1)
	}

	params, err := abcrypt.NewParams(ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	if *jsonFlag {
		json, err := json.Marshal(params)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(json))
	} else {
		fmt.Printf("Parameters used: memoryCost = %v; timeCost = %v; parallelism = %v;\n", params.MemoryCost, params.TimeCost, params.Parallelism)
	}
}
