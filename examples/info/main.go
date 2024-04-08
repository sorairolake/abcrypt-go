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
	"github.com/sorairolake/abcrypt-go/examples"
)

func main() {
	flag.Parse()
	args := flag.Args()

	if opt.version {
		fmt.Printf("abcrypt-go %v\n", examples.Version)
		os.Exit(0)
	}

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

	if opt.json {
		json, err := json.Marshal(params)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(json))
	} else {
		m := params.MemoryCost
		t := params.TimeCost
		p := params.Parallelism
		fmt.Printf("Parameters used: memoryCost = %v; timeCost = %v; parallelism = %v;\n", m, t, p)
	}
}
