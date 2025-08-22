// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

type options struct {
	output  string
	version bool
}

var opt options

func init() {
	flag.StringVar(&opt.output, "output", "", "Output the result to a file")
	flag.BoolVar(&opt.version, "version", false, "Print version number")

	flag.Usage = func() {
		if _, err := fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [OPTIONS] <FILE>\n", os.Args[0]); err != nil {
			log.Fatal(err)
		}

		flag.PrintDefaults()
	}
}
