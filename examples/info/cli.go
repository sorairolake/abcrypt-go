// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package main

import (
	"flag"
	"fmt"
	"os"
)

type options struct {
	json    bool
	version bool
}

var opt options

func init() {
	flag.BoolVar(&opt.json, "json", false, "Output the encryption parameters as JSON")
	flag.BoolVar(&opt.version, "version", false, "Print version number")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [OPTIONS] [FILE]\n", os.Args[0])
		flag.PrintDefaults()
	}
}
