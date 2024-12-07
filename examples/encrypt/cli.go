// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package main

import (
	"flag"
	"fmt"
	"os"
)

const (
	defaultArgon2Type    = 2
	defaultArgon2Version = 0x13
)

const (
	defaultMemoryCost  = 19456
	defaultTimeCost    = 2
	defaultParallelism = 1
)

type options struct {
	argon2Type    uint
	argon2Version uint
	memoryCost    uint
	timeCost      uint
	parallelism   uint
	version       bool
}

var opt options

func init() {
	flag.UintVar(&opt.argon2Type, "argon2-type", defaultArgon2Type, "Set the Argon2 type")
	flag.UintVar(&opt.argon2Version, "argon2-version", defaultArgon2Version, "Set the Argon2 version")
	flag.UintVar(&opt.memoryCost, "memory-cost", defaultMemoryCost, "Set the memory size in KiB")
	flag.UintVar(&opt.timeCost, "time-cost", defaultTimeCost, "Set the number of iterations")
	flag.UintVar(&opt.parallelism, "parallelism", defaultParallelism, "Set the degree of parallelism")
	flag.BoolVar(&opt.version, "version", false, "Print version number")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [OPTIONS] <INFILE> <OUTFILE>\n", os.Args[0])
		flag.PrintDefaults()
	}
}
