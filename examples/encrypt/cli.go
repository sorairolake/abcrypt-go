// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/sorairolake/abcrypt-go"
)

const (
	defaultArgon2Type  = uint(abcrypt.Argon2id)
	defaultMemoryCost  = 19456
	defaultTimeCost    = 2
	defaultParallelism = 1
)

type options struct {
	argon2Type  uint
	memoryCost  uint
	timeCost    uint
	parallelism uint
	version     bool
}

var opt options

func init() {
	flag.UintVar(&opt.argon2Type, "argon2-type", defaultArgon2Type, "Set the Argon2 type")
	flag.UintVar(&opt.memoryCost, "memory-cost", defaultMemoryCost, "Set the memory size in KiB")
	flag.UintVar(&opt.timeCost, "time-cost", defaultTimeCost, "Set the number of iterations")
	flag.UintVar(&opt.parallelism, "parallelism", defaultParallelism, "Set the degree of parallelism")
	flag.BoolVar(&opt.version, "version", false, "Print version number")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [OPTIONS] <INFILE> <OUTFILE>\n", os.Args[0])
		flag.PrintDefaults()
	}
}
