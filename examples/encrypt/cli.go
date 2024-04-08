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
	defaultMemoryCost  = 19456
	defaultTimeCost    = 2
	defaultParallelism = 1
)

type options struct {
	memoryCost  uint
	timeCost    uint
	parallelism uint
	version     bool
}

var opt options

func init() {
	flag.UintVar(&opt.memoryCost, "memory-cost", defaultMemoryCost, "Set the memory size in KiB")
	flag.UintVar(&opt.timeCost, "time-cost", defaultTimeCost, "Set the number of iterations")
	flag.UintVar(&opt.parallelism, "parallelism", defaultParallelism, "Set the degree of parallelism")
	flag.BoolVar(&opt.version, "version", false, "Print version number")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [OPTIONS] <INFILE> <OUTFILE>\n", os.Args[0])
		flag.PrintDefaults()
	}
}
