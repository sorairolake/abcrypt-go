// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Encrypt is an example of encrypting a file to the abcrypt encrypted data
// format.
//
// Usage:
//
//	encrypt [OPTIONS] <INFILE> <OUTFILE>
//
// Arguments:
//
//	<INFILE>
//		Input file.
//	<OUTFILE>
//		Output file.
//
// Options:
//
//	-argon2-type <TYPE>
//		Set the Argon2 type.
//	-memory-cost <NUM>
//		Set the memory size in KiB.
//	-time-cost <NUM>
//		Set the number of iterations.
//	-parallelism <NUM>
//		Set the degree of parallelism.
//	-version
//		Print version number.
package main
