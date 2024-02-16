// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

package abcrypt

// Params represents the Argon2 parameters used for the encrypted data.
type Params struct {
	// MemoryCost represents memory size in KiB.
	MemoryCost uint32 `json:"memoryCost"`
	// TimeCost represents the number of iterations.
	TimeCost uint32 `json:"timeCost"`
	// Parallelism represents the degree of parallelism.
	Parallelism uint32 `json:"parallelism"`
}

// NewParams creates a new [Params] from the given ciphertext.
func NewParams(ciphertext []byte) (*Params, error) {
	header, err := parse(ciphertext)
	if err != nil {
		return nil, err
	}

	params := Params{header.memoryCost, header.timeCost, header.parallelism}

	return &params, nil
}
