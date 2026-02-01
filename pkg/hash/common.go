/* SPDX-License-Identifier: BSD-2-Clause

Copyright (c) 2020-2026, Jef Oliver
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice, this
     list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright notice
     this list of conditions and the following disclaimer in the documentation
     and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package hash

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	// Argon2I is the argon2i function constant
	Argon2I = "argon2i"
	// Argon2ID is the argon2id function constant
	Argon2ID = "argon2id"
)

var (
	// randReadFun is the function to read random bytes.
	// This is set as a global to allow override for testing.
	randReadFunc = rand.Read

	// validVersions is the versions of the argon algorithms supported by this module
	validVersions = []int{0x13}
)

// clearInfo clears an Info struct
func clearInfo(info *Info) {
	info.Encoded = ""
	info.Function = ""
	info.Hash = nil
	info.Iterations = 0
	info.KeySize = 0
	info.Memory = 0
	info.Salt = nil
	info.SaltSize = 0
	info.Threads = 0
	info.Version = 0
}

// GetConfigDefaults returns sane defaults to be used with the argon hashing algorithms.
//
// hashing parameters arrived at via recommendations from
// https://tools.ietf.org/html/draft-irtf-cfrg-argon2-04#section-4
func GetConfigDefaults() Config {
	return Config{
		Function:   "argon2id",
		Iterations: 20,
		KeySize:    32,
		Memory:     65535,
		SaltSize:   16,
		Threads:    4,
		Version:    argon2.Version,
	}
}

// isValidVersion determines if the provided version is in validVersions
func isValidVersion(version int) bool {
	for _, ver := range validVersions {
		if ver == version {
			return true
		}
	}

	return false
}

// validateConfig validates that the provided config can be used.
// nolint:cyclop,gocyclo,gocognit
// unfortunately, checking the config takes some cycles
func validateConfig(config *Config) error {
	if !isValidVersion(config.Version) {
		return fmt.Errorf("invalid or unsupported version provided: %d", config.Version)
	}

	if config.Iterations < 1 || config.KeySize < 1 || config.Memory < 1 || config.SaltSize < 1 || config.Threads < 1 {
		return errors.New("config cannot contain zero values")
	}

	if config.KeySize%32 != 0 {
		return fmt.Errorf("keysize of %d is not a multiple of 32", config.KeySize)
	}

	if config.SaltSize%16 != 0 {
		return fmt.Errorf("salt size of %d is not a multiple of 16", config.SaltSize)
	}

	if config.Function != Argon2ID && config.Function != Argon2I {
		return fmt.Errorf("unknown argon function: %s", config.Function)
	}

	return nil
}
