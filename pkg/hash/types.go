/* SPDX-License-Identifier: BSD-2-Clause

Copyright (c) 2020-2025, Jef Oliver
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

// Config holds the default configuration values for the hash module.
type Config struct {
	Function   string `json:"function,omitempty" toml:"function"`     // Function is the name of the function to create the hash.
	Iterations uint32 `json:"iterations.omitempty" toml:"iterations"` // Iterations is the number of passes over hashing memory should occur.
	KeySize    uint32 `json:"key_size,omitempty" toml:"key_size"`     // KeySize is the size, in bytes, the returned derived key should be. Must be a multiple of 32.
	Memory     uint32 `json:"memory,omitempty" toml:"memory"`         // Memory is the size of memory, in kilobytes, to be used in iteration during hashing.
	SaltSize   uint32 `json:"salt_size,omitempty" toml:"salt_size"`   // SaltSize is the size, in bytes, that randomly generated salt to be used for hashing should be. Must be a multiple of 16.
	Threads    uint8  `json:"threads,omitempty" toml:"threads"`       // Threads is the number of threads to be used in the hashing process.
	Version    int    `json:"version,omitempty" toml:"version"`       // Version is the default version fo the argon hashing algorithms to use for hashing.
}

// Info holds information about a hash
type Info struct {
	Config // Config is an embedded config struct

	Encoded string // Encoded the full encoded form of the hash. Usually used in storage.
	Hash    []byte // Hash is the hashed data itself.
	Salt    []byte // Salt is the salt used in creating this hash.
}
