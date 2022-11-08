// # SPDX-License-Identifier: BSD-2-Clause

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
