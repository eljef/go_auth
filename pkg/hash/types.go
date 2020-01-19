// Copyright (c) 2020 Jef Oliver. All rights reserved.
// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package hash

// Config holds the default configuration values for the hash module.
type Config struct {
	Function   string // Function is the name of the function to create the hash.
	Iterations uint32 // Iterations is the number of passes over hashing memory should occur.
	KeySize    uint32 // KeySize is the size, in bytes, the returned derived key should be. Must be a multiple of 32.
	Memory     uint32 // Memory is the size of memory, in kilobytes, to be used in iteration during hashing.
	SaltSize   uint32 // SaltSize is the size, in bytes, that randomly generated salt to be used for hashing should be. Must be a multiple of 16.
	Threads    uint8  // Threads is the number of threads to be used in the hashing process.
	Version    int    // DefaultVersion is the default version fo the argon hashing algorithms to use for hashing.
}

// Info holds information about a hash
type Info struct {
	Config // Config is an embedded config struct

	Encoded string // Encoded the full encoded form of the hash. Usually used in storage.
	Hash    []byte // Hash is the hashed data itself.
	Salt    []byte // Salt is the salt used in creating this hash.
}
