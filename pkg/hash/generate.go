// # SPDX-License-Identifier: BSD-2-Clause

package hash

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// encodeHash encodes the hashed password and information into a string per output from
// https://github.com/P-H-C/phc-winner-argon2#command-line-utility
func encodeHash(info *Info) {
	b64pass := base64.RawStdEncoding.EncodeToString(info.Hash)
	b64salt := base64.RawStdEncoding.EncodeToString(info.Salt)

	info.Encoded = fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		info.Function, info.Version, info.Memory, info.Iterations, info.Threads, b64salt, b64pass)
}

// generateHash hashes data using the Argon2id variant
func generateHash(data string, info *Info) {
	// Per documentation for bytes.Buffer.WriteString(), err is always nil, so it is safe to ignore error returns
	// on this call.

	b := bytes.Buffer{}
	/* #nosec */
	_, _ = b.WriteString(data)

	switch info.Function {
	case Argon2ID:
		info.Hash = argon2.IDKey(b.Bytes(), info.Salt, info.Iterations, info.Memory, info.Threads, info.KeySize)
	case Argon2I:
		info.Hash = argon2.Key(b.Bytes(), info.Salt, info.Iterations, info.Memory, info.Threads, info.KeySize)
	}

	b.Reset()
}

// genSalt generates random salt to be used in hashing.
func genSalt(info *Info) error {
	info.Salt = make([]byte, info.SaltSize)

	_, err := randReadFunc(info.Salt)
	if err != nil {
		// An explicit error check is done here so that incomplete data doesn't get sent to the caller.
		// Paranoia is sometimes an OK policy.
		info.Salt = nil
		return err
	}

	return nil
}

// Generate hashes the provided data and creates an encoded string for storage, returning all information used to
// create the hash.
//
// If an error is encountered, an uninitialized Info struct is returned to prevent leaking of data to the caller.
func Generate(data string, defaults Config) (Info, error) {
	var err error

	if data == "" {
		return Info{}, errors.New("empty data")
	}

	if err = validateConfig(&defaults); err != nil {
		return Info{}, err
	}

	ret := Info{Config: defaults}

	if err = genSalt(&ret); err != nil {
		clearInfo(&ret)
		return Info{}, err
	}

	generateHash(data, &ret)
	encodeHash(&ret)

	return ret, nil
}
