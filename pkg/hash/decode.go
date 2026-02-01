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
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

const (
	// errInvalidConfig is returned when the configuration section of a hash is malformed or missing
	errInvalidConfig = "invalid hash configuration"
	// errInvalidVersion is returned when the version section of a hash is malformed or missing
	errInvalidVersion = "invalid hash version"
)

// Decode decodes the provided hash
//
// When an error is encountered, a newly instantiated blank Info struct is returned to try to prevent as much
// data leakage as possible.
func Decode(data string) (Info, error) {
	var err error

	parts := strings.Split(data, "$")
	ret := Info{Config: GetConfigDefaults()}

	if ret.Function, err = decodeHashFunction(parts[1]); err != nil {
		clearInfo(&ret)
		return Info{}, err
	}

	if ret.Version, err = decodeHashVersion(parts[2]); err != nil {
		clearInfo(&ret)
		return Info{}, err
	}

	if err = decodeHashConfig(parts[3], &ret); err != nil {
		clearInfo(&ret)
		return Info{}, err
	}

	if ret.Salt, ret.SaltSize, err = decodeHashBytes(parts[4], "invalid hash salt"); err != nil {
		clearInfo(&ret)
		return Info{}, err
	}

	if ret.Hash, ret.KeySize, err = decodeHashBytes(parts[5], "invalid hash body"); err != nil {
		clearInfo(&ret)
		return Info{}, err
	}

	ret.Encoded = data

	return ret, nil
}

// decodeHashBytes decodes the given hash string to a byte slice via base64 decoding
func decodeHashBytes(data string, errorStr string) ([]byte, uint32, error) {
	dataBytes, err := base64.RawStdEncoding.DecodeString(data)
	if err != nil {
		return nil, 0, errors.New(errorStr)
	}

	dLen := len(dataBytes)
	if dLen > 0 && dLen <= math.MaxUint32 {
		return dataBytes, uint32(dLen), nil
	}

	return nil, 0, errors.New(errorStr)
}

// decodeHashConfig validates the provided configuration information in a hash
// nolint:cyclop,gocyclo,gocognit
// decoding does take some cycles to run
func decodeHashConfig(configInfo string, info *Info) error {
	var err error

	parts := strings.Split(configInfo, ",")
	if len(parts) != 3 {
		return errors.New(errInvalidConfig)
	}

	for _, part := range parts {
		confParts := strings.Split(part, "=")
		if len(confParts) != 2 {
			return errors.New(errInvalidConfig)
		}

		switch confParts[0] {
		case "m":
			info.Memory, err = decodeHashConfigUint32(confParts[1], "invalid memory configuration")
		case "p":
			info.Threads, err = decodeHashConfigThreads(confParts[1])
		case "t":
			info.Iterations, err = decodeHashConfigUint32(confParts[1], "invalid iterations/time configuration")
		default:
			err = errors.New(errInvalidConfig)
		}

		if err != nil {
			return err
		}
	}

	if info.Iterations == 0 || info.Memory == 0 || info.Threads == 0 {
		return errors.New(errInvalidConfig)
	}

	return nil
}

// decodeHashConfigUint32 validates the provided configuration part information in a hash
func decodeHashConfigUint32(sectionInfo string, errorStr string) (uint32, error) {
	ret, err := strconv.ParseUint(sectionInfo, 10, 32)
	if err != nil {
		return 0, errors.New(errorStr)
	}

	return uint32(ret), nil
}

// decodeHashConfigThreads validates the provided threads configuration information in a hash
func decodeHashConfigThreads(threadInfo string) (uint8, error) {
	ret, err := strconv.ParseUint(threadInfo, 10, 8)
	if err != nil {
		return 0, errors.New("invalid threads configuration")
	}

	return uint8(ret), nil
}

// decodeHashFunction validates the provided encode function in a hash
func decodeHashFunction(functionName string) (string, error) {
	if functionName == Argon2ID || functionName == Argon2I {
		return functionName, nil
	}

	return "", fmt.Errorf("unknown encode function: %s", functionName)
}

// decodeHashVersion validates the provided encode version in a hash
func decodeHashVersion(versionString string) (int, error) {
	parts := strings.Split(versionString, "=")
	if len(parts) != 2 {
		return 0, errors.New(errInvalidVersion)
	}
	if parts[0] != "v" {
		return 0, errors.New(errInvalidVersion)
	}

	ret, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, errors.New(errInvalidVersion)
	}

	if !isValidVersion(ret) {
		return 0, errors.New(errInvalidVersion)
	}

	return ret, nil
}
