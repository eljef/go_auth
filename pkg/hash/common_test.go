// Copyright (c) 2020 Jef Oliver. All rights reserved.
// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package hash

import (
	"reflect"
	"testing"

	"golang.org/x/crypto/argon2"
)

func Test_clearInfo(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		want := Info{Config: Config{}}

		info := Info{
			Config: Config{
				Function:   Argon2ID,
				Iterations: 1,
				KeySize:    2,
				Memory:     3,
				SaltSize:   4,
				Threads:    5,
				Version:    6,
			},
			Encoded: "test",
			Hash:    []byte(`testHash`),
			Salt:    []byte(`testSalt`),
		}

		clearInfo(&info)

		if !reflect.DeepEqual(info, want) {
			t.Errorf("clearInfo() info = %v, want = %v", info, want)
		}
	})
}

func Test_GetConfigDefaults(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		want := Config{
			Function:   "argon2id",
			Iterations: 20,
			KeySize:    32,
			Memory:     65535,
			SaltSize:   16,
			Threads:    4,
			Version:    argon2.Version,
		}

		if got := GetConfigDefaults(); !reflect.DeepEqual(got, want) {
			t.Errorf("GetConfigDefaults() got = %v, want = %v", got, want)
		}
	})
}

func Test_isValidVersion(t *testing.T) {
	tests := []struct {
		name string
		arg  int
		want bool
	}{
		{"no match 1", 9999, false},
		{"no match 2", 13, false},
		{"match 1", 0x13, true},
		{"match 2", 19, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidVersion(tt.arg); got != tt.want {
				t.Errorf("isValidVersion() got = %v, want = %v", got, tt.want)
				return
			}
		})
	}
}

func Test_validateConfig(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
		data    *Config
	}{
		{"version not set", true, &Config{}},
		{"bad version", true, &Config{Version: 9999}},
		{"no iterations", true, &Config{Version: 19}},
		{"no key size", true, &Config{Version: 19, Iterations: 1}},
		{"no memory", true, &Config{Version: 19, Iterations: 1, KeySize: 1}},
		{"no salt size", true, &Config{Version: 19, Iterations: 1, KeySize: 1, Memory: 1}},
		{"no threads", true, &Config{Version: 19, Iterations: 1, KeySize: 1, Memory: 1, SaltSize: 1}},
		{"bad key size", true,
			&Config{Version: 19, Iterations: 1, KeySize: 1, Memory: 1, SaltSize: 1, Threads: 1}},
		{"bad salt size", true,
			&Config{Version: 19, Iterations: 1, KeySize: 32, Memory: 1, SaltSize: 1, Threads: 1}},
		{"no function", true,
			&Config{Version: 19, Iterations: 1, KeySize: 32, Memory: 1, SaltSize: 16, Threads: 1}},
		{"bad function", true,
			&Config{Version: 19, Iterations: 1, KeySize: 32, Memory: 1, SaltSize: 16, Threads: 1,
				Function: "unknown"}},
		{"good argon2i", false,
			&Config{Version: 19, Iterations: 1, KeySize: 32, Memory: 1, SaltSize: 16, Threads: 1,
				Function: "argon2i"}},
		{"good argon2id", false,
			&Config{Version: 19, Iterations: 1, KeySize: 32, Memory: 1, SaltSize: 16, Threads: 1,
				Function: "argon2id"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateConfig(tt.data); (err != nil) != tt.wantErr {
				t.Errorf("validateConfig() err = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
