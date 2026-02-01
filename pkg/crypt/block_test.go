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

package crypt

import (
	"bytes"
	"crypto/aes"
	"testing"
)

type badCipherBlock struct{}

func (b *badCipherBlock) BlockSize() int      { return 0 }
func (b *badCipherBlock) Encrypt(_, _ []byte) {}
func (b *badCipherBlock) Decrypt(_, _ []byte) {}

// nolint: gocognit
func Test_blockDecrypt(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		badCipher bool
		data      []byte
		want      []byte
		wantErr   bool
	}{
		{"no data", "testKeySixteen16", false, nil, nil, true},
		{"NewGCM error", "testKeySixteen16", true,
			[]byte{202, 202, 128, 183, 95, 130, 153, 150, 136, 28, 103, 56, 208, 21, 82, 188, 119, 13, 218, 189, 60, 44,
				159, 101, 34, 236, 28, 56, 32, 22, 63, 26, 137, 246, 193, 77, 21, 16, 179, 185, 0, 188, 160, 23, 30},
			nil, true},
		{"good", "testKeySixteen16", false,
			[]byte{202, 202, 128, 183, 95, 130, 153, 150, 136, 28, 103, 56, 208, 21, 82, 188, 119, 13, 218, 189, 60, 44,
				159, 101, 34, 236, 28, 56, 32, 22, 63, 26, 137, 246, 193, 77, 21, 16, 179, 185, 0, 188, 160, 23, 30},
			[]byte{116, 104, 105, 115, 32, 105, 115, 32, 116, 101, 115, 116, 32, 100, 97, 116, 97},
			false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tester := &block{}
			if tt.badCipher {
				tester.aes = &badCipherBlock{}
			} else {
				rAES, err := aes.NewCipher([]byte(tt.key))
				if err != nil {
					t.Fatal(err)
				}
				tester.aes = rAES
			}

			got, err := tester.Decrypt(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("block.Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if bytes.Equal(got, tt.want) != true {
				t.Errorf("block.Decrypt() = %v, want %v", got, tt.want)
				return
			}
		})
	}
}

func Test_blockDecryptFromString(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		data    string
		want    []byte
		wantErr bool
	}{
		{"no data", "testKeySixteen16", "", nil, true},
		{"bad data", "testKeySixteen16", "8906ay9douigh89adjghfajkldgkljgzx", nil, true},
		{"good", "testKeySixteen16",
			"62cee51629a72beee654a8fbc6d81ed07e981c15889c80baf636b73f22f95cc0e659dbeebe278792c256dd096f",
			[]byte{116, 104, 105, 115, 32, 105, 115, 32, 116, 101, 115, 116, 32, 100, 97, 116, 97},
			false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []byte

			tester := &block{}
			rAES, err := aes.NewCipher([]byte(tt.key))
			if err != nil {
				t.Fatal(err)
			}
			tester.aes = rAES

			got, err = tester.DecryptFromString(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("blockDecryptFromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if bytes.Equal(got, tt.want) != true {
				t.Errorf("blockDecryptFromString() = %v, want %v", got, tt.want)
			}
		})
	}
}

// nolint: gocognit
func Test_blockEncrypt(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		badCipher bool
		data      []byte
		wantErr   bool
		wantNil   bool
	}{
		{"no data", "testKeySixteen16", false, nil, true, true},
		{"NewGCM error", "testKeySixteen16", true,
			[]byte{116, 104, 105, 115, 32, 105, 115, 32, 116, 101, 115, 116, 32, 100, 97, 116, 97},
			true, true},
		{"good", "testKeySixteen16", false,
			[]byte{116, 104, 105, 115, 32, 105, 115, 32, 116, 101, 115, 116, 32, 100, 97, 116, 97},
			false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tester := &block{}
			if tt.badCipher {
				tester.aes = &badCipherBlock{}
			} else {
				rAES, err := aes.NewCipher([]byte(tt.key))
				if err != nil {
					t.Fatal(err)
				}
				tester.aes = rAES
			}

			got, err := tester.Encrypt(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("block.Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if (got == nil) != tt.wantNil {
				t.Errorf("block.Encrypt() = %v, wantNil %v", got, tt.wantNil)
			}
			t.Logf("got = %v", got)
		})
	}
}

func Test_blockEncryptToString(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		data      []byte
		wantEmpty bool
		wantErr   bool
	}{
		{"no data", "testKeySixteen16", nil, true, true},
		{"good", "testKeySixteen16",
			[]byte{116, 104, 105, 115, 32, 105, 115, 32, 116, 101, 115, 116, 32, 100, 97, 116, 97},
			false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string

			tester := &block{}
			rAES, err := aes.NewCipher([]byte(tt.key))
			if err != nil {
				t.Fatal(err)
			}
			tester.aes = rAES

			got, err = tester.EncryptToString(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("block.EncryptToString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if (len(got) > 0) == tt.wantEmpty {
				t.Errorf("block.EncryptToString() = %v, wantEmpty %v", got, tt.wantEmpty)
			}

			t.Logf("got = %v", got)
		})
	}
}

// nolint: gocognit
func Test_blockFullRun(t *testing.T) {
	t.Run("block full run", func(t *testing.T) {
		var decryptedData []byte
		var encryptedData string

		data := []byte("this is test data")

		tester := &block{}
		rAES, err := aes.NewCipher([]byte("testKeySixteen16"))
		if err != nil {
			t.Fatal(err)
		}
		tester.aes = rAES

		encryptedData, err = tester.EncryptToString(data)
		if err != nil {
			t.Errorf("block.EncryptToString() error = %v", err)
			return
		}
		if encryptedData == "" {
			t.Error("block.EncryptToString() = empty string")
			return
		}

		decryptedData, err = tester.DecryptFromString(encryptedData)
		if err != nil {
			t.Errorf("block.DecryptToString() error = %v", err)
			return
		}

		if decryptedData == nil {
			t.Error("block.DecryptToString() = empty data")
			return
		}

		decryptedDataString := string(decryptedData)
		if decryptedDataString != "this is test data" {
			t.Errorf("block.DecryptToString() = %s, want \"this is test data\"", decryptedDataString)
		}
	})
}
