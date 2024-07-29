/* SPDX-License-Identifier: BSD-2-Clause

Copyright (c) 2020-2024, Jef Oliver
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

// nolint:dupl
package hash

import (
	"reflect"
	"testing"
)

func Test_Decode(t *testing.T) {
	tests := []struct {
		name    string
		hash    string
		wantErr bool
		want    Info
	}{
		{"unknown function",
			"$argon2$v=19$m=65535,t=20,p=4$FgfkCqnF7CDOm5OigAR9EA$/hL4WFDYAQdfe8+D055mx1qQ9YBY24Tzyvcidlqrq5Y",
			true, Info{}},
		{"unsupported version",
			"$argon2id$v=20$m=65535,t=20,p=4$FgfkCqnF7CDOm5OigAR9EA$/hL4WFDYAQdfe8+D055mx1qQ9YBY24Tzyvcidlqrq5Y",
			true, Info{}},
		{"bad configuration",
			"$argon2id$v=19$t=20,p=4$FgfkCqnF7CDOm5OigAR9EA$/hL4WFDYAQdfe8+D055mx1qQ9YBY24Tzyvcidlqrq5Y",
			true, Info{}},
		{"bad salt",
			"$argon2id$v=19$m=65535,t=20,p=4$$/hL4WFDYAQdfe8+D055mx1qQ9YBY24Tzyvcidlqrq5Y",
			true, Info{}},
		{"bad data",
			"$argon2id$v=19$m=65535,t=20,p=4$FgfkCqnF7CDOm5OigAR9EA$",
			true, Info{}},
		{"good", "$argon2id$v=19$m=65535,t=20,p=4$FgfkCqnF7CDOm5OigAR9EA$/hL4WFDYAQdfe8+D055mx1qQ9YBY24Tzyvcidlqrq5Y",
			false, Info{
				Config:  GetConfigDefaults(),
				Encoded: "$argon2id$v=19$m=65535,t=20,p=4$FgfkCqnF7CDOm5OigAR9EA$/hL4WFDYAQdfe8+D055mx1qQ9YBY24Tzyvcidlqrq5Y",
				Hash: []byte{254, 18, 248, 88, 80, 216, 1, 7, 95, 123, 207, 131, 211, 158, 102, 199,
					90, 144, 245, 128, 88, 219, 132, 243, 202, 247, 34, 118, 90, 171, 171, 150},
				Salt: []byte{22, 7, 228, 10, 169, 197, 236, 32, 206, 155, 147, 162, 128, 4, 125, 16},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decode(tt.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decode() err = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Decode() got = %v,\nwant = %v", got, tt.want)
			}
		})
	}
}

func Test_decodeHashBytes(t *testing.T) {
	tests := []struct {
		name       string
		data       string
		wantBytes  []byte
		wantUint32 uint32
		wantErr    bool
	}{
		{"bad data", "not_base64_encoded", nil, 0, true},
		{"no data", "", nil, 0, true},
		{"good", "/hL4WFDYAQdfe8+D055mx1qQ9YBY24Tzyvcidlqrq5Y",
			[]byte{254, 18, 248, 88, 80, 216, 1, 7, 95, 123, 207, 131, 211, 158, 102, 199, 90, 144, 245,
				128, 88, 219, 132, 243, 202, 247, 34, 118, 90, 171, 171, 150},
			32, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBytes, gotUint32, err := decodeHashBytes(tt.data, "test error string")
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeHashBytes() err = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotBytes, tt.wantBytes) {
				t.Errorf("decodeHashBytes() gotBytes = %v, wantBytes = %v", gotBytes, tt.wantBytes)
				return
			}
			if gotUint32 != tt.wantUint32 {
				t.Errorf("decodeHashBytes() gotUint32 = %v, wantUint32 = %v", gotUint32, tt.wantUint32)
			}
		})
	}
}

// nolint:gocognit
func Test_decodeHashConfig(t *testing.T) {
	tests := []struct {
		name           string
		data           string
		info           Info
		wantErr        bool
		wantIterations uint32
		wantMemory     uint32
		wantThreads    uint8
	}{
		{"too few parts", "m=65535,t=20", Info{Config: Config{}}, true, 0, 0, 0},
		{"too many parts", "m=65535,t=20,p=4,s=1", Info{Config: Config{}}, true, 0, 0, 0},
		{"inner parts has too few parts", "m=,t=20,p=4", Info{Config: Config{}}, true, 0, 0, 0},
		{"inner parts has too many", "m=65535=65535,t=20,p=4", Info{Config: Config{}}, true, 0, 0, 0},
		{"unknown part", "f=65535,t=20,p=4", Info{Config: Config{}}, true, 0, 0, 0},
		{"zero mem", "m=0,t=20,p=4", Info{Config: Config{}}, true, 20, 0, 4},
		{"zero iterations", "m=65535,t=0,p=4", Info{Config: Config{}}, true, 0, 65535, 4},
		{"zero threads", "m=65535,t=20,p=0", Info{Config: Config{}}, true, 20, 65535, 0},
		{"good", "m=65535,t=20,p=4", Info{Config: Config{}}, false, 20, 65535, 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := tt.info
			err := decodeHashConfig(tt.data, &info)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeHashConfig() err = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if info.Iterations != tt.wantIterations {
				t.Errorf("decodeHashConfig() iterations = %d, want = %d, err=%v", tt.info.Iterations, tt.wantIterations, err)
				return
			}
			if info.Memory != tt.wantMemory {
				t.Errorf("decodeHashConfig() memory = %d, want = %d, err=%v", tt.info.Memory, tt.wantMemory, err)
				return
			}
			if info.Threads != tt.wantThreads {
				t.Errorf("decodeHashConfig() memory = %d, want = %d, err=%v", tt.info.Threads, tt.wantThreads, err)
			}
		})
	}
}

func Test_decodeHashConfigUint32(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		want    uint32
		wantErr bool
	}{
		{"not a number", "not a number", 0, true},
		{"not a number 2", "a", 0, true},
		{"number too big", "4294967296", 0, true},
		{"good", "2", 2, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeHashConfigUint32(tt.data, "test error message")
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeHashConfigUint32() err = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("decodeHashConfigUint32() got = %v, want = %v", got, tt.want)
			}
		})
	}
}

func Test_decodeHashConfigThreads(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		want    uint8
		wantErr bool
	}{
		{"not a number", "not a number", 0, true},
		{"not a number 2", "a", 0, true},
		{"number too big", "4294967295", 0, true},
		{"good", "2", 2, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeHashConfigThreads(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeHashConfigThreads() err = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("decodeHashConfigThreads() got = %d, want = %d", got, tt.want)
			}
		})
	}
}

func Test_decodeHashFunction(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		want    string
		wantErr bool
	}{
		{"unknown function name", "argon2", "", true},
		{"unknown function name 2", "some function", "", true},
		{"argon2i", "argon2i", "argon2i", false},
		{"argon2id", "argon2id", "argon2id", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeHashFunction(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeHashFunction() err = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("decodeHashFunction() got = %s, want = %s", got, tt.want)
			}
		})
	}
}

func Test_decodeHashVersion(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		want    int
		wantErr bool
	}{
		{"empty", "", 0, true},
		{"too few parts", "v", 0, true},
		{"too many parts", "v=0=0", 0, true},
		{"not version", "t=0", 0, true},
		{"not a number", "v=a", 0, true},
		{"number too large", "v=4294967296", 0, true},
		{"version is zero", "v=0", 0, true},
		{"invalid version", "v=200", 0, true},
		{"good", "v=19", 19, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeHashVersion(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeHashVersion() err = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("decodeHashVersion() got = %d, want = %d", got, tt.want)
			}
		})
	}
}
