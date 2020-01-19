// Copyright (c) 2020 Jef Oliver. All rights reserved.
// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package hash

import (
	"crypto/rand"
	"errors"
	"reflect"
	"testing"
)

func Test_encodeHash(t *testing.T) {
	tests := []struct {
		name string
		want string
		data *Info
	}{
		{"argon2i", "$argon2i$v=19$m=65535,t=20,p=4$SERVMzRhZGFkJSRER0VeRA$KCYqJSomUkZJR0tKTFRZKSooJlImKkdvaWdocDk4dGdQKEQqRzgwN3RmZ1AoRA",
			&Info{
				Config: Config{
					Function:   Argon2I,
					Iterations: 20,
					Memory:     65535,
					Threads:    4,
					Version:    19,
				},
				Hash: []byte("(&*%*&RFIGKJLTY)*(&R&*Goighp98tgP(D*G807tfgP(D"),
				Salt: []byte("HDU34adad%$DGE^D"),
			}},
		{"argon2id", "$argon2id$v=19$m=65535,t=20,p=4$SERVMzRhZGFkJSRER0VeRA$KCYqJSomUkZJR0tKTFRZKSooJlImKkdvaWdocDk4dGdQKEQqRzgwN3RmZ1AoRA",
			&Info{
				Config: Config{
					Function:   Argon2ID,
					Iterations: 20,
					Memory:     65535,
					Threads:    4,
					Version:    19,
				},
				Hash: []byte("(&*%*&RFIGKJLTY)*(&R&*Goighp98tgP(D*G807tfgP(D"),
				Salt: []byte("HDU34adad%$DGE^D"),
			}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encodeHash(tt.data)
			if tt.data.Encoded != tt.want {
				t.Errorf("encodeHash() got = %v, want = %v", tt.data.Encoded, tt.want)
				return
			}
		})
	}
}

func Test_genHash(t *testing.T) {
	tests := []struct {
		name string
		data string
		want []byte
		info *Info
	}{
		{"argon2i", "testing_argon2i",
			[]byte{108, 145, 147, 224, 28, 86, 142, 62, 200, 39, 64, 105, 26, 244, 206, 75, 147, 241, 56,
				233, 155, 201, 31, 98, 183, 248, 35, 151, 40, 122, 11, 124},
			&Info{
				Config: Config{
					Function:   Argon2I,
					Iterations: 20,
					KeySize:    32,
					Memory:     65535,
					Threads:    4,
					Version:    19,
				},
			},
		},
		{"argon2id", "testing_argon2i",
			[]byte{51, 21, 162, 211, 226, 76, 244, 154, 200, 76, 242, 62, 218, 180, 171, 24, 148, 26, 40,
				240, 66, 167, 141, 213, 47, 173, 198, 190, 178, 79, 113, 207},
			&Info{
				Config: Config{
					Function:   Argon2ID,
					Iterations: 20,
					KeySize:    32,
					Memory:     65535,
					Threads:    4,
					Version:    19,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generateHash(tt.data, tt.info)
			if !reflect.DeepEqual(tt.info.Hash, tt.want) {
				t.Errorf("generateHash() got = %v, want = %v", tt.info.Hash, tt.want)
			}
		})
	}
}

func Test_genSalt(t *testing.T) {
	tests := []struct {
		name    string
		readErr bool
		wantErr bool
		info    *Info
	}{
		{"bad read", true, true, &Info{}},
		{"good", false, false, &Info{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				randReadFunc = rand.Read
			}()
			if tt.readErr {
				randReadFunc = func(_ []byte) (int, error) {
					return 0, errors.New("testing error")
				}
			}

			if err := genSalt(tt.info); (err != nil) != tt.wantErr {
				t.Errorf("genSalt() err = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.info.Salt == nil {
				t.Errorf("genSalt() salt = nil, want = not nil")
			}
		})
	}
}

func Test_Generate(t *testing.T) {
	argon2i := GetConfigDefaults()
	argon2i.Function = Argon2I

	argon2id := GetConfigDefaults()

	tests := []struct {
		name     string
		data     string
		readErr  bool
		wantErr  bool
		defaults Config
	}{
		{"empty data", "", false, true, Config{}},
		{"bad config", "test", false, true, Config{}},
		{"bad readFunc", "test", true, true, argon2id},
		{"argon2i", "testing string", false, false, argon2i},
		{"argon2id", "testing string", false, false, argon2id},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				randReadFunc = rand.Read
			}()
			if tt.readErr {
				randReadFunc = func(_ []byte) (int, error) {
					return 0, errors.New("testing error")
				}
			}

			got, err := Generate(tt.data, tt.defaults)
			if (err != nil) != tt.wantErr {
				t.Errorf("Generate() err = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil && got.Encoded == "" {
				t.Error("Generate() got.Encoded empty, want not empty")
			}
		})
	}
}
