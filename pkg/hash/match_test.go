// Copyright (c) 2020 Jef Oliver. All rights reserved.
// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package hash

import (
	"testing"
)

func Test_MatchesAfterHash(t *testing.T) {
	matchInfo := Info{
		Config: Config{
			Function:   "argon2id",
			Iterations: 20,
			KeySize:    32,
			Memory:     65535,
			SaltSize:   16,
			Threads:    4,
			Version:    19,
		},
		Encoded: "$argon2id$v=19$m=65535,t=20,p=4$4bRVv/m0ARcjyUeavESBpw$qTdZ06xgx+01yTx0zOLAiax0XIvTokIvBy9mOSQLf0Q",
		Hash: []byte{169, 55, 89, 211, 172, 96, 199, 237, 53, 201, 60, 116, 204, 226, 192, 137, 172, 116, 92,
			139, 211, 162, 66, 47, 7, 47, 102, 57, 36, 11, 127, 68},
		Salt: []byte{225, 180, 85, 191, 249, 180, 1, 23, 35, 201, 71, 154, 188, 68, 129, 167},
	}

	tests := []struct {
		name string
		data string
		want bool
	}{
		{"doesn't match", "test data", false},
		{"good", "testing data", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchesAfterHash(tt.data, matchInfo); got != tt.want {
				t.Errorf("MatchesAfterHash() got = %v, want = %v", got, tt.want)
			}
		})
	}
}
