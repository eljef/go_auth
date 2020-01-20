// Copyright (c) 2020 Jef Oliver. All rights reserved.
// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package password

import (
	"reflect"
	"testing"
)

func Test_compareCountToPolicy(t *testing.T) {
	tests := []struct {
		name   string
		want   bool
		count  Policy
		policy Policy
	}{
		{"not long enough", false, Policy{7, 1, 1, 1, 1}, Policy{8, 1, 1, 1, 1}},
		{"not enough lower", false, Policy{8, 0, 1, 1, 1}, Policy{8, 1, 1, 1, 1}},
		{"not enough numbers", false, Policy{8, 1, 0, 1, 1}, Policy{8, 1, 1, 1, 1}},
		{"not enough other", false, Policy{8, 1, 1, 0, 1}, Policy{8, 1, 1, 1, 1}},
		{"not enough upper", false, Policy{8, 1, 1, 1, 0}, Policy{8, 1, 1, 1, 1}},
		{"meets", true, Policy{8, 1, 1, 1, 1}, Policy{8, 1, 1, 1, 1}},
		{"exceeds", true, Policy{10, 2, 2, 2, 2}, Policy{8, 1, 1, 1, 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := compareCountToPolicy(tt.count, tt.policy); got != tt.want {
				t.Errorf("compareCountToPolicy() got = %v, want = %v", got, tt.want)
			}
		})
	}
}

func Test_countCharacters(t *testing.T) {
	tests := []struct {
		name string
		data string
		want Policy
	}{
		{"test1", "1Password!\n", Policy{11, 7, 1, 2, 1}},
		{"test2", "1P@ssword!\n", Policy{11, 6, 1, 3, 1}},
		{"test3", "1Password!", Policy{10, 7, 1, 1, 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := countCharacters(tt.data); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("countCharacters() got = %v, want = %v", got, tt.want)
			}
		})
	}
}

func Test_MatchesPolicy(t *testing.T) {
	tests := []struct {
		name   string
		data   string
		want   bool
		policy Policy
	}{
		{"empty", "", false, Policy{8, 1, 1, 1, 1}},
		{"does not match", "password", false, Policy{8, 1, 1, 1, 1}},
		{"matches", "1Password!", true, Policy{8, 1, 1, 1, 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchesPolicy(tt.data, tt.policy); got != tt.want {
				t.Errorf("MatchesPolicy() got = %v, want = %v", got, tt.want)
			}
		})
	}
}
