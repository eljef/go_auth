/* SPDX-License-Identifier: BSD-2-Clause

Copyright (c) 2020-2025, Jef Oliver
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
