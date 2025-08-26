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

package crypt

import (
	"encoding/hex"
	"testing"
)

func TestNewBlock(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"bad", "9d9a7ae2334a", true},
		{"good", "9c059f5890d780952375226e2526b6134d703e37076b1b8d8da36f1e12d73859", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := hex.DecodeString(tt.key)
			if err != nil {
				t.Fatalf("NewBlock() error = %v", err)
			}

			got, err := NewBlock(key)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewBlock() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (got == nil) != tt.wantErr {
				t.Errorf("NewBlock() got = %v, wantNil = %v", got, tt.wantErr)
			}
		})
	}
}
