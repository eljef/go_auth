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

package password

import (
	"unicode"
)

type Policy struct {
	Length int `json:"length" toml:"length"` // Length is the minimum length allowed for a password.
	Lower  int `json:"lower" toml:"lower"`   // Lower is the number of lower case characters required.
	Number int `json:"number" toml:"number"` // Number is the number of special characters required.
	Other  int `json:"other" toml:"other"`   // Other is the number of other characters required. (ie special, mark, etc..)
	Upper  int `json:"upper" toml:"upper"`   // Upper is the number of upper case characters required.
}

// compareCountToPolicy determines if the finds from countCharacters meets/exceeds the provided policy
func compareCountToPolicy(count Policy, policy Policy) bool {
	return count.Length >= policy.Length &&
		count.Lower >= policy.Lower &&
		count.Number >= policy.Number &&
		count.Other >= policy.Other &&
		count.Upper >= policy.Upper
}

// countCharacters counts the number of different types of characters in a password
func countCharacters(password string) Policy {
	var count Policy

	count.Length = len(password)

	for _, r := range password {
		switch {
		case unicode.IsLower(r):
			count.Lower++
		case unicode.IsUpper(r):
			count.Upper++
		case unicode.IsNumber(r):
			count.Number++
		default:
			count.Other++
		}
	}

	return count
}

// MatchesPolicy determines if a password matches the provided policy
func MatchesPolicy(password string, policy Policy) bool {
	return compareCountToPolicy(countCharacters(password), policy)
}
