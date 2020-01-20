// Copyright (c) 2020 Jef Oliver. All rights reserved.
// Use of this source code is governed by a license
// that can be found in the LICENSE file.

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
