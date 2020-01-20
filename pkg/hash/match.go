// Copyright (c) 2020 Jef Oliver. All rights reserved.
// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package hash

// MatchesAfterHash generates hash info for the provided data, and then compares to the provided match info.
func MatchesAfterHash(data string, matchInfo Info) bool {
	newInfo := matchInfo
	generateHash(data, &newInfo)
	encodeHash(&newInfo)

	return newInfo.Encoded == matchInfo.Encoded
}
