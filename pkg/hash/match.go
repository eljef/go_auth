// # SPDX-License-Identifier: BSD-2-Clause

package hash

// MatchesAfterHash generates hash info for the provided data, and then compares to the provided match info.
func MatchesAfterHash(data string, matchInfo Info) bool {
	newInfo := matchInfo
	generateHash(data, &newInfo)
	encodeHash(&newInfo)

	return newInfo.Encoded == matchInfo.Encoded
}
