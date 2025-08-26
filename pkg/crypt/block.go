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
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
)

type block struct {
	aes cipher.Block
}

// Decrypt decrypts the provided data
func (b *block) Decrypt(data []byte) ([]byte, error) {
	if data == nil {
		return nil, errors.New("no data provided to encrypt")
	}

	gcm, err := cipher.NewGCM(b.aes)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	return gcm.Open(nil, nonce, ciphertext, nil)
}

// DecryptFromString decrypts data stored in a hex encoded string
func (b *block) DecryptFromString(data string) ([]byte, error) {
	if data == "" {
		return nil, errors.New("no data provided to decrypt")
	}

	dataToDecode, err := hex.DecodeString(data)
	if err != nil {
		return nil, err
	}

	return b.Decrypt(dataToDecode)
}

// Encrypt encrypts the provided data
func (b *block) Encrypt(data []byte) ([]byte, error) {
	var encryptedText []byte

	if data == nil {
		return nil, errors.New("no data provided to encrypt")
	}

	gcm, err := cipher.NewGCM(b.aes)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err == nil {
		encryptedText = gcm.Seal(nonce, nonce, data, nil)
	}

	return encryptedText, err
}

// EncryptToString encrypts the provided data and returns it as a nex encoded string
func (b *block) EncryptToString(data []byte) (string, error) {
	var ret string

	encryptedData, err := b.Encrypt(data)
	if err == nil {
		ret = hex.EncodeToString(encryptedData)
	}

	return ret, err
}
