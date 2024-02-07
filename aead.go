// SPDX-FileCopyrightText: 2024 Thibault NORMAND <me@zenithar.org>
//
// SPDX-License-Identifier: Apache-2.0 AND MIT

package stronghold

import (
	"crypto/aes"
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
)

// AEAD is the authenticated encryption with associated data type.
type AEAD uint8

const (
	// AESGCM is the authenticated encryption with associated data.
	AESGCM AEAD = iota
	// CHACHAPOLY is the authenticated encryption with associated data.
	CHACHAPOLY
)

// aeadRegistry is the authenticated encryption with associated data registry.
var aeadRegistry = map[AEAD]func([]byte) (cipher.AEAD, error) {
	AESGCM: func(key []byte) (cipher.AEAD, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, &operationError{operation: "aesgcm", err: err}
		}

		aead, err := cipher.NewGCMWithNonceSize(block, saltSize)
		if err != nil {
			return nil, &operationError{operation: "aesgcm", err: err}
		}

		return aead, nil
	},
	CHACHAPOLY: func(key []byte) (cipher.AEAD, error) {
		aead, err := chacha20poly1305.NewX(key)
		if err != nil {
			return nil, &operationError{
				operation: "chachapoly", 
				err: err}
		}

		return aead, nil
	},
}
