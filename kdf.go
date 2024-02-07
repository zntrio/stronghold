// SPDX-FileCopyrightText: 2024 Thibault NORMAND <me@zenithar.org>
//
// SPDX-License-Identifier: Apache-2.0 AND MIT

package stronghold

import (
	"crypto/sha512"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// KDF is the key derivation function type.
type KDF uint8 

const (
	// SCRYPT is the key derivation function.
	SCRYPT KDF = iota
	// PBKDF2 is the key derivation function.
	PBKDF2
	// ARGON2ID is the key derivation function.
	ARGON2ID
)

const (
	// scryptN is the CPU/memory cost parameter.
	scryptN = 1 << 15
	// scryptR is the block size parameter.
	scryptR = 8
	// scryptP is the parallelization parameter.
	scryptP = 1
	// pbkdf2IterationCount is the number of iterations for PBKDF2.
	pbkdf2IterationCount = 250000
	// argon2Iterations is the number of iterations for Argon2.
	argon2Iterations = 4
	// argon2Memory is the memory cost parameter for Argon2.
	argon2Memory = 64 * 1024
	// argon2Threads is the number of threads for Argon2.
	argon2Threads = 4
)

// kdfRegistry is the key derivation function registry.
var kdfRegistry = map[KDF]func(secret []byte, salt []byte, dkLen int) ([]byte, error) {
	PBKDF2: func(secret, salt []byte, dkLen int) ([]byte, error) {
		return pbkdf2.Key(secret, salt, pbkdf2IterationCount, dkLen, sha512.New), nil
	},
	SCRYPT: func(secret, salt []byte, dkLen int) ([]byte, error) {
		return scrypt.Key(secret, salt, scryptN, scryptR, scryptP, dkLen)
	},
	ARGON2ID: func(secret, salt []byte, dkLen int) ([]byte, error) {
		return argon2.IDKey(secret, salt, argon2Iterations, argon2Memory, argon2Threads, uint32(dkLen)), nil
	},
}
